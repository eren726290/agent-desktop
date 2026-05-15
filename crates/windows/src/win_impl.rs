use agent_desktop_core::adapter::{
    PlatformAdapter, PermissionStatus, WindowFilter, TreeOptions, NativeHandle,
};
use agent_desktop_core::action::{Action, ActionResult, DragParams, MouseEvent, MouseEventKind, MouseButton};
use agent_desktop_core::error::AdapterError;
use agent_desktop_core::node::{AccessibilityNode, AppInfo, Rect, WindowInfo};
use agent_desktop_core::refs::RefEntry;

use windows::Win32::Foundation::{HWND, BOOL, LPARAM, TRUE, HANDLE};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, MOUSEINPUT,
    MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
    MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP,
    MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP,
    MOUSEEVENTF_MOVE, MOUSEEVENTF_ABSOLUTE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowTextW, IsWindowVisible, GetWindowThreadProcessId,
    SetForegroundWindow, GetForegroundWindow, GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_NAME_WIN32,
};
use windows::Win32::System::DataExchange::{
    OpenClipboard, CloseClipboard, EmptyClipboard, GetClipboardData, SetClipboardData,
};
use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
const CF_UNICODETEXT: u32 = 13;
use windows::Win32::UI::Accessibility::{
    IUIAutomation, IUIAutomationElement,
    UIA_CONTROLTYPE_ID,
    UIA_ButtonControlTypeId, UIA_EditControlTypeId,
    UIA_CheckBoxControlTypeId, UIA_HyperlinkControlTypeId,
    UIA_ListControlTypeId, UIA_ListItemControlTypeId,
    UIA_ComboBoxControlTypeId, UIA_TreeControlTypeId,
    UIA_TreeItemControlTypeId, UIA_TabControlTypeId,
    UIA_TabItemControlTypeId, UIA_SliderControlTypeId,
    UIA_ProgressBarControlTypeId, UIA_TextControlTypeId,
    IUIAutomationInvokePattern, IUIAutomationValuePattern,
    UIA_InvokePatternId, UIA_ValuePatternId,
    TreeScope_Children,
};
use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CLSCTX_ALL, COINIT_MULTITHREADED};
use windows::core::{Interface, BSTR, PWSTR};

use std::collections::HashSet;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

pub struct WindowsAdapter;

impl WindowsAdapter {
    pub fn new() -> Self { Self }

    unsafe fn traverse_element(
        &self,
        element: &IUIAutomationElement,
        opts: &TreeOptions,
        depth: u8,
    ) -> Result<AccessibilityNode, AdapterError> {
        let name = element.CurrentName()
            .map(|b| b.to_string())
            .ok()
            .filter(|s| !s.is_empty());

        let control_type = element.CurrentControlType().unwrap_or(UIA_TextControlTypeId);
        let role = self.uia_role(control_type);

        // Build states vec from element properties
        let mut states: Vec<String> = Vec::new();
        if element.CurrentHasKeyboardFocus().map(|b| b.as_bool()).unwrap_or(false) {
            states.push("focused".into());
        }

        let bounds = if opts.include_bounds {
            element.CurrentBoundingRectangle().ok().map(|rect| Rect {
                x: rect.left as f64,
                y: rect.top as f64,
                width: (rect.right - rect.left) as f64,
                height: (rect.bottom - rect.top) as f64,
            })
        } else {
            None
        };

        let mut node = AccessibilityNode {
            ref_id: None,
            role,
            name,
            value: None,
            description: None,
            hint: None,
            states,
            bounds,
            children_count: None,
            children: Vec::new(),
        };

        if depth < opts.max_depth {
            if let Ok(children) = element.FindAll(TreeScope_Children, None) {
                let count = children.Length().unwrap_or(0);
                node.children_count = Some(count as u32);
                for i in 0..count {
                    if let Ok(child) = children.GetElement(i) {
                        node.children.push(self.traverse_element(&child, opts, depth + 1)?);
                    }
                }
            }
        }

        Ok(node)
    }

    fn uia_role(&self, id: UIA_CONTROLTYPE_ID) -> String {
        match id {
            UIA_ButtonControlTypeId      => "button",
            UIA_EditControlTypeId        => "textfield",
            UIA_CheckBoxControlTypeId    => "checkbox",
            UIA_HyperlinkControlTypeId   => "link",
            UIA_ListItemControlTypeId    => "cell",
            UIA_ListControlTypeId        => "list",
            UIA_ComboBoxControlTypeId    => "combobox",
            UIA_TreeItemControlTypeId    => "treeitem",
            UIA_TreeControlTypeId        => "tree",
            UIA_TabItemControlTypeId     => "tab",
            UIA_TabControlTypeId         => "tablist",
            UIA_SliderControlTypeId      => "slider",
            UIA_ProgressBarControlTypeId => "progressbar",
            _                            => "group",
        }.to_string()
    }
}

impl Default for WindowsAdapter {
    fn default() -> Self { Self::new() }
}

// ── Win32 helpers ─────────────────────────────────────────────────────────────

unsafe fn hwnd_title(hwnd: HWND) -> Option<String> {
    let mut buf = [0u16; 512];
    let len = GetWindowTextW(hwnd, &mut buf);
    if len == 0 { return None; }
    Some(String::from_utf16_lossy(&buf[..len as usize]))
}

unsafe fn hwnd_pid(hwnd: HWND) -> u32 {
    let mut pid = 0u32;
    GetWindowThreadProcessId(hwnd, Some(&mut pid));
    pid
}

unsafe fn pid_exe(pid: u32) -> Option<String> {
    let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
    let mut buf = [0u16; 512];
    let mut size = buf.len() as u32;
    QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut size).ok()?;
    let path = OsString::from_wide(&buf[..size as usize]);
    Some(path.to_string_lossy().into_owned())
}

struct WinCollector(Vec<(HWND, String, u32)>);

unsafe extern "system" fn enum_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    if IsWindowVisible(hwnd).as_bool() {
        let collector = &mut *(lparam.0 as *mut WinCollector);
        if let Some(title) = hwnd_title(hwnd) {
            if !title.is_empty() {
                let pid = hwnd_pid(hwnd);
                collector.0.push((hwnd, title, pid));
            }
        }
    }
    TRUE
}

fn collect_windows() -> Vec<(HWND, String, u32)> {
    let mut collector = WinCollector(Vec::new());
    unsafe {
        let _ = EnumWindows(Some(enum_callback), LPARAM(&mut collector as *mut _ as isize));
    }
    collector.0
}

fn send_mouse(kind: MouseEventKind, button: MouseButton, x: f64, y: f64) -> Result<(), AdapterError> {
    use windows::Win32::UI::Input::KeyboardAndMouse::INPUT_MOUSE;
    unsafe {
        let screen_w = GetSystemMetrics(SM_CXSCREEN) as f64;
        let screen_h = GetSystemMetrics(SM_CYSCREEN) as f64;
        let nx = (x * 65535.0 / screen_w) as i32;
        let ny = (y * 65535.0 / screen_h) as i32;

        let dwflags = match (&kind, &button) {
            (MouseEventKind::Move, _)               => MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE,
            (MouseEventKind::Down, MouseButton::Left)   => MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_ABSOLUTE,
            (MouseEventKind::Up,   MouseButton::Left)   => MOUSEEVENTF_LEFTUP | MOUSEEVENTF_ABSOLUTE,
            (MouseEventKind::Down, MouseButton::Right)  => MOUSEEVENTF_RIGHTDOWN | MOUSEEVENTF_ABSOLUTE,
            (MouseEventKind::Up,   MouseButton::Right)  => MOUSEEVENTF_RIGHTUP | MOUSEEVENTF_ABSOLUTE,
            (MouseEventKind::Down, MouseButton::Middle) => MOUSEEVENTF_MIDDLEDOWN | MOUSEEVENTF_ABSOLUTE,
            (MouseEventKind::Up,   MouseButton::Middle) => MOUSEEVENTF_MIDDLEUP | MOUSEEVENTF_ABSOLUTE,
            (MouseEventKind::Click { count }, btn) => {
                // Expand click into down+up
                for _ in 0..*count {
                    send_mouse(MouseEventKind::Down, btn.clone(), x, y)?;
                    send_mouse(MouseEventKind::Up, btn.clone(), x, y)?;
                }
                return Ok(());
            }
        };

        let input = INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx: nx, dy: ny,
                    mouseData: 0,
                    dwFlags: dwflags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
    }
    Ok(())
}

// ── PlatformAdapter ───────────────────────────────────────────────────────────

impl PlatformAdapter for WindowsAdapter {

    fn check_permissions(&self) -> PermissionStatus {
        PermissionStatus::Granted
    }

    fn list_apps(&self) -> Result<Vec<AppInfo>, AdapterError> {
        let windows = collect_windows();
        let mut seen = HashSet::new();
        let mut apps = Vec::new();
        for (_, title, pid) in windows {
            if seen.insert(pid) {
                let exe = unsafe { pid_exe(pid) }.unwrap_or_default();
                let name = std::path::Path::new(&exe)
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or(title);
                apps.push(AppInfo {
                    name,
                    pid: pid as i32,
                    bundle_id: Some(exe),
                });
            }
        }
        Ok(apps)
    }

    fn list_windows(&self, filter: &WindowFilter) -> Result<Vec<WindowInfo>, AdapterError> {
        let windows = collect_windows();
        let mut result = Vec::new();
        for (hwnd, title, pid) in windows {
            if let Some(ref app) = filter.app {
                let exe = unsafe { pid_exe(pid) }.unwrap_or_default();
                let stem = std::path::Path::new(&exe)
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if !stem.to_lowercase().contains(&app.to_lowercase()) {
                    continue;
                }
            }
            let exe = unsafe { pid_exe(pid) }.unwrap_or_default();
            let app_name = std::path::Path::new(&exe)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| title.clone());

            result.push(WindowInfo {
                id: format!("w-{}", hwnd.0 as usize),
                title,
                pid: pid as i32,
                app: app_name,
                bounds: None,
                is_focused: false,
            });
        }
        Ok(result)
    }

    fn focused_window(&self) -> Result<Option<WindowInfo>, AdapterError> {
        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd.0.is_null() { return Ok(None); }
            let title = hwnd_title(hwnd).unwrap_or_default();
            let pid = hwnd_pid(hwnd);
            let exe = unsafe { pid_exe(pid) }.unwrap_or_default();
            let app_name = std::path::Path::new(&exe)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| title.clone());

            Ok(Some(WindowInfo {
                id: format!("w-{}", hwnd.0 as usize),
                title,
                pid: pid as i32,
                app: app_name,
                bounds: None,
                is_focused: true,
            }))
        }
    }

    fn focus_window(&self, win: &WindowInfo) -> Result<(), AdapterError> {
        let hwnd_val: usize = win.id
            .strip_prefix("w-")
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| AdapterError::not_supported("focus_window: bad id"))?;
        unsafe { let _ = SetForegroundWindow(HWND(hwnd_val as *mut _)); }
        Ok(())
    }

    fn get_tree(&self, win: &WindowInfo, opts: &TreeOptions) -> Result<AccessibilityNode, AdapterError> {
        let hwnd_val: usize = win.id
            .strip_prefix("w-")
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| AdapterError::not_supported("get_tree: bad id"))?;
        let hwnd = HWND(hwnd_val as *mut _);
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
            let automation: IUIAutomation = CoCreateInstance(
                &windows::Win32::UI::Accessibility::CUIAutomation,
                None, CLSCTX_ALL,
            ).map_err(|e| AdapterError::not_supported(&format!("COM: {}", e)))?;
            let element = automation.ElementFromHandle(hwnd)
                .map_err(|e| AdapterError::not_supported(&format!("UIA: {}", e)))?;
            self.traverse_element(&element, opts, 0)
        }
    }

    fn resolve_element(&self, _entry: &RefEntry) -> Result<NativeHandle, AdapterError> {
        Err(AdapterError::not_supported("resolve_element: not yet implemented"))
    }

    fn execute_action(&self, handle: &NativeHandle, action: Action) -> Result<ActionResult, AdapterError> {
        if handle.as_raw().is_null() {
            return Err(AdapterError::not_supported("execute_action: null handle"));
        }
        unsafe {
            // Use std::mem::transmute_copy to reconstruct IUIAutomationElement from raw pointer
            let raw = handle.as_raw() as *mut std::ffi::c_void;
            let element = IUIAutomationElement::from_raw(raw as *mut _);

            match action {
                Action::Click | Action::DoubleClick | Action::RightClick => {
                    // Try UIA Invoke first
                    if matches!(action, Action::Click) {
                        if let Ok(pattern) = element.GetCurrentPattern(UIA_InvokePatternId) {
                            if let Ok(invoke) = pattern.cast::<IUIAutomationInvokePattern>() {
                                let _ = invoke.Invoke();
                                return Ok(ActionResult::new("click"));
                            }
                        }
                    }
                    // Fallback: coordinate click
                    let rect = element.CurrentBoundingRectangle()
                        .map_err(|e| AdapterError::not_supported(&e.to_string()))?;
                    let x = (rect.left + rect.right) as f64 / 2.0;
                    let y = (rect.top + rect.bottom) as f64 / 2.0;
                    let btn = if matches!(action, Action::RightClick) { MouseButton::Right } else { MouseButton::Left };
                    let count = if matches!(action, Action::DoubleClick) { 2 } else { 1 };
                    for _ in 0..count {
                        send_mouse(MouseEventKind::Down, btn.clone(), x, y)?;
                        send_mouse(MouseEventKind::Up, btn.clone(), x, y)?;
                    }
                    Ok(ActionResult::new("click"))
                }
                Action::SetValue(value) => {
                    if let Ok(pattern) = element.GetCurrentPattern(UIA_ValuePatternId) {
                        if let Ok(val_pattern) = pattern.cast::<IUIAutomationValuePattern>() {
                            let _ = val_pattern.SetValue(&BSTR::from(value.as_str()));
                            return Ok(ActionResult::new("set-value"));
                        }
                    }
                    Err(AdapterError::not_supported("set_value: ValuePattern not supported"))
                }
                _ => Err(AdapterError::not_supported("action not yet implemented")),
            }
        }
    }

    fn mouse_event(&self, event: MouseEvent) -> Result<(), AdapterError> {
        send_mouse(event.kind, event.button, event.point.x, event.point.y)
    }

    fn drag(&self, params: DragParams) -> Result<(), AdapterError> {
        send_mouse(MouseEventKind::Move, MouseButton::Left, params.from.x, params.from.y)?;
        send_mouse(MouseEventKind::Down, MouseButton::Left, params.from.x, params.from.y)?;
        send_mouse(MouseEventKind::Move, MouseButton::Left, params.to.x, params.to.y)?;
        send_mouse(MouseEventKind::Up,   MouseButton::Left, params.to.x, params.to.y)?;
        Ok(())
    }

    fn get_clipboard(&self) -> Result<String, AdapterError> {
        unsafe {
            OpenClipboard(None).map_err(|e| AdapterError::not_supported(&e.to_string()))?;
            let handle = GetClipboardData(CF_UNICODETEXT)
                .map_err(|e| { let _ = CloseClipboard(); AdapterError::not_supported(&e.to_string()) })?;
            let ptr = handle.0 as *const u16;
            let mut len = 0;
            while *ptr.add(len) != 0 { len += 1; }
            let text = String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len));
            let _ = CloseClipboard();
            Ok(text)
        }
    }

    fn set_clipboard(&self, text: &str) -> Result<(), AdapterError> {
        unsafe {
            OpenClipboard(None).map_err(|e| AdapterError::not_supported(&e.to_string()))?;
            let _ = EmptyClipboard();
            let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
            let hmem = GlobalAlloc(GMEM_MOVEABLE, wide.len() * 2)
                .map_err(|e| { let _ = CloseClipboard(); AdapterError::not_supported(&e.to_string()) })?;
            let dst = GlobalLock(hmem) as *mut u16;
            std::ptr::copy_nonoverlapping(wide.as_ptr(), dst, wide.len());
            let _ = GlobalUnlock(hmem);
            SetClipboardData(CF_UNICODETEXT, HANDLE(hmem.0))
                .map_err(|e| { let _ = CloseClipboard(); AdapterError::not_supported(&e.to_string()) })?;
            let _ = CloseClipboard();
        }
        Ok(())
    }

    fn clear_clipboard(&self) -> Result<(), AdapterError> {
        unsafe {
            OpenClipboard(None).map_err(|e| AdapterError::not_supported(&e.to_string()))?;
            let _ = EmptyClipboard();
            let _ = CloseClipboard();
        }
        Ok(())
    }
}
