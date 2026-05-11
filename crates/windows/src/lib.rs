#[cfg(target_os = "windows")]
mod win_impl;

#[cfg(target_os = "windows")]
pub use win_impl::WindowsAdapter;

#[cfg(not(target_os = "windows"))]
pub struct WindowsAdapter;

#[cfg(not(target_os = "windows"))]
impl WindowsAdapter {
    pub fn new() -> Self { Self }
}

#[cfg(not(target_os = "windows"))]
impl Default for WindowsAdapter {
    fn default() -> Self { Self::new() }
}

#[cfg(not(target_os = "windows"))]
impl agent_desktop_core::adapter::PlatformAdapter for WindowsAdapter {}
