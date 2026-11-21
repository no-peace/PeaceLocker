//! Explorer folder observations through Shell Automation on a dedicated COM STA.
//! COM interfaces never leave the worker thread.

use std::{
    ffi::c_void,
    sync::mpsc::{self, Receiver, RecvTimeoutError, Sender},
    thread::{self, JoinHandle},
    time::Duration,
};

use peacelocker_monitor::{ExplorerObservation, ExplorerWindowIdentity};
use thiserror::Error;
use windows::{
    core::{GUID, VARIANT},
    Win32::{
        System::Com::{
            CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_ALL,
            COINIT_APARTMENTTHREADED,
        },
        UI::Shell::{IShellWindows, IWebBrowser2},
    },
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, FILETIME, HANDLE},
    System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
    UI::WindowsAndMessaging::{GetClassNameW, GetWindowThreadProcessId, IsWindowVisible},
};

const CLSID_SHELL_WINDOWS: GUID = GUID::from_u128(0x9BA05972F6A811CFA44200A0C90A8F39);

#[derive(Debug, Error)]
pub enum ExplorerEnumerationError {
    #[error("Shell window enumeration failed")]
    ShellEnumeration,
}

#[derive(Debug)]
pub enum ExplorerMonitorMessage {
    Snapshot(Vec<ExplorerObservation>),
    Degraded(String),
    Stopped,
}

#[derive(Debug, Error)]
pub enum ExplorerMonitorStartError {
    #[error("Explorer monitor polling interval must be at least 250 ms")]
    InvalidInterval,
    #[error("Explorer monitor worker could not be started")]
    ThreadSpawn,
}

/// Worker owns its COM STA and joins on stop/drop.
pub struct ExplorerMonitorService {
    stop: Sender<()>,
    worker: Option<JoinHandle<()>>,
}

impl ExplorerMonitorService {
    pub fn start(interval: Duration) -> Result<(Self, Receiver<ExplorerMonitorMessage>), ExplorerMonitorStartError> {
        if interval < Duration::from_millis(250) {
            return Err(ExplorerMonitorStartError::InvalidInterval);
        }
        let (stop_tx, stop_rx) = mpsc::channel();
        let (message_tx, message_rx) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("peacelocker-explorer-sta".into())
            .spawn(move || {
                if unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }.is_err() {
                    let _ = message_tx.send(ExplorerMonitorMessage::Degraded("COM STA initialization failed".into()));
                    let _ = message_tx.send(ExplorerMonitorMessage::Stopped);
                    return;
                }
                let _apartment = ComApartment;
                let mut failures = 0u32;
                let mut delay = interval;
                loop {
                    match enumerate_explorer_windows() {
                        Ok(observations) => {
                            failures = 0;
                            delay = interval;
                            if message_tx.send(ExplorerMonitorMessage::Snapshot(observations)).is_err() { break; }
                        }
                        Err(_) => {
                            failures = failures.saturating_add(1);
                            let _ = message_tx.send(ExplorerMonitorMessage::Degraded(
                                format!("Explorer query failed ({failures} consecutive failures)")
                            ));
                            delay = delay.saturating_mul(2).min(Duration::from_secs(30));
                        }
                    }
                    match stop_rx.recv_timeout(delay) {
                        Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
                        Err(RecvTimeoutError::Timeout) => {}
                    }
                }
                let _ = message_tx.send(ExplorerMonitorMessage::Stopped);
            })
            .map_err(|_| ExplorerMonitorStartError::ThreadSpawn)?;
        Ok((Self { stop: stop_tx, worker: Some(worker) }, message_rx))
    }

    pub fn stop(&mut self) {
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}
impl Drop for ExplorerMonitorService {
    fn drop(&mut self) { self.stop(); }
}

struct ComApartment;
impl Drop for ComApartment {
    fn drop(&mut self) { unsafe { CoUninitialize(); } }
}

/// Enumerates real Explorer windows and accepts filesystem-backed file URLs
/// only. Virtual shell locations and window-title guesses are deliberately
/// excluded.
fn enumerate_explorer_windows() -> Result<Vec<ExplorerObservation>, ExplorerEnumerationError> {
    let shell: IShellWindows = unsafe {
        CoCreateInstance(&CLSID_SHELL_WINDOWS, None, CLSCTX_ALL)
    }.map_err(|_| ExplorerEnumerationError::ShellEnumeration)?;
    let count = unsafe { shell.Count() }.map_err(|_| ExplorerEnumerationError::ShellEnumeration)?;
    let mut observations = Vec::new();

    for index in 0..count {
        let variant = VARIANT::from(index);
        let dispatch = match unsafe { shell.Item(&variant) } { Ok(v) => v, Err(_) => continue };
        let browser: IWebBrowser2 = match dispatch.cast() { Ok(v) => v, Err(_) => continue };
        let hwnd = match unsafe { browser.HWND() } { Ok(v) => v as isize, Err(_) => continue };
        if !is_file_explorer_window(hwnd) { continue; }

        let location = match unsafe { browser.LocationURL() } { Ok(v) => v.to_string(), Err(_) => continue };
        let Ok(parsed) = url::Url::parse(&location) else { continue; };
        let Ok(path) = parsed.to_file_path() else { continue; };
        let Some((process_id, process_creation_time_100ns)) = window_process_identity(hwnd) else { continue; };

        observations.push(ExplorerObservation {
            identity: ExplorerWindowIdentity { hwnd, process_id, process_creation_time_100ns },
            folder_path: path.to_string_lossy().into_owned(),
        });
    }
    observations.sort_by_key(|item| item.identity);
    Ok(observations)
}

fn is_file_explorer_window(hwnd: isize) -> bool {
    if unsafe { IsWindowVisible(hwnd as *mut c_void) } == 0 { return false; }
    let mut class_name = [0u16; 128];
    let len = unsafe { GetClassNameW(hwnd as *mut c_void, class_name.as_mut_ptr(), class_name.len() as i32) };
    if len <= 0 { return false; }
    matches!(String::from_utf16_lossy(&class_name[..len as usize]).as_str(), "CabinetWClass" | "ExploreWClass")
}

fn window_process_identity(hwnd: isize) -> Option<(u32, u64)> {
    let mut pid = 0u32;
    if unsafe { GetWindowThreadProcessId(hwnd as *mut c_void, &mut pid) } == 0 || pid == 0 { return None; }
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() { return None; }
    let _guard = ProcessHandle(process);
    let mut created: FILETIME = unsafe { std::mem::zeroed() };
    let mut exited: FILETIME = unsafe { std::mem::zeroed() };
    let mut kernel: FILETIME = unsafe { std::mem::zeroed() };
    let mut user: FILETIME = unsafe { std::mem::zeroed() };
    if unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) } == 0 { return None; }
    let ticks = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    (ticks != 0).then_some((pid, ticks))
}

struct ProcessHandle(HANDLE);
impl Drop for ProcessHandle {
    fn drop(&mut self) { unsafe { CloseHandle(self.0); } }
}
