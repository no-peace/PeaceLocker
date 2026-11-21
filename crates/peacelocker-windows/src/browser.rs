//! Read-only active-browser URL observer using Windows UI Automation.
//! All COM objects are created, used and released on one dedicated STA worker.

use std::{ffi::c_void, os::windows::ffi::OsStringExt, sync::mpsc::{self, Receiver, RecvTimeoutError, Sender}, thread::{self, JoinHandle}, time::Duration};
use peacelocker_monitor::{normalize_browser_url, BrowserObservation, BrowserWindowIdentity};
use thiserror::Error;
use windows::{
    core::{Interface, VARIANT},
    Win32::{
        System::Com::{CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED},
        UI::Accessibility::{CUIAutomation, IUIAutomation, IUIAutomationValuePattern, TreeScope_Descendants, UIA_AutomationIdPropertyId, UIA_ValuePatternId},
    },
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, FILETIME, HANDLE},
    System::Threading::{OpenProcess, QueryFullProcessImageNameW, GetProcessTimes, PROCESS_QUERY_LIMITED_INFORMATION},
    UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId},
};

#[derive(Debug, Error)]
pub enum BrowserMonitorStartError {
    #[error("browser monitor interval must be at least 500 ms")] InvalidInterval,
    #[error("browser monitor worker could not be started")] ThreadSpawn,
}
#[derive(Debug)]
pub enum BrowserMonitorMessage { Snapshot(BrowserObservation), NoSupportedBrowser, Degraded(String), Stopped }

pub struct BrowserMonitorService { stop: Sender<()>, worker: Option<JoinHandle<()>> }

impl BrowserMonitorService {
    pub fn start(interval: Duration) -> Result<(Self, Receiver<BrowserMonitorMessage>), BrowserMonitorStartError> {
        if interval < Duration::from_millis(500) { return Err(BrowserMonitorStartError::InvalidInterval); }
        let (stop_tx, stop_rx) = mpsc::channel();
        let (message_tx, message_rx) = mpsc::channel();
        let worker = thread::Builder::new().name("peacelocker-browser-uia".into()).spawn(move || {
            if unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }.ok().is_err() {
                let _ = message_tx.send(BrowserMonitorMessage::Degraded("COM STA initialization failed".into()));
                let _ = message_tx.send(BrowserMonitorMessage::Stopped); return;
            }
            let _apartment = ComApartment;
            let automation: IUIAutomation = match unsafe { CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER) } {
                Ok(value) => value,
                Err(_) => {
                    let _ = message_tx.send(BrowserMonitorMessage::Degraded("UI Automation initialization failed".into()));
                    let _ = message_tx.send(BrowserMonitorMessage::Stopped); return;
                }
            };
            let mut failures = 0u32;
            let mut delay = interval;
            loop {
                match enumerate_active_browser(&automation) {
                    Ok(Some(observation)) => {
                        failures = 0; delay = interval;
                        if message_tx.send(BrowserMonitorMessage::Snapshot(observation)).is_err() { break; }
                    }
                    Ok(None) => {
                        failures = 0; delay = interval;
                        if message_tx.send(BrowserMonitorMessage::NoSupportedBrowser).is_err() { break; }
                    }
                    Err(_) => {
                        failures = failures.saturating_add(1);
                        let _ = message_tx.send(BrowserMonitorMessage::Degraded(format!("Browser address-bar query failed ({failures} consecutive failures)")));
                        delay = delay.saturating_mul(2).min(Duration::from_secs(30));
                    }
                }
                match stop_rx.recv_timeout(delay) {
                    Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
                    Err(RecvTimeoutError::Timeout) => {}
                }
            }
            let _ = message_tx.send(BrowserMonitorMessage::Stopped);
        }).map_err(|_| BrowserMonitorStartError::ThreadSpawn)?;
        Ok((Self { stop: stop_tx, worker: Some(worker) }, message_rx))
    }
    pub fn stop(&mut self) {
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}
impl Drop for BrowserMonitorService { fn drop(&mut self) { self.stop(); } }
struct ComApartment;
impl Drop for ComApartment { fn drop(&mut self) { unsafe { CoUninitialize(); } } }

fn enumerate_active_browser(automation: &IUIAutomation) -> Result<Option<BrowserObservation>, ()> {
    let hwnd = unsafe { GetForegroundWindow() };
    if hwnd.is_null() { return Ok(None); }
    let mut pid = 0u32;
    if unsafe { GetWindowThreadProcessId(hwnd, &mut pid) } == 0 || pid == 0 { return Ok(None); }
    let Some((browser, creation_time)) = browser_process(pid) else { return Ok(None); };
    let root = unsafe { automation.ElementFromHandle(hwnd) }.map_err(|_| ())?;
    // Restrict reads to known browser address-bar AutomationIds. Never scan
    // arbitrary Edit controls, which may contain passwords or page form data.
    let ids: &[&str] = match browser.as_str() {
        "chrome.exe" | "brave.exe" | "vivaldi.exe" => &["omnibox"],
        "msedge.exe" => &["addressEditBox", "omnibox"],
        "firefox.exe" => &["urlbar-input"],
        "opera.exe" => &["addressbar"],
        _ => return Ok(None),
    };
    for id in ids {
        let condition = unsafe { automation.CreatePropertyCondition(UIA_AutomationIdPropertyId, &VARIANT::from(*id)) }.map_err(|_| ())?;
        let element = match unsafe { root.FindFirst(TreeScope_Descendants, &condition) } { Ok(element) => element, Err(_) => continue };
        if unsafe { element.CurrentIsPassword() }.map(|value| value.0 != 0).unwrap_or(true) { continue; }
        let pattern: IUIAutomationValuePattern = match unsafe { element.GetCurrentPatternAs(UIA_ValuePatternId) } {
            Ok(pattern) => pattern, Err(_) => continue,
        };
        let value = unsafe { pattern.CurrentValue() }.map_err(|_| ())?.to_string();
        let Some(hostname) = normalize_browser_url(&value) else { continue; };
        return Ok(Some(BrowserObservation {
            identity: BrowserWindowIdentity { hwnd: hwnd as isize, process_id: pid, process_creation_time_100ns: creation_time },
            browser, hostname,
        }));
    }
    Ok(None)
}

fn browser_process(pid: u32) -> Option<(String, u64)> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() { return None; }
    let _guard = ProcessHandle(process);
    let mut buffer = vec![0u16; 32_768];
    let mut length = buffer.len() as u32;
    if unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut length) } == 0 { return None; }
    let path = std::ffi::OsString::from_wide(&buffer[..length as usize]).to_string_lossy().into_owned();
    let name = path.rsplit(['\\', '/']).next()?.to_ascii_lowercase();
    if !matches!(name.as_str(), "chrome.exe" | "msedge.exe" | "firefox.exe" | "brave.exe" | "vivaldi.exe" | "opera.exe") { return None; }
    let mut created: FILETIME = unsafe { std::mem::zeroed() };
    let mut exited: FILETIME = unsafe { std::mem::zeroed() };
    let mut kernel: FILETIME = unsafe { std::mem::zeroed() };
    let mut user: FILETIME = unsafe { std::mem::zeroed() };
    if unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) } == 0 { return None; }
    let ticks = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    (ticks != 0).then_some((name, ticks))
}
struct ProcessHandle(HANDLE);
impl Drop for ProcessHandle { fn drop(&mut self) { unsafe { CloseHandle(self.0); } } }
