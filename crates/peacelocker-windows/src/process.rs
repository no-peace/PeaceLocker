//! Process enumeration through documented Windows APIs.
//!
//! Uses Tool Help snapshots, OpenProcess, GetProcessTimes, and
//! QueryFullProcessImageNameW. Access-denied processes are counted and
//! skipped; the source never attempts to elevate privileges.

use std::{ffi::OsString, os::windows::ffi::OsStringExt};

use peacelocker_monitor::{ProcessIdentity, ProcessSnapshot};
use thiserror::Error;
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, FILETIME, HANDLE, ERROR_NO_MORE_FILES},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        },
        Threading::{
            GetProcessTimes, OpenProcess, QueryFullProcessImageNameW,
            PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessEnumeration {
    pub processes: Vec<ProcessSnapshot>,
    /// Processes that could not be queried for a stable creation-time identity.
    pub inaccessible_count: u32,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProcessEnumerationError {
    #[error("Windows process snapshot could not be created")]
    SnapshotCreation,
    #[error("Windows process snapshot enumeration failed")]
    SnapshotEnumeration,
}

/// Enumerate visible processes without requiring administrator privileges.
///
/// Processes for which Windows denies query access are skipped and counted.
/// A process is included only when its creation timestamp can be read, because
/// PID alone is not a safe lifetime identity (Windows can reuse PIDs).
pub fn enumerate_processes() -> Result<ProcessEnumeration, ProcessEnumerationError> {
    // SAFETY: CreateToolhelp32Snapshot is a documented Win32 API. The returned
    // handle is checked against INVALID_HANDLE_VALUE and closed by HandleGuard.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(ProcessEnumerationError::SnapshotCreation);
    }
    let _snapshot_guard = HandleGuard(snapshot);

    // SAFETY: PROCESSENTRY32W is a plain C struct; zero initialization is valid.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    // SAFETY: snapshot is a valid Tool Help snapshot handle and entry points to
    // writable storage of the exact documented structure size.
    if unsafe { Process32FirstW(snapshot, &mut entry) } == 0 {
        return Err(ProcessEnumerationError::SnapshotEnumeration);
    }

    let mut result = ProcessEnumeration {
        processes: Vec::new(),
        inaccessible_count: 0,
    };

    loop {
        let pid = entry.th32ProcessID;
        let name = nul_terminated(&entry.szExeFile);

        if pid != 0 {
            // SAFETY: OpenProcess is called with query-only rights and a PID
            // obtained from the current system process snapshot.
            let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
            if process.is_null() {
                result.inaccessible_count = result.inaccessible_count.saturating_add(1);
            } else {
                let _process_guard = HandleGuard(process);
                match query_process(process, pid, name) {
                    Some(observation) => result.processes.push(observation),
                    None => {
                        result.inaccessible_count =
                            result.inaccessible_count.saturating_add(1);
                    }
                }
            }
        }

        // SAFETY: same valid snapshot handle and writable structure as above.
        if unsafe { Process32NextW(snapshot, &mut entry) } == 0 {
            // ERROR_NO_MORE_FILES is the normal end-of-snapshot condition.
            // Any other error means enumeration was incomplete.
            if unsafe { GetLastError() } == ERROR_NO_MORE_FILES {
                break;
            }
            return Err(ProcessEnumerationError::SnapshotEnumeration);
        }
    }

    result.processes.sort_by_key(|process| process.identity.pid);
    Ok(result)
}

fn query_process(process: HANDLE, pid: u32, name: String) -> Option<ProcessSnapshot> {
    // SAFETY: FILETIME values are plain output structs and all pointers are
    // valid writable references for the duration of the call.
    let mut creation: FILETIME = unsafe { std::mem::zeroed() };
    let mut exit: FILETIME = unsafe { std::mem::zeroed() };
    let mut kernel: FILETIME = unsafe { std::mem::zeroed() };
    let mut user: FILETIME = unsafe { std::mem::zeroed() };
    // SAFETY: process is a live handle opened with PROCESS_QUERY_LIMITED_INFORMATION.
    if unsafe {
        GetProcessTimes(
            process,
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return None;
    }

    let creation_time_100ns =
        (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    if creation_time_100ns == 0 {
        return None;
    }

    let mut path_buffer = vec![0u16; 32_768];
    let mut path_len = path_buffer.len() as u32;
    // SAFETY: process is a valid query handle and path_buffer has path_len
    // writable UTF-16 elements. The API updates path_len with characters used.
    let executable_path = if unsafe {
        QueryFullProcessImageNameW(
            process,
            0,
            path_buffer.as_mut_ptr(),
            &mut path_len,
        )
    } != 0
    {
        Some(OsString::from_wide(&path_buffer[..path_len as usize])
            .to_string_lossy()
            .into_owned())
    } else {
        None
    };

    Some(ProcessSnapshot {
        identity: ProcessIdentity {
            pid,
            creation_time_100ns,
        },
        name,
        executable_path,
    })
}

fn nul_terminated(value: &[u16]) -> String {
    let end = value.iter().position(|unit| *unit == 0).unwrap_or(value.len());
    OsString::from_wide(&value[..end])
        .to_string_lossy()
        .into_owned()
}

const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        // SAFETY: this guard is created only for a successful, owned Win32
        // handle and Drop runs once for that ownership.
        unsafe {
            CloseHandle(self.0);
        }
    }
}
