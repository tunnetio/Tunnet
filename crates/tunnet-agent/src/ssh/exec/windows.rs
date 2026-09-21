//! Windows SSH sessions run under a logged-on user token. Never LocalSystem.

use std::ffi::c_void;
use std::fs::File;
use std::os::windows::io::{FromRawHandle, OwnedHandle, RawHandle};
use std::ptr;

use anyhow::bail;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::{EqualSid, GetTokenInformation, TOKEN_USER, TokenUser};
use windows_sys::Win32::System::Console::{
    COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, ResizePseudoConsole,
};
use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::RemoteDesktop::{
    WTS_CURRENT_SERVER_HANDLE, WTSActive, WTSEnumerateSessionsW, WTSFreeMemory, WTSQueryUserToken,
};
use windows_sys::Win32::System::Threading::{
    CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, INFINITE, InitializeProcThreadAttributeList,
    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROCESS_INFORMATION, STARTUPINFOEXW,
    UpdateProcThreadAttribute, WaitForSingleObject,
};

use super::{LaunchRequest, SessionProcess, child_argv};
use crate::actors::ssh_registry::SessionKill;
use crate::ssh::account::LocalAccount;

struct ConptyKiller {
    process: HANDLE,
    thread: HANDLE,
    hpcon: std::sync::Arc<std::sync::Mutex<Option<HPCON>>>,
    exited: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

unsafe impl Send for ConptyKiller {}
unsafe impl Sync for ConptyKiller {}

impl SessionKill for ConptyKiller {
    fn kill(&mut self) {
        unsafe {
            windows_sys::Win32::System::Threading::TerminateProcess(self.process, 1);
        }
    }
}

impl Drop for ConptyKiller {
    fn drop(&mut self) {
        self.exited
            .store(true, std::sync::atomic::Ordering::Relaxed);
        unsafe {
            windows_sys::Win32::System::Threading::TerminateProcess(self.process, 1);
            if let Some(hpcon) = self.hpcon.lock().ok().and_then(|mut g| g.take()) {
                ClosePseudoConsole(hpcon);
            }
            CloseHandle(self.thread);
            CloseHandle(self.process);
        }
    }
}

pub fn spawn_shell(req: &LaunchRequest) -> anyhow::Result<SessionProcess> {
    let token = user_token_for_sid(&req.account.sid)?;
    let shell = req.account.shell.display();
    let cmdline = if let Some(command) = &req.command {
        wide_cmdline(&format!(
            "{shell} -NoLogo -NoProfile -NonInteractive -Command {command}"
        ))
    } else {
        wide_cmdline(&format!("{shell} -NoLogo -NoProfile"))
    };
    spawn_conpty(
        token,
        cmdline,
        req.width,
        req.height,
        req.account.home_dir.to_string_lossy().as_ref(),
        &req.term,
        &req.env_vars,
    )
}

pub fn spawn_sftp(account: &LocalAccount) -> anyhow::Result<tokio::process::Child> {
    let _token = user_token_for_sid(&account.sid)?;
    let _ = (child_argv(), super::sanitized_path());
    bail!(
        "Windows SFTP is not available yet; interactive SSH requires an active logon token and ConPTY"
    )
}

fn spawn_conpty(
    token: OwnedHandle,
    mut cmdline: Vec<u16>,
    cols: u16,
    rows: u16,
    home: &str,
    term: &str,
    env_vars: &[(String, String)],
) -> anyhow::Result<SessionProcess> {
    let (input_read, input_write) = anon_pipe()?;
    let (output_read, output_write) = anon_pipe()?;
    let size = COORD {
        X: cols.max(1) as i16,
        Y: rows.max(1) as i16,
    };
    let mut hpcon: HPCON = 0;
    let hr = unsafe {
        CreatePseudoConsole(
            size,
            input_read.as_raw() as HANDLE,
            output_write.as_raw() as HANDLE,
            0,
            &mut hpcon,
        )
    };
    if hr != 0 {
        bail!("CreatePseudoConsole failed: HRESULT 0x{hr:08X}");
    }
    drop(input_read);
    drop(output_write);

    let mut attr_size = 0usize;
    unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut attr_size) };
    let mut attr_buf = vec![0u8; attr_size];
    let attr_list = attr_buf.as_mut_ptr().cast();
    if unsafe { InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size) } == 0 {
        unsafe { ClosePseudoConsole(hpcon) };
        bail!("InitializeProcThreadAttributeList failed");
    }
    if unsafe {
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
            hpcon as *const c_void as *mut c_void,
            size_of::<HPCON>(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    } == 0
    {
        unsafe {
            DeleteProcThreadAttributeList(attr_list);
            ClosePseudoConsole(hpcon);
        }
        bail!("UpdateProcThreadAttribute failed");
    }

    let mut env = ptr::null_mut();
    let _ = unsafe { CreateEnvironmentBlock(&mut env, token.as_raw() as HANDLE, FALSE_I32) };
    let _ = (term, env_vars);
    let home_wide: Vec<u16> = home.encode_utf16().chain(std::iter::once(0)).collect();

    let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    si.lpAttributeList = attr_list;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let created = unsafe {
        CreateProcessAsUserW(
            token.as_raw() as HANDLE,
            ptr::null(),
            cmdline.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            env,
            home_wide.as_ptr(),
            &si.StartupInfo,
            &mut pi,
        )
    };
    unsafe { DeleteProcThreadAttributeList(attr_list) };
    if !env.is_null() {
        unsafe { DestroyEnvironmentBlock(env) };
    }
    if created == 0 {
        unsafe { ClosePseudoConsole(hpcon) };
        bail!(
            "CreateProcessAsUser failed: {}",
            std::io::Error::last_os_error()
        );
    }

    let reader = unsafe { File::from_raw_handle(output_read.into_raw()) };
    let writer = unsafe { File::from_raw_handle(input_write.into_raw()) };
    let (resize_tx, resize_rx) = std::sync::mpsc::channel::<(u16, u16)>();
    let hpcon_slot = std::sync::Arc::new(std::sync::Mutex::new(Some(hpcon)));
    let hpcon_for_resize = hpcon_slot.clone();
    std::thread::spawn(move || {
        while let Ok((cols, rows)) = resize_rx.recv() {
            let Some(hpcon) = hpcon_for_resize.lock().ok().and_then(|g| *g) else {
                break;
            };
            let size = COORD {
                X: cols.max(1) as i16,
                Y: rows.max(1) as i16,
            };
            unsafe {
                ResizePseudoConsole(hpcon, size);
            }
        }
    });
    let hpcon_for_exit = hpcon_slot.clone();
    let exited = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let exited_flag = exited.clone();
    let process_bits = pi.hProcess as usize;
    std::thread::spawn(move || {
        unsafe {
            WaitForSingleObject(process_bits as HANDLE, INFINITE);
        }
        if exited_flag.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        if let Some(hpcon) = hpcon_for_exit.lock().ok().and_then(|mut g| g.take()) {
            unsafe { ClosePseudoConsole(hpcon) };
        }
    });
    Ok(SessionProcess {
        reader: Box::new(reader),
        writer: Box::new(writer),
        killer: Box::new(ConptyKiller {
            process: pi.hProcess,
            thread: pi.hThread,
            hpcon: hpcon_slot,
            exited,
        }),
        resize: Some(resize_tx),
    })
}

struct PipeHandle(HANDLE);
impl PipeHandle {
    fn as_raw(&self) -> HANDLE {
        self.0
    }
    fn into_raw(self) -> RawHandle {
        let h = self.0;
        std::mem::forget(self);
        h as RawHandle
    }
}
impl Drop for PipeHandle {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE_VALUE && !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

fn anon_pipe() -> anyhow::Result<(PipeHandle, PipeHandle)> {
    let mut read = INVALID_HANDLE_VALUE;
    let mut write = INVALID_HANDLE_VALUE;
    if unsafe { CreatePipe(&mut read, &mut write, ptr::null(), 0) } == 0 {
        bail!("CreatePipe failed: {}", std::io::Error::last_os_error());
    }
    Ok((PipeHandle(read), PipeHandle(write)))
}

fn wide_cmdline(cmd: &str) -> Vec<u16> {
    cmd.encode_utf16().chain(std::iter::once(0)).collect()
}

const FALSE_I32: i32 = 0;

fn user_token_for_sid(sid: &str) -> anyhow::Result<OwnedHandle> {
    let want = string_sid_to_sid(sid)?;
    let mut info = ptr::null_mut();
    let mut count = 0u32;
    let ok =
        unsafe { WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut info, &mut count) };
    if ok == 0 || info.is_null() {
        unsafe { LocalFree(want.cast()) };
        bail!(
            "no usable Windows logon session; Tunnet's passwordless Windows SSH backend requires an active logon for the requested account"
        );
    }
    let mut found = None;
    for i in 0..count {
        let session = unsafe { &*info.add(i as usize) };
        if session.State != WTSActive {
            continue;
        }
        let mut token: HANDLE = INVALID_HANDLE_VALUE;
        let ok = unsafe { WTSQueryUserToken(session.SessionId, &mut token) };
        if ok == 0 || token == INVALID_HANDLE_VALUE {
            continue;
        }
        if token_sid_equals(token, want) {
            found = Some(token);
            break;
        }
        unsafe { CloseHandle(token) };
    }
    unsafe { WTSFreeMemory(info.cast()) };
    unsafe { LocalFree(want.cast()) };
    found
        .map(|h| unsafe { OwnedHandle::from_raw_handle(h as RawHandle) })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "requested Windows account has no active logon session; Tunnet will not fall back to SYSTEM"
            )
        })
}

fn token_sid_equals(token: HANDLE, want: *mut c_void) -> bool {
    let mut needed = 0u32;
    unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return false;
    }
    let mut buf = vec![0u8; needed as usize];
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return false;
    }
    let user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    unsafe { EqualSid(user.User.Sid, want) != 0 }
}

fn string_sid_to_sid(sid: &str) -> anyhow::Result<*mut c_void> {
    let wide: Vec<u16> = sid.encode_utf16().chain(std::iter::once(0)).collect();
    let mut out = ptr::null_mut();
    let ok = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut out) };
    if ok == 0 || out.is_null() {
        bail!("invalid SID {sid}");
    }
    Ok(out)
}

trait HandleRaw {
    fn as_raw(&self) -> HANDLE;
}
impl HandleRaw for OwnedHandle {
    fn as_raw(&self) -> HANDLE {
        self.as_raw_handle() as HANDLE
    }
}
use std::os::windows::io::AsRawHandle;

#[cfg(test)]
mod tests {
    use super::user_token_for_sid;

    #[test]
    fn missing_sid_fails_closed() {
        let err = user_token_for_sid("S-1-5-99-1-2-3-4").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("no active logon")
                || msg.contains("no usable")
                || msg.contains("invalid SID"),
            "{msg}"
        );
    }
}
