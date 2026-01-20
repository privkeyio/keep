#![forbid(unsafe_code)]

use std::backtrace::Backtrace;
use std::panic::PanicHookInfo;
use std::path::PathBuf;

pub fn install() {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        cleanup_terminal();
        log_panic(info);
        original_hook(info);
    }));
}

fn cleanup_terminal() {
    let _ = crossterm::terminal::disable_raw_mode();
    let _ = crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen);
}

fn log_panic(info: &PanicHookInfo<'_>) {
    let backtrace = Backtrace::capture();
    let location = info
        .location()
        .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()));
    let message = extract_panic_message(info);

    tracing::error!(
        panic.file = location.as_deref().unwrap_or("unknown"),
        panic.message = %message,
        "panic occurred"
    );

    if std::env::var("KEEP_CRASH_DUMP").is_ok() {
        if let Err(e) = write_crash_dump(&message, location.as_deref(), &backtrace) {
            tracing::warn!(error = %e, "failed to write crash dump");
        }
    }

    if backtrace.status() == std::backtrace::BacktraceStatus::Captured
        && std::env::var("KEEP_NO_BACKTRACE").is_err()
    {
        eprintln!("\nBacktrace (may reveal function call patterns - set KEEP_NO_BACKTRACE=1 to disable):\n{}", backtrace);
    }
}

fn extract_panic_message(info: &PanicHookInfo<'_>) -> String {
    let payload = info.payload();
    let msg = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(|s| s.as_str()));

    match msg {
        Some(s) => sanitize_message(s),
        None => "unknown panic".to_string(),
    }
}

fn sanitize_message(msg: &str) -> String {
    const SENSITIVE_PATTERNS: &[&str] = &[
        "password",
        "secret",
        "key",
        "nsec",
        "private",
        "credential",
        "token",
        "auth",
        "mnemonic",
        "seed",
        "xprv",
        "share",
        "nonce",
        "commitment",
    ];

    let lower = msg.to_lowercase();
    for pattern in SENSITIVE_PATTERNS {
        if lower.contains(pattern) {
            return "[redacted - potentially sensitive]".to_string();
        }
    }
    msg.to_string()
}

fn write_crash_dump(
    message: &str,
    location: Option<&str>,
    backtrace: &Backtrace,
) -> std::io::Result<PathBuf> {
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let filename = format!("keep_crash_{}.log", timestamp);
    let path = std::env::temp_dir().join(&filename);

    let content = format!(
        "Keep Crash Report\n\
         ==================\n\
         Time: {}\n\
         Location: {}\n\
         Message: {}\n\n\
         Backtrace:\n{}\n",
        chrono::Utc::now().to_rfc3339(),
        location.unwrap_or("unknown"),
        message,
        backtrace
    );

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(content.as_bytes())?;
    }

    #[cfg(windows)]
    {
        write_crash_dump_windows(&path, &content)?;
    }

    #[cfg(not(any(unix, windows)))]
    std::fs::write(&path, content)?;

    eprintln!("Crash dump written to: {}", path.display());
    Ok(path)
}

#[cfg(windows)]
fn write_crash_dump_windows(path: &std::path::Path, content: &str) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, GENERIC_WRITE, INVALID_HANDLE_VALUE, PSID,
    };
    use windows_sys::Win32::Security::Authorization::{
        SetEntriesInAclW, EXPLICIT_ACCESS_W, NO_INHERITANCE, SET_ACCESS, TRUSTEE_IS_SID,
        TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, InitializeSecurityDescriptor, SetSecurityDescriptorDacl, TokenUser,
        DACL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
        SECURITY_DESCRIPTOR_REVISION, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, WriteFile, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
    };
    use windows_sys::Win32::System::Memory::{GetProcessHeap, HeapAlloc, HeapFree};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    const GENERIC_ALL: u32 = 0x10000000;

    unsafe {
        let mut token_handle = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle) == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut token_info_len: u32 = 0;
        GetTokenInformation(
            token_handle,
            TokenUser,
            ptr::null_mut(),
            0,
            &mut token_info_len,
        );

        let heap = GetProcessHeap();
        let token_info = HeapAlloc(heap, 0, token_info_len as usize);
        if token_info.is_null() {
            CloseHandle(token_handle);
            return Err(std::io::Error::from_raw_os_error(8)); // ERROR_NOT_ENOUGH_MEMORY
        }

        if GetTokenInformation(
            token_handle,
            TokenUser,
            token_info,
            token_info_len,
            &mut token_info_len,
        ) == 0
        {
            HeapFree(heap, 0, token_info);
            CloseHandle(token_handle);
            return Err(std::io::Error::last_os_error());
        }

        let token_user = &*(token_info as *const TOKEN_USER);
        let user_sid: PSID = token_user.User.Sid;

        let mut ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_ALL,
            grfAccessMode: SET_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: ptr::null_mut(),
                MultipleTrusteeOperation: 0,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: user_sid as *mut u16,
            },
        };

        let mut acl = ptr::null_mut();
        let result = SetEntriesInAclW(1, &mut ea, ptr::null_mut(), &mut acl);
        if result != 0 {
            HeapFree(heap, 0, token_info);
            CloseHandle(token_handle);
            return Err(std::io::Error::from_raw_os_error(result as i32));
        }

        let mut sd: SECURITY_DESCRIPTOR = std::mem::zeroed();
        if InitializeSecurityDescriptor(&mut sd, SECURITY_DESCRIPTOR_REVISION) == 0 {
            LocalFree(acl as _);
            HeapFree(heap, 0, token_info);
            CloseHandle(token_handle);
            return Err(std::io::Error::last_os_error());
        }

        if SetSecurityDescriptorDacl(&mut sd, 1, acl, 0) == 0 {
            LocalFree(acl as _);
            HeapFree(heap, 0, token_info);
            CloseHandle(token_handle);
            return Err(std::io::Error::last_os_error());
        }

        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: &mut sd as *mut _ as *mut _,
            bInheritHandle: 0,
        };

        let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();

        let file_handle = CreateFileW(
            wide_path.as_ptr(),
            GENERIC_WRITE,
            0, // No sharing
            &mut sa,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        );

        LocalFree(acl as _);
        HeapFree(heap, 0, token_info);
        CloseHandle(token_handle);

        if file_handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }

        let bytes = content.as_bytes();
        let mut written: u32 = 0;
        let write_result = WriteFile(
            file_handle,
            bytes.as_ptr(),
            bytes.len() as u32,
            &mut written,
            ptr::null_mut(),
        );

        CloseHandle(file_handle);

        if write_result == 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_message_clean() {
        let msg = "index out of bounds";
        assert_eq!(sanitize_message(msg), msg);
    }

    #[test]
    fn test_sanitize_message_sensitive() {
        assert_eq!(
            sanitize_message("failed to decrypt password"),
            "[redacted - potentially sensitive]"
        );
        assert_eq!(
            sanitize_message("invalid SECRET key format"),
            "[redacted - potentially sensitive]"
        );
        assert_eq!(
            sanitize_message("nsec1abc..."),
            "[redacted - potentially sensitive]"
        );
    }
}
