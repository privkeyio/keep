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

    if backtrace.status() == std::backtrace::BacktraceStatus::Captured {
        if std::env::var("KEEP_NO_BACKTRACE").is_err() {
            eprintln!("\nBacktrace (may reveal function call patterns - set KEEP_NO_BACKTRACE=1 to disable):\n{}", backtrace);
        }
    }
}

fn extract_panic_message(info: &PanicHookInfo<'_>) -> String {
    let payload = info.payload();
    let msg = payload
        .downcast_ref::<&str>()
        .map(|s| *s)
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

    #[cfg(not(unix))]
    std::fs::write(&path, content)?;

    eprintln!("Crash dump written to: {}", path.display());
    Ok(path)
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
