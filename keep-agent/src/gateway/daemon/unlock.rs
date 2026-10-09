// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The vault password the gateway unlocks with, read from a systemd
//! credential: systemd decrypts it (sealed to the TPM, or to the host) into a
//! private directory it names in `$CREDENTIALS_DIRECTORY`, so the password is
//! never at rest in plaintext and never in the environment.

use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use zeroize::Zeroizing;

use crate::error::{AgentError, Result};

/// The name of the credential holding the vault password.
pub const PASSWORD_CREDENTIAL: &str = "vault-password";

/// The longest password read.
pub const MAX_PASSWORD: usize = 4096;

/// Whether `uid` may own the credentials directory or a credential in it:
/// systemd creates them as root and grants the service's user access, or
/// gives them to that user.
fn trusted_owner(uid: u32, euid: u32) -> bool {
    uid == 0 || uid == euid
}

/// Read credential `name` from the credentials directory `dir`, for a
/// process running as `euid`.
///
/// The directory must be a real directory owned by root or `euid` that no
/// one else can write. The credential must be a regular file, not a symlink,
/// owned by root or `euid`, that no one else can write or other users read,
/// of at most [`MAX_PASSWORD`] bytes of UTF-8 on one line. One trailing
/// newline (`\n` or `\r\n`) is dropped, as `echo` and editors add one. The
/// file's contents are never put in an error.
pub fn read_credential(dir: &Path, name: &str, euid: u32) -> Result<Zeroizing<String>> {
    let fail =
        |m: String| AgentError::Other(format!("credential {name:?} in {}: {m}", dir.display()));
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(fail("not a credential name".into()));
    }
    if !dir.is_absolute() {
        return Err(fail(
            "the credentials directory is not an absolute path".into(),
        ));
    }
    let meta = std::fs::symlink_metadata(dir)
        .map_err(|e| fail(format!("the credentials directory cannot be read: {e}")))?;
    if !meta.file_type().is_dir() {
        return Err(fail("the credentials directory is not a directory".into()));
    }
    if !trusted_owner(meta.uid(), euid) {
        return Err(fail(format!(
            "the credentials directory is owned by uid {}, not root or uid {euid}",
            meta.uid()
        )));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(fail(format!(
            "the credentials directory has mode {:o}; others could replace the credential",
            meta.mode() & 0o7777
        )));
    }
    // Not through a symlink, and non-blocking, so a FIFO in its place cannot
    // hang the open.
    let flags =
        rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOCTTY;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags.bits() as i32)
        .open(dir.join(name))
        .map_err(|e| {
            if e.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) {
                fail("is a symlink".into())
            } else {
                fail(e.to_string())
            }
        })?;
    let meta = file.metadata().map_err(|e| fail(e.to_string()))?;
    if !meta.file_type().is_file() {
        return Err(fail("is not a regular file".into()));
    }
    if !trusted_owner(meta.uid(), euid) {
        return Err(fail(format!(
            "is owned by uid {}, not root or uid {euid}",
            meta.uid()
        )));
    }
    if meta.mode() & 0o027 != 0 {
        return Err(fail(format!(
            "has mode {:o}; it must be closed to other users and writable by its owner alone",
            meta.mode() & 0o7777
        )));
    }
    if meta.len() > MAX_PASSWORD as u64 {
        return Err(fail(format!("is larger than {MAX_PASSWORD} bytes")));
    }
    let mut buf = Zeroizing::new([0u8; MAX_PASSWORD + 1]);
    let mut len = 0;
    loop {
        match file.read(&mut buf[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(fail(e.to_string())),
        }
    }
    if len > MAX_PASSWORD {
        return Err(fail(format!("is larger than {MAX_PASSWORD} bytes")));
    }
    let mut text = &buf[..len];
    if let Some(rest) = text.strip_suffix(b"\n") {
        text = rest.strip_suffix(b"\r").unwrap_or(rest);
    }
    if text.is_empty() {
        return Err(fail("is empty".into()));
    }
    if text.iter().any(|&b| b == b'\n' || b == b'\r' || b == 0) {
        return Err(fail(
            "holds more than one line, or a NUL byte; it must hold the password alone".into(),
        ));
    }
    let text = std::str::from_utf8(text).map_err(|_| fail("is not UTF-8".into()))?;
    let mut password = Zeroizing::new(String::with_capacity(text.len()));
    password.push_str(text);
    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    const PASSWORD: &str = "correct horse battery staple";

    fn me() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    /// A credentials directory like the one systemd makes, holding `contents`
    /// as the credential, with the given modes.
    fn creds(contents: &[u8], dir_mode: u32, file_mode: u32) -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("credentials");
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join(PASSWORD_CREDENTIAL);
        std::fs::write(&file, contents).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(file_mode)).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(dir_mode)).unwrap();
        (root, dir)
    }

    fn read(dir: &Path) -> Result<Zeroizing<String>> {
        read_credential(dir, PASSWORD_CREDENTIAL, me())
    }

    fn refused(dir: &Path, why: &str) {
        let err = read(dir).err().expect("refused").to_string();
        assert!(err.contains(why), "{why}: {err}");
        assert!(!err.contains("horse"), "the contents were echoed: {err}");
    }

    #[test]
    fn the_password_is_read_as_systemd_delivers_it() {
        for (contents, dir_mode, file_mode) in [
            (PASSWORD.to_string(), 0o550, 0o440),
            (format!("{PASSWORD}\n"), 0o500, 0o400),
            (format!("{PASSWORD}\r\n"), 0o700, 0o600),
        ] {
            let (_root, dir) = creds(contents.as_bytes(), dir_mode, file_mode);
            assert_eq!(read(&dir).unwrap().as_str(), PASSWORD, "{contents:?}");
        }
        // Spaces are part of a password; only the trailing newline goes.
        let (_root, dir) = creds(b" spaced \n", 0o500, 0o400);
        assert_eq!(read(&dir).unwrap().as_str(), " spaced ");
        let longest = "p".repeat(MAX_PASSWORD);
        let (_root, dir) = creds(longest.as_bytes(), 0o500, 0o400);
        assert_eq!(read(&dir).unwrap().len(), MAX_PASSWORD);
    }

    #[test]
    fn a_credential_others_could_read_or_replace_is_refused() {
        for mode in [0o444, 0o404, 0o460, 0o602, 0o620, 0o664] {
            let (_root, dir) = creds(PASSWORD.as_bytes(), 0o500, mode);
            refused(&dir, "closed to other users");
        }
        for mode in [0o770, 0o757, 0o777, 0o720] {
            let (_root, dir) = creds(PASSWORD.as_bytes(), mode, 0o400);
            refused(&dir, "others could replace the credential");
        }
        // Owned by another user: refused unless that user is root, which may
        // own them for any service.
        let (_root, dir) = creds(PASSWORD.as_bytes(), 0o500, 0o400);
        let other = read_credential(&dir, PASSWORD_CREDENTIAL, me() + 1);
        if me() == 0 {
            assert!(other.is_ok());
        } else {
            let err = other.err().unwrap().to_string();
            assert!(err.contains("is owned by uid"), "{err}");
        }
    }

    #[test]
    fn only_a_regular_file_in_a_real_directory_is_read() {
        let (root, dir) = creds(PASSWORD.as_bytes(), 0o700, 0o400);
        // A symlink to a file holding the password.
        let target = root.path().join("elsewhere");
        std::fs::write(&target, PASSWORD).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o400)).unwrap();
        let file = dir.join(PASSWORD_CREDENTIAL);
        std::fs::remove_file(&file).unwrap();
        std::os::unix::fs::symlink(&target, &file).unwrap();
        refused(&dir, "is a symlink");
        // A FIFO is refused without waiting for a writer.
        std::fs::remove_file(&file).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &file,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o400),
            0,
        )
        .unwrap();
        refused(&dir, "not a regular file");
        std::fs::remove_file(&file).unwrap();
        std::fs::create_dir(&file).unwrap();
        refused(&dir, "not a regular file");
        std::fs::remove_dir(&file).unwrap();
        refused(&dir, "No such file");

        // The directory itself through a symlink, or not a directory.
        let (root, dir) = creds(PASSWORD.as_bytes(), 0o700, 0o400);
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        refused(&link, "is not a directory");
        refused(&dir.join(PASSWORD_CREDENTIAL), "is not a directory");
        refused(Path::new("relative/dir"), "not an absolute path");
        for name in ["", ".", "..", "a/b"] {
            assert!(read_credential(&dir, name, me()).is_err(), "{name:?}");
        }
    }

    #[test]
    fn the_credential_must_hold_one_password_and_nothing_else() {
        for bad in [
            b"".to_vec(),
            b"\n".to_vec(),
            b"\r\n".to_vec(),
            format!("{PASSWORD}\n\n").into_bytes(),
            format!("{PASSWORD}\nhorse").into_bytes(),
            format!("{PASSWORD}\rhorse").into_bytes(),
            format!("{PASSWORD}\0").into_bytes(),
        ] {
            let (_root, dir) = creds(&bad, 0o500, 0o400);
            let err = read(&dir).err().expect("refused").to_string();
            assert!(
                err.contains("is empty") || err.contains("more than one line"),
                "{bad:?}: {err}"
            );
            assert!(!err.contains("horse"), "{err}");
        }
        let (_root, dir) = creds(&[b'p', 0xff, 0xfe], 0o500, 0o400);
        refused(&dir, "is not UTF-8");
        let (_root, dir) = creds("h".repeat(MAX_PASSWORD + 1).as_bytes(), 0o500, 0o400);
        refused(&dir, "larger than");
    }
}
