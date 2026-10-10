// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The vault password the gateway unlocks with, read from a systemd
//! credential: systemd decrypts it (sealed to the TPM, or to the host) into a
//! private directory it names in `$CREDENTIALS_DIRECTORY`, so the password is
//! never at rest in plaintext and never in the environment.

use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;

use rustix::fs::{FileType, Mode, OFlags};
use rustix::io::Errno;
use zeroize::Zeroizing;

use crate::error::{AgentError, Result};

/// The name of the credential holding the vault password.
pub const PASSWORD_CREDENTIAL: &str = "vault-password";

/// The longest password read.
pub const MAX_PASSWORD: usize = 4096;

/// The process a credential is read for.
#[derive(Debug, Clone, Copy)]
pub struct Reader {
    pub uid: u32,
    pub gid: u32,
}

impl Reader {
    /// This process.
    pub fn this_process() -> Self {
        Self {
            uid: rustix::process::geteuid().as_raw(),
            gid: rustix::process::getegid().as_raw(),
        }
    }

    /// Whether `uid` may own the credentials directory or a credential in
    /// it: systemd creates them as root and grants the service's user
    /// access, or gives them to that user.
    fn trusts_user(&self, uid: u32) -> bool {
        uid == 0 || uid == self.uid
    }

    /// Whether group `gid` may be given access: root's group, which systemd
    /// gives them, or the reader's own.
    fn trusts_group(&self, gid: u32) -> bool {
        gid == 0 || gid == self.gid
    }
}

/// Why access by someone the reader does not trust is refused, if it is:
/// none for others, no writing for the group, and reading (or entering) for
/// the group only when the group is trusted.
fn untrusted_access(stat: &rustix::fs::Stat, reader: &Reader) -> Option<String> {
    let mode = stat.st_mode & 0o7777;
    if mode & 0o007 != 0 {
        return Some(format!(
            "has mode {mode:o}; it must be closed to other users"
        ));
    }
    if mode & 0o020 != 0 {
        return Some(format!("has mode {mode:o}; its group may not write to it"));
    }
    if mode & 0o050 != 0 && !reader.trusts_group(stat.st_gid) {
        return Some(format!(
            "has mode {mode:o} and group {}; only root's group or the gateway's may read it",
            stat.st_gid
        ));
    }
    None
}

/// Why a POSIX access ACL on `fd` gives access to someone the reader does
/// not trust, if it does. The mode bits cannot show this: with an ACL, the
/// group bits are only the mask over every named entry.
fn untrusted_acl(fd: impl AsFd, reader: &Reader) -> Option<String> {
    const USER: u16 = 0x02;
    const GROUP: u16 = 0x08;
    const MASK: u16 = 0x10;
    let mut buf = [0u8; 4096];
    let len = match rustix::fs::fgetxattr(fd, "system.posix_acl_access", &mut buf[..]) {
        Ok(len) => len,
        // No ACL, or none possible on this file system.
        Err(Errno::NODATA) | Err(Errno::NOTSUP) => return None,
        Err(e) => return Some(format!("its access ACL cannot be read: {e}")),
    };
    let acl = &buf[..len];
    if acl.len() < 4 || (acl.len() - 4) % 8 != 0 || acl[..4] != 2u32.to_le_bytes() {
        return Some("has an access ACL that cannot be parsed".into());
    }
    let entries: Vec<(u16, u16, u32)> = acl[4..]
        .chunks_exact(8)
        .map(|e| {
            (
                u16::from_le_bytes([e[0], e[1]]),
                u16::from_le_bytes([e[2], e[3]]),
                u32::from_le_bytes([e[4], e[5], e[6], e[7]]),
            )
        })
        .collect();
    let mask = entries
        .iter()
        .find(|(tag, _, _)| *tag == MASK)
        .map_or(0o7, |(_, perm, _)| *perm);
    entries.iter().find_map(|&(tag, perm, id)| {
        let granted = perm & mask != 0;
        match tag {
            USER if granted && !reader.trusts_user(id) => {
                Some(format!("has an access ACL that lets uid {id} in"))
            }
            GROUP if granted && !reader.trusts_group(id) => {
                Some(format!("has an access ACL that lets gid {id} in"))
            }
            _ => None,
        }
    })
}

/// Read credential `name` from the credentials directory `dir` for `reader`.
///
/// The directory must be a real directory, not a symlink, owned by root or
/// the reader, closed to other users, that its group cannot write. The
/// credential must be a regular file in it, not a symlink, owned by root or
/// the reader, closed to other users, that its group cannot write, of at most
/// [`MAX_PASSWORD`] bytes of UTF-8 on one line. Either may be readable by its
/// group only when that is root's group or the reader's, and neither may
/// carry an ACL entry for anyone else. One trailing newline (`\n` or `\r\n`)
/// is dropped, as `echo` and editors add one. Everything is checked on what
/// was opened, so nothing can be swapped in between, and the file's contents
/// are never put in an error.
pub fn read_credential(dir: &Path, name: &str, reader: Reader) -> Result<Zeroizing<String>> {
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
    let dir_fd: OwnedFd = rustix::fs::open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| match e {
        Errno::NOTDIR | Errno::LOOP => fail("the credentials directory is not a directory".into()),
        e => fail(format!("the credentials directory cannot be read: {e}")),
    })?;
    let stat = rustix::fs::fstat(&dir_fd).map_err(|e| fail(e.to_string()))?;
    if !reader.trusts_user(stat.st_uid) {
        return Err(fail(format!(
            "the credentials directory is owned by uid {}, not root or uid {}",
            stat.st_uid, reader.uid
        )));
    }
    if let Some(why) = untrusted_access(&stat, &reader).or_else(|| untrusted_acl(&dir_fd, &reader))
    {
        return Err(fail(format!("the credentials directory {why}")));
    }
    // Not through a symlink, and non-blocking, so a FIFO in its place cannot
    // hang the open.
    let fd = rustix::fs::openat(
        &dir_fd,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| match e {
        Errno::LOOP => fail("is a symlink".into()),
        e => fail(e.to_string()),
    })?;
    let stat = rustix::fs::fstat(&fd).map_err(|e| fail(e.to_string()))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(fail("is not a regular file".into()));
    }
    if !reader.trusts_user(stat.st_uid) {
        return Err(fail(format!(
            "is owned by uid {}, not root or uid {}",
            stat.st_uid, reader.uid
        )));
    }
    if let Some(why) = untrusted_access(&stat, &reader).or_else(|| untrusted_acl(&fd, &reader)) {
        return Err(fail(why));
    }
    let mut file = std::fs::File::from(fd);
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
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;

    const PASSWORD: &str = "correct horse battery staple";

    fn me() -> Reader {
        Reader::this_process()
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

    fn refused_for(dir: &Path, reader: Reader, why: &str) {
        // Not expect_err: that would print the password.
        let Err(err) = read_credential(dir, PASSWORD_CREDENTIAL, reader) else {
            panic!("read, not refused ({why})");
        };
        let err = err.to_string();
        assert!(err.contains(why), "{why}: {err}");
        assert!(!err.contains("horse"), "the contents were echoed: {err}");
    }

    fn refused(dir: &Path, why: &str) {
        refused_for(dir, me(), why)
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
        for mode in [0o444, 0o404, 0o401, 0o664, 0o602] {
            let (_root, dir) = creds(PASSWORD.as_bytes(), 0o500, mode);
            refused(&dir, "closed to other users");
        }
        for mode in [0o460, 0o620, 0o420] {
            let (_root, dir) = creds(PASSWORD.as_bytes(), 0o500, mode);
            refused(&dir, "its group may not write");
        }
        for mode in [0o757, 0o705, 0o701] {
            let (_root, dir) = creds(PASSWORD.as_bytes(), mode, 0o400);
            refused(&dir, "the credentials directory has mode");
        }
        for mode in [0o770, 0o720] {
            let (_root, dir) = creds(PASSWORD.as_bytes(), mode, 0o400);
            refused(&dir, "its group may not write");
        }
    }

    /// The group may read only when it is root's or the reader's: another
    /// supervisor's `root:agents 0440` would hand the password to agents.
    #[test]
    fn only_a_trusted_group_may_read_the_credential() {
        let (_root, dir) = creds(PASSWORD.as_bytes(), 0o550, 0o440);
        let gid = std::fs::metadata(dir.join(PASSWORD_CREDENTIAL))
            .unwrap()
            .gid();
        // The reader's own group.
        assert!(read_credential(&dir, PASSWORD_CREDENTIAL, Reader { gid, ..me() }).is_ok());
        let stranger = Reader {
            gid: gid + 1,
            ..me()
        };
        if gid == 0 {
            // Root's group is trusted: move the file and directory to
            // another before asking.
            let file = dir.join(PASSWORD_CREDENTIAL);
            std::os::unix::fs::chown(&file, None, Some(4_321)).unwrap();
            refused_for(&dir, stranger, "only root's group or the gateway's");
            std::os::unix::fs::chown(&file, None, Some(0)).unwrap();
            std::os::unix::fs::chown(&dir, None, Some(4_321)).unwrap();
            refused_for(
                &dir,
                stranger,
                "the credentials directory has mode 550 and group 4321",
            );
        } else {
            refused_for(&dir, stranger, "only root's group or the gateway's");
            // Closed to the group, it does not matter whose the group is.
            let (_root, dir) = creds(PASSWORD.as_bytes(), 0o500, 0o400);
            assert!(read_credential(&dir, PASSWORD_CREDENTIAL, stranger).is_ok());
        }
    }

    /// An ACL can let a user or group in while the mode bits show only the
    /// mask: a named entry for anyone but the reader and root is refused.
    #[test]
    fn an_acl_that_lets_anyone_else_read_is_refused() {
        fn acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
            // The kernel takes entries in tag order only.
            let mut entries = entries.to_vec();
            entries.sort_by_key(|e| e.0);
            let mut v = 2u32.to_le_bytes().to_vec();
            for (tag, perm, id) in &entries {
                v.extend_from_slice(&tag.to_le_bytes());
                v.extend_from_slice(&perm.to_le_bytes());
                v.extend_from_slice(&id.to_le_bytes());
            }
            v
        }
        const UNDEFINED: u32 = u32::MAX;
        let set = |path: &Path, entries: &[(u16, u16, u32)]| -> bool {
            match rustix::fs::setxattr(
                path,
                "system.posix_acl_access",
                &acl(entries),
                rustix::fs::XattrFlags::empty(),
            ) {
                Ok(()) => true,
                Err(Errno::NOTSUP) => false,
                Err(e) => panic!("setxattr: {e}"),
            }
        };
        let reader = me();
        let base = |user: (u16, u32), mask: u16| {
            vec![
                (0x01, 0o4, UNDEFINED),
                (user.0, 0o4, user.1),
                (0x04, 0, UNDEFINED),
                (0x10, mask, UNDEFINED),
                (0x20, 0, UNDEFINED),
            ]
        };
        let (_root, dir) = creds(PASSWORD.as_bytes(), 0o500, 0o400);
        let file = dir.join(PASSWORD_CREDENTIAL);
        // The reader by name, as systemd grants the service's user.
        if !set(&file, &base((0x02, reader.uid), 0o4)) {
            eprintln!("skipped: no ACLs on this file system");
            return;
        }
        assert!(read(&dir).is_ok());
        // Another user, or another group.
        assert!(set(&file, &base((0x02, reader.uid + 1), 0o4)));
        refused(&dir, &format!("lets uid {} in", reader.uid + 1));
        assert!(set(&file, &base((0x08, reader.gid + 1), 0o4)));
        refused(&dir, &format!("lets gid {} in", reader.gid + 1));
        // Masked out, the entry grants nothing.
        assert!(set(&file, &base((0x02, reader.uid + 1), 0)));
        assert!(read(&dir).is_ok());
        // On the directory too.
        assert!(set(&file, &base((0x02, reader.uid), 0o4)));
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir_acl = vec![
            (0x01, 0o7, UNDEFINED),
            (0x02, 0o5, reader.uid + 1),
            (0x04, 0, UNDEFINED),
            (0x10, 0o5, UNDEFINED),
            (0x20, 0, UNDEFINED),
        ];
        assert!(set(&dir, &dir_acl));
        refused(
            &dir,
            &format!(
                "the credentials directory has an access ACL that lets uid {} in",
                reader.uid + 1
            ),
        );
    }

    #[test]
    fn the_credential_must_belong_to_root_or_the_reader() {
        let (_root, dir) = creds(PASSWORD.as_bytes(), 0o500, 0o400);
        let other = Reader {
            uid: me().uid + 1,
            ..me()
        };
        if me().uid != 0 {
            refused_for(&dir, other, "is owned by uid");
            return;
        }
        // Root owns them for any service.
        assert!(read_credential(&dir, PASSWORD_CREDENTIAL, other).is_ok());
        // Only root can give them to other users: each check on its own.
        let reader = Reader {
            uid: 5_555,
            gid: 5_555,
        };
        let chown = |p: &Path, uid: u32| std::os::unix::fs::chown(p, Some(uid), None).unwrap();
        let file = dir.join(PASSWORD_CREDENTIAL);
        // The reader's credential in a stranger's directory.
        chown(&file, reader.uid);
        chown(&dir, 4_321);
        refused_for(
            &dir,
            reader,
            "the credentials directory is owned by uid 4321",
        );
        // A stranger's credential in a directory of root's.
        chown(&dir, 0);
        chown(&file, 4_321);
        refused_for(&dir, reader, "is owned by uid 4321, not root");
        // Both the reader's, or the directory root's: read.
        chown(&file, reader.uid);
        assert!(read_credential(&dir, PASSWORD_CREDENTIAL, reader).is_ok());
        chown(&dir, reader.uid);
        assert!(read_credential(&dir, PASSWORD_CREDENTIAL, reader).is_ok());
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
        // A name that leads out of the directory, to a file that would pass
        // every other check.
        let outside = root.path().join("outside");
        std::fs::write(&outside, PASSWORD).unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o400)).unwrap();
        let err = read_credential(&dir, "../outside", me()).err().unwrap();
        assert!(err.to_string().contains("not a credential name"), "{err}");
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
            let Err(err) = read(&dir) else {
                panic!("read {bad:?}");
            };
            let err = err.to_string();
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
