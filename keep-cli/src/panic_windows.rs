// SAFETY: Windows API calls for setting file ACLs require unsafe.
#![allow(unsafe_code)]

use std::fs::File;
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, GENERIC_WRITE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    SetEntriesInAclW, EXPLICIT_ACCESS_W, SET_ACCESS, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, InitializeSecurityDescriptor, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, TokenUser, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
    SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, CREATE_ALWAYS, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_CREATION_DISPOSITION,
    FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_OPEN_REPARSE_POINT,
};
use windows_sys::Win32::System::Memory::{GetProcessHeap, HeapAlloc, HeapFree};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const GENERIC_ALL: u32 = 0x10000000;
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const NO_INHERITANCE: u32 = 0;

pub fn write_file_owner_only(path: &Path, content: &str) -> std::io::Result<()> {
    let mut file = unsafe { create_owner_only(path, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL) }?;
    file.write_all(content.as_bytes())
}

/// Create `path` for writing, accessible only to the current user. Fails if
/// anything already exists at `path`, including a symlink, which is never
/// followed.
pub fn create_new_owner_only(path: &Path) -> std::io::Result<File> {
    unsafe {
        create_owner_only(
            path,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        )
    }
}

/// The DACL grants only the current user and is marked protected, so no ACEs
/// are inherited from the parent directory.
unsafe fn create_owner_only(
    path: &Path,
    disposition: FILE_CREATION_DISPOSITION,
    flags: FILE_FLAGS_AND_ATTRIBUTES,
) -> std::io::Result<File> {
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
        return Err(std::io::Error::from_raw_os_error(8));
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
    let user_sid = token_user.User.Sid;

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
    let sd_ptr = (&mut sd as *mut SECURITY_DESCRIPTOR).cast();
    if InitializeSecurityDescriptor(sd_ptr, SECURITY_DESCRIPTOR_REVISION) == 0 {
        LocalFree(acl as _);
        HeapFree(heap, 0, token_info);
        CloseHandle(token_handle);
        return Err(std::io::Error::last_os_error());
    }

    if SetSecurityDescriptorDacl(sd_ptr, 1, acl, 0) == 0
        || SetSecurityDescriptorControl(sd_ptr, SE_DACL_PROTECTED, SE_DACL_PROTECTED) == 0
    {
        LocalFree(acl as _);
        HeapFree(heap, 0, token_info);
        CloseHandle(token_handle);
        return Err(std::io::Error::last_os_error());
    }

    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd_ptr,
        bInheritHandle: 0,
    };

    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();

    let file_handle = CreateFileW(
        wide_path.as_ptr(),
        GENERIC_WRITE,
        0,
        &mut sa,
        disposition,
        flags,
        ptr::null_mut(),
    );

    LocalFree(acl as _);
    HeapFree(heap, 0, token_info);
    CloseHandle(token_handle);

    if file_handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }

    Ok(File::from_raw_handle(file_handle as *mut _))
}

/// Replace `to` with `from`, asking Windows to write the move through to disk
/// before returning (`MOVEFILE_WRITE_THROUGH`), in place of a Unix rename and
/// directory fsync. A same-volume replace is atomic: `to` holds the old or the
/// new contents, never a mix.
pub fn replace_file_durably(from: &Path, to: &Path) -> std::io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let wide = |p: &Path| -> Vec<u16> { p.as_os_str().encode_wide().chain(Some(0)).collect() };
    let (from, to) = (wide(from), wide(to));
    // SAFETY: both arguments are NUL-terminated UTF-16 strings that outlive the call.
    let moved = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        AclSizeInformation, GetAclInformation, GetSecurityDescriptorControl, ACL_SIZE_INFORMATION,
        DACL_SECURITY_INFORMATION,
    };

    /// The number of ACEs in `path`'s DACL and whether the DACL is protected.
    fn dacl_of(path: &Path) -> (u32, bool) {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut dacl = ptr::null_mut();
        let mut sd = ptr::null_mut();
        unsafe {
            let err = GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut sd,
            );
            assert_eq!(err, 0, "GetNamedSecurityInfoW");
            let mut control = 0u16;
            let mut revision = 0u32;
            assert_ne!(
                GetSecurityDescriptorControl(sd, &mut control, &mut revision),
                0
            );
            let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
            assert_ne!(
                GetAclInformation(
                    dacl,
                    (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                    std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                ),
                0
            );
            LocalFree(sd as _);
            (info.AceCount, control & SE_DACL_PROTECTED != 0)
        }
    }

    #[test]
    fn a_new_owner_only_file_has_one_protected_ace_and_never_reuses_a_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        create_new_owner_only(&path)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        assert_eq!(dacl_of(&path), (1, true));
        assert_eq!(
            create_new_owner_only(&path).unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
    }
}
