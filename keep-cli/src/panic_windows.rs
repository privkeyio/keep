use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, GENERIC_WRITE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    SetEntriesInAclW, EXPLICIT_ACCESS_W, SET_ACCESS, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, InitializeSecurityDescriptor, SetSecurityDescriptorDacl, TokenUser,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, WriteFile, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
};
use windows_sys::Win32::System::Memory::{GetProcessHeap, HeapAlloc, HeapFree};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const GENERIC_ALL: u32 = 0x10000000;
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const NO_INHERITANCE: u32 = 0;

pub fn write_file_owner_only(path: &Path, content: &str) -> std::io::Result<()> {
    unsafe { write_file_owner_only_impl(path, content) }
}

unsafe fn write_file_owner_only_impl(path: &Path, content: &str) -> std::io::Result<()> {
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

    let mut sd = vec![0u8; 256];
    let sd_ptr = sd.as_mut_ptr() as *mut _;
    if InitializeSecurityDescriptor(sd_ptr, SECURITY_DESCRIPTOR_REVISION) == 0 {
        LocalFree(acl as _);
        HeapFree(heap, 0, token_info);
        CloseHandle(token_handle);
        return Err(std::io::Error::last_os_error());
    }

    if SetSecurityDescriptorDacl(sd_ptr, 1, acl, 0) == 0 {
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
