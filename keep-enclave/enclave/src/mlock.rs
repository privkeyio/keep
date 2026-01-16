// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Memory-locked storage utilities for secure key handling.
//!
//! These types use mlock to prevent secrets from being swapped to disk.

#![allow(unsafe_code)]

use std::alloc::{alloc_zeroed, dealloc, Layout};
use zeroize::Zeroize;

pub struct MlockedBox<const N: usize> {
    ptr: *mut [u8; N],
    locked: bool,
}

impl<const N: usize> MlockedBox<N> {
    /// Creates a new mlocked box from a mutable reference, zeroing the source.
    ///
    /// The source data is copied into mlocked memory and then immediately
    /// zeroed to prevent secrets from remaining on the stack.
    pub fn new(data: &mut [u8; N]) -> Self {
        let layout = Layout::new::<[u8; N]>();
        let ptr = unsafe { alloc_zeroed(layout) as *mut [u8; N] };
        if ptr.is_null() {
            std::alloc::handle_alloc_error(layout);
        }

        // Copy data to mlocked memory
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, N) };

        // Zero the source immediately
        data.zeroize();

        let locked = unsafe { memsec::mlock(ptr as *mut u8, N) };

        Self { ptr, locked }
    }

    #[allow(dead_code)]
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl<const N: usize> std::ops::Deref for MlockedBox<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.ptr }
    }
}

impl<const N: usize> std::ops::DerefMut for MlockedBox<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.ptr }
    }
}

impl<const N: usize> Drop for MlockedBox<N> {
    fn drop(&mut self) {
        unsafe {
            memsec::memzero(self.ptr as *mut u8, N);
            if self.locked {
                memsec::munlock(self.ptr as *mut u8, N);
            }
            dealloc(self.ptr as *mut u8, Layout::new::<[u8; N]>());
        }
    }
}

impl<const N: usize> Zeroize for MlockedBox<N> {
    fn zeroize(&mut self) {
        unsafe { memsec::memzero(self.ptr as *mut u8, N) };
    }
}

unsafe impl<const N: usize> Send for MlockedBox<N> {}
unsafe impl<const N: usize> Sync for MlockedBox<N> {}

pub struct MlockedVec {
    ptr: *mut u8,
    len: usize,
    capacity: usize,
    locked: bool,
}

impl MlockedVec {
    /// Creates a new mlocked vec, taking ownership and locking the memory.
    ///
    /// Note: The Vec's memory is locked in place. The original allocation
    /// is preserved (not copied), so this is efficient for large data.
    pub fn new(mut data: Vec<u8>) -> Self {
        let len = data.len();
        let capacity = data.capacity();
        let ptr = data.as_mut_ptr();
        std::mem::forget(data);

        let locked = unsafe { memsec::mlock(ptr, capacity) };

        Self {
            ptr,
            len,
            capacity,
            locked,
        }
    }

    #[allow(dead_code)]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Drop for MlockedVec {
    fn drop(&mut self) {
        unsafe {
            // Zero the full capacity, not just len, to catch any leftover data
            memsec::memzero(self.ptr, self.capacity);
            if self.locked {
                memsec::munlock(self.ptr, self.capacity);
            }
            let _ = Vec::from_raw_parts(self.ptr, self.len, self.capacity);
        }
    }
}

impl Zeroize for MlockedVec {
    fn zeroize(&mut self) {
        unsafe { memsec::memzero(self.ptr, self.capacity) };
    }
}

unsafe impl Send for MlockedVec {}
unsafe impl Sync for MlockedVec {}
