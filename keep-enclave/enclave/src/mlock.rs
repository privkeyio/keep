// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Memory-locked storage utilities for secure key handling.
//!
//! These types use mlock to prevent secrets from being swapped to disk.

#![allow(unsafe_code)]

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::ptr::NonNull;
use zeroize::Zeroize;

pub struct MlockedBox<const N: usize> {
    ptr: NonNull<[u8; N]>,
    locked: bool,
}

impl<const N: usize> MlockedBox<N> {
    /// Creates a new mlocked box from a mutable reference, zeroing the source.
    ///
    /// The source data is copied into mlocked memory and then immediately
    /// zeroed to prevent secrets from remaining on the stack.
    pub fn new(data: &mut [u8; N]) -> Self {
        let layout = Layout::new::<[u8; N]>();
        let raw_ptr = unsafe { alloc_zeroed(layout) as *mut [u8; N] };
        let ptr = NonNull::new(raw_ptr).unwrap_or_else(|| std::alloc::handle_alloc_error(layout));

        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), ptr.as_ptr() as *mut u8, N) };

        data.zeroize();

        let locked = unsafe { memsec::mlock(ptr.as_ptr() as *mut u8, N) };

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
        // SAFETY: ptr is guaranteed non-null by NonNull and valid by construction
        unsafe { self.ptr.as_ref() }
    }
}

impl<const N: usize> std::ops::DerefMut for MlockedBox<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: ptr is guaranteed non-null by NonNull and valid by construction,
        // and we have exclusive access via &mut self
        unsafe { self.ptr.as_mut() }
    }
}

impl<const N: usize> Drop for MlockedBox<N> {
    fn drop(&mut self) {
        // SAFETY: ptr is guaranteed valid by construction, and we own the allocation
        unsafe {
            memsec::memzero(self.ptr.as_ptr() as *mut u8, N);
            if self.locked {
                memsec::munlock(self.ptr.as_ptr() as *mut u8, N);
            }
            dealloc(self.ptr.as_ptr() as *mut u8, Layout::new::<[u8; N]>());
        }
    }
}

impl<const N: usize> Zeroize for MlockedBox<N> {
    fn zeroize(&mut self) {
        // SAFETY: ptr is guaranteed valid by construction
        unsafe { memsec::memzero(self.ptr.as_ptr() as *mut u8, N) };
    }
}

// SAFETY: MlockedBox owns its data exclusively (like Box<T>).
// NonNull<T> is covariant over T and the data is heap-allocated.
// The type is safe to send/share because it doesn't contain any thread-local
// state, and all operations on the inner data require &mut self for mutation.
unsafe impl<const N: usize> Send for MlockedBox<N> {}
unsafe impl<const N: usize> Sync for MlockedBox<N> {}

pub struct MlockedVec {
    ptr: NonNull<u8>,
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
        let raw_ptr = data.as_mut_ptr();
        std::mem::forget(data);

        // SAFETY: Vec guarantees a valid, non-null pointer for non-zero capacity.
        // For zero-capacity Vec, we use NonNull::dangling() which is valid for zero-sized access.
        let ptr = NonNull::new(raw_ptr).unwrap_or(NonNull::dangling());
        let locked = if capacity > 0 {
            unsafe { memsec::mlock(ptr.as_ptr(), capacity) }
        } else {
            false
        };

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
        // SAFETY: ptr and len are valid from Vec construction
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for MlockedVec {
    fn drop(&mut self) {
        if self.capacity == 0 {
            return;
        }
        // SAFETY: ptr is valid and we own the allocation from the original Vec
        unsafe {
            memsec::memzero(self.ptr.as_ptr(), self.capacity);
            if self.locked {
                memsec::munlock(self.ptr.as_ptr(), self.capacity);
            }
            let _ = Vec::from_raw_parts(self.ptr.as_ptr(), self.len, self.capacity);
        }
    }
}

impl Zeroize for MlockedVec {
    fn zeroize(&mut self) {
        if self.capacity > 0 {
            // SAFETY: ptr is valid for capacity bytes
            unsafe { memsec::memzero(self.ptr.as_ptr(), self.capacity) };
        }
    }
}

// SAFETY: MlockedVec owns its data exclusively (like Vec<T>).
// NonNull<u8> is used for the heap allocation which we own.
// The type is safe to send/share because it doesn't contain any thread-local
// state, and the inner data is only accessed via &self methods.
unsafe impl Send for MlockedVec {}
unsafe impl Sync for MlockedVec {}
