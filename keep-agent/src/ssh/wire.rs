// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The SSH wire encoding (RFC 4251 section 5), read strictly: every length
//! must fit what is left, and callers check that nothing is left over.

/// Reads SSH-encoded fields from the front of a buffer.
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { rest: buf }
    }

    pub fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.rest.len() {
            return None;
        }
        let (head, rest) = self.rest.split_at(n);
        self.rest = rest;
        Some(head)
    }

    pub fn u8(&mut self) -> Option<u8> {
        self.bytes(1).map(|b| b[0])
    }

    pub fn u32(&mut self) -> Option<u32> {
        self.bytes(4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A `string`: a 32-bit length, then that many bytes.
    pub fn string(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()?;
        self.bytes(usize::try_from(len).ok()?)
    }

    /// A `string` that must be UTF-8.
    pub fn text(&mut self) -> Option<&'a str> {
        std::str::from_utf8(self.string()?).ok()
    }

    pub fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }
}

/// Append `s` as a `string`.
pub fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    let len = u32::try_from(s.len()).expect("SSH fields here are far under 4 GiB");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(s);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_are_read_only_when_they_fit() {
        let mut buf = Vec::new();
        put_string(&mut buf, b"abc");
        buf.push(7);
        let mut r = Reader::new(&buf);
        assert_eq!(r.string(), Some(&b"abc"[..]));
        assert_eq!(r.u8(), Some(7));
        assert!(r.is_empty());
        assert_eq!(r.u8(), None);

        let mut short = Reader::new(&[0, 0, 0, 4, b'a', b'b']);
        assert_eq!(short.string(), None);
        let mut huge = Reader::new(&[0xff, 0xff, 0xff, 0xff]);
        assert_eq!(huge.string(), None);
        let mut not_text = Reader::new(&[0, 0, 0, 1, 0xff]);
        assert_eq!(not_text.text(), None);
    }
}
