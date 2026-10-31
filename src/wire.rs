//! Small helpers for the Graal byte encodings the listserver speaks.
//!
//! A GCHAR is a number plus 32. A GSTRING is a GCHAR length and that many
//! bytes. A GSHORT is two GCHARs, the high 7 bits first. Messages are one
//! GCHAR id, the payload and a line feed.

use std::io::{self, Read, Write};

/// The largest number one GCHAR carries.
pub const GCHAR_MAX: usize = 255 - 32;

/// The largest frame body a `u16` length can announce.
pub const MAX_FRAME: usize = u16::MAX as usize;

/// `n` as a GCHAR. Values above [`GCHAR_MAX`] are clamped.
pub fn gchar(n: usize) -> u8 {
    (n.min(GCHAR_MAX) + 32) as u8
}

/// Append `s` as a GSTRING, cut to [`GCHAR_MAX`] bytes.
pub fn put_gstr(out: &mut Vec<u8>, s: &[u8]) {
    let s = &s[..s.len().min(GCHAR_MAX)];
    out.push(gchar(s.len()));
    out.extend_from_slice(s);
}

/// Reads GCHARs and GSTRINGs from a message payload.
pub struct Fields<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Fields<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// The next GCHAR.
    pub fn gchar(&mut self) -> Option<usize> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b.wrapping_sub(32) as usize)
    }

    /// The next GSHORT.
    pub fn gshort(&mut self) -> Option<u16> {
        let hi = self.gchar()? as u16 & 0x7F;
        let lo = self.gchar()? as u16 & 0x7F;
        Some((hi << 7) | lo)
    }

    /// The next `n` raw bytes.
    pub fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.data.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(s)
    }

    /// The next GSTRING.
    pub fn gstr(&mut self) -> Option<&'a [u8]> {
        let n = self.gchar()?;
        self.bytes(n)
    }

    /// Everything not read yet.
    pub fn rest(&self) -> &'a [u8] {
        &self.data[self.pos.min(self.data.len())..]
    }
}

/// The non-empty lines of a decoded frame body.
pub fn lines(body: &[u8]) -> impl Iterator<Item = &[u8]> {
    body.split(|&b| b == b'\n').filter(|l| !l.is_empty())
}

/// Read one frame: a `u16be` length, then that many bytes.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len)?;
    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    r.read_exact(&mut body)?;
    Ok(body)
}

/// Write one frame: a `u16be` length, then `body`.
pub fn write_frame<W: Write>(w: &mut W, body: &[u8]) -> io::Result<()> {
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("frame of {} bytes is over the u16 length", body.len()),
        ));
    }
    let mut out = Vec::with_capacity(2 + body.len());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    w.write_all(&out)
}

/// Bytes from the network, shown safely in a log line.
pub fn show(b: &[u8]) -> String {
    let cut = &b[..b.len().min(80)];
    let mut s = cut.escape_ascii().to_string();
    if b.len() > cut.len() {
        s.push_str("...");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gstr_round_trip_and_clamp() {
        let mut out = Vec::new();
        put_gstr(&mut out, b"abc");
        put_gstr(&mut out, &[b'x'; 300]);
        let mut f = Fields::new(&out);
        assert_eq!(f.gstr(), Some(&b"abc"[..]));
        assert_eq!(f.gstr().map(<[u8]>::len), Some(GCHAR_MAX));
        assert_eq!(f.gstr(), None);
    }

    #[test]
    fn gshort_reads_high_bits_first() {
        let data = [32 + 1, 32 + 2];
        assert_eq!(Fields::new(&data).gshort(), Some(130));
    }

    #[test]
    fn short_payloads_read_as_none() {
        let mut f = Fields::new(&[32 + 5, b'a']);
        assert_eq!(f.gstr(), None);
    }
}
