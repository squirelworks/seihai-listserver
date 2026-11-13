//! Graal's comma-tokenized text, as the gserver link's text messages carry
//! it (`docs/design/gserver-text-profiles-guilds.md`, "Notation").
//!
//! A line is fields joined by `,`. A field that holds a `,`, a `"`, a
//! space or nothing is written in quotes with inner `"` doubled. A field
//! that is itself a list is the list written the same way, one level
//! deeper. Written from that description; no gserver code.

/// Split one line into its fields. Quotes are taken off and `""` inside
/// them becomes `"`. Bytes outside quotes are kept as they are.
pub fn split(line: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if line.is_empty() {
        return out;
    }
    let mut field = Vec::new();
    let mut i = 0;
    let mut quoted = false;
    while i < line.len() {
        let b = line[i];
        if quoted {
            if b == b'"' {
                if line.get(i + 1) == Some(&b'"') {
                    field.push(b'"');
                    i += 1;
                } else {
                    quoted = false;
                }
            } else {
                field.push(b);
            }
        } else if b == b'"' && field.is_empty() {
            quoted = true;
        } else if b == b',' {
            out.push(std::mem::take(&mut field));
        } else {
            field.push(b);
        }
        i += 1;
    }
    out.push(field);
    out
}

/// One field, quoted when it needs to be.
pub fn field(f: &[u8]) -> Vec<u8> {
    let needs = f.is_empty() || f.iter().any(|&b| matches!(b, b',' | b'"' | b' '));
    if !needs {
        return f.to_vec();
    }
    let mut out = Vec::with_capacity(f.len() + 2);
    out.push(b'"');
    for &b in f {
        if b == b'"' {
            out.push(b'"');
        }
        out.push(b);
    }
    out.push(b'"');
    out
}

/// Fields joined into one line, each quoted when it needs to be.
pub fn join<F: AsRef<[u8]>>(fields: &[F]) -> Vec<u8> {
    let mut out = Vec::new();
    for (n, f) in fields.iter().enumerate() {
        if n > 0 {
            out.push(b',');
        }
        out.extend_from_slice(&field(f.as_ref()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_and_quoted_fields_round_trip() {
        let fields: Vec<&[u8]> = vec![b"GraalEngine", b"pmservers", b"", b"Lab Server", b"a,\"b\""];
        let line = join(&fields);
        assert_eq!(
            line,
            b"GraalEngine,pmservers,\"\",\"Lab Server\",\"a,\"\"b\"\"\"".to_vec()
        );
        assert_eq!(split(&line), fields);
    }

    #[test]
    fn a_list_field_is_one_level_deeper() {
        let pair = join(&[&b"alice"[..], b"Alice A"]);
        let line = join(&[&b"GraalEngine"[..], b"pmserverplayers", b"Lab", &pair]);
        assert_eq!(
            line,
            b"GraalEngine,pmserverplayers,Lab,\"alice,\"\"Alice A\"\"\"".to_vec()
        );
        let f = split(&line);
        assert_eq!(split(&f[3]), vec![b"alice".to_vec(), b"Alice A".to_vec()]);
    }

    #[test]
    fn the_clients_empty_option_is_one_empty_field() {
        // Real 4.04r2 and 4.20r8 send `GraalEngine,pmguilds,""`.
        assert_eq!(
            split(b"GraalEngine,pmguilds,\"\""),
            vec![b"GraalEngine".to_vec(), b"pmguilds".to_vec(), Vec::new()]
        );
        assert!(split(b"").is_empty());
        assert_eq!(split(b"a,"), vec![b"a".to_vec(), Vec::new()]);
    }
}
