//! *S-Expressions* for communicating cryptographic primitives.
//!
//! *S-Expressions* as described in the internet draft [S-Expressions],
//! are a way to communicate cryptographic primitives like keys,
//! signatures, and ciphertexts between agents or implementations.
//!
//! [S-Expressions]: https://people.csail.mit.edu/rivest/Sexp.txt

use std::convert::TryFrom;
use std::fmt;
use std::ops::Deref;

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

use sequoia_openpgp as openpgp;
use openpgp::crypto::{mpi, SessionKey};
use openpgp::crypto::mem::Protected;

use openpgp::Error;
use openpgp::Result;

mod parse;

/// An *S-Expression*.
///
/// An *S-Expression* is either a string, or a list of *S-Expressions*.
#[derive(Clone, PartialEq, Eq)]
pub enum Sexp {
    /// Just a string.
    String(String_),
    /// A list of *S-Expressions*.
    List(Vec<Sexp>),
}

impl fmt::Debug for Sexp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Sexp::String(ref s) => s.fmt(f),
            Sexp::List(ref l) => l.fmt(f),
        }
    }
}

impl Sexp {
    /// Completes the decryption of this S-Expression representing a
    /// wrapped session key.
    ///
    /// Such an expression is returned from gpg-agent's `PKDECRYPT`
    /// command.  `padding` must be set according to the status
    /// messages sent.
    pub fn finish_decryption<R>(&self,
                                recipient: &openpgp::packet::Key<
                                        openpgp::packet::key::PublicParts, R>,
                                ciphertext: &mpi::Ciphertext,
                                padding: bool)
        -> Result<SessionKey>
        where R: openpgp::packet::key::KeyRole
    {
        use openpgp::crypto::mpi::PublicKey;
        let not_a_session_key = || -> anyhow::Error {
            Error::MalformedMPI(
                format!("Not a session key: {:?}", self)).into()
        };

        let value = self.get(b"value")?.ok_or_else(not_a_session_key)?
            .into_iter().next().ok_or_else(not_a_session_key)?;

        match value {
            Sexp::String(ref s) => match recipient.mpis() {
                PublicKey::RSA { .. } | PublicKey::ElGamal { .. } if padding =>
                {
                    // The session key is padded.  The format is
                    // described in g10/pubkey-enc.c (note that we,
                    // like GnuPG 2.2, only support the new encoding):
                    //
                    //   * Later versions encode the DEK like this:
                    //   *
                    //   *     0  2  RND(n bytes)  [...]
                    //   *
                    //   * (mpi_get_buffer already removed the leading zero).
                    //   *
                    //   * RND are non-zero random bytes.
                    let mut s = &s[..];

                    // The leading 0 may or may not be swallowed along
                    // the way due to MPI encoding.
                    if s[0] == 0 {
                        s = &s[1..];
                    }

                    // Version.
                    if s[0] != 2 {
                        return Err(Error::MalformedMPI(
                            format!("DEK encoding version {} not understood",
                                    s[0])).into());
                    }

                    // Skip non-zero bytes.
                    while !s.is_empty() && s[0] > 0 {
                        s = &s[1..];
                    }

                    if s.is_empty() {
                        return Err(Error::MalformedMPI(
                            "Invalid DEK encoding, no zero found".into())
                                   .into());
                    }

                    // Skip zero.
                    s = &s[1..];

                    Ok(s.to_vec().into())
                },

                PublicKey::RSA { .. } | PublicKey::ElGamal { .. } => {
                    // The session key is not padded.  Currently, this
                    // happens if the session key is decrypted using
                    // scdaemon.
                    assert!(! padding); // XXX: Don't assert that.
                    Ok(s.to_vec().into())
                },

                PublicKey::ECDH { curve, .. } => {
                    // The shared point has been computed by the
                    // remote agent.  The shared point is not padded.
                    let s_: mpi::ProtectedMPI = s.to_vec().into();
                    #[allow(non_snake_case)]
                    let S: Protected = s_.decode_point(curve)?.0.into();
                    // XXX: Erase shared point from s.

                    // Now finish the decryption.
                    openpgp::crypto::ecdh::decrypt_unwrap(recipient, &S, ciphertext)
                },

                _ =>
                    Err(Error::InvalidArgument(
                        format!("Don't know how to handle key {:?}", recipient))
                        .into()),
            }
            Sexp::List(..) => Err(not_a_session_key()),
        }
    }

    /// Parses this s-expression to a signature.
    ///
    /// Such an expression is returned from gpg-agent's `PKSIGN`
    /// command.
    pub fn to_signature(&self) -> Result<mpi::Signature> {
        let not_a_signature = || -> anyhow::Error {
            Error::MalformedMPI(
                format!("Not a signature: {:?}", self)).into()
        };

        let sig = self.get(b"sig-val")?.ok_or_else(not_a_signature)?
            .into_iter().next().ok_or_else(not_a_signature)?;

        if let Some(param) = sig.get(b"eddsa")? {
            let r = param.iter().find_map(|p| {
                p.get(b"r").ok().unwrap_or_default()
                    .and_then(|l| l.get(0).and_then(Sexp::string).cloned())
            }).ok_or_else(not_a_signature)?;
            let s = param.iter().find_map(|p| {
                p.get(b"s").ok().unwrap_or_default()
                    .and_then(|l| l.get(0).and_then(Sexp::string).cloned())
            }).ok_or_else(not_a_signature)?;
            Ok(mpi::Signature::EdDSA {
                r: mpi::MPI::new(&r),
                s: mpi::MPI::new(&s),
            })
        } else if let Some(param) = sig.get(b"ecdsa")? {
            let r = param.iter().find_map(|p| {
                p.get(b"r").ok().unwrap_or_default()
                    .and_then(|l| l.get(0).and_then(Sexp::string).cloned())
            }).ok_or_else(not_a_signature)?;
            let s = param.iter().find_map(|p| {
                p.get(b"s").ok().unwrap_or_default()
                    .and_then(|l| l.get(0).and_then(Sexp::string).cloned())
            }).ok_or_else(not_a_signature)?;
            Ok(mpi::Signature::ECDSA {
                r: mpi::MPI::new(&r),
                s: mpi::MPI::new(&s),
            })
        } else if let Some(param) = sig.get(b"rsa")? {
            let s = param.iter().find_map(|p| {
                p.get(b"s").ok().unwrap_or_default()
                    .and_then(|l| l.get(0).and_then(Sexp::string).cloned())
            }).ok_or_else(not_a_signature)?;
            Ok(mpi::Signature::RSA {
                s: mpi::MPI::new(&s),
            })
        } else if let Some(param) = sig.get(b"dsa")? {
            let r = param.iter().find_map(|p| {
                p.get(b"r").ok().unwrap_or_default()
                    .and_then(|l| l.get(0).and_then(Sexp::string).cloned())
            }).ok_or_else(not_a_signature)?;
            let s = param.iter().find_map(|p| {
                p.get(b"s").ok().unwrap_or_default()
                    .and_then(|l| l.get(0).and_then(Sexp::string).cloned())
            }).ok_or_else(not_a_signature)?;
            Ok(mpi::Signature::DSA {
                r: mpi::MPI::new(&r),
                s: mpi::MPI::new(&s),
            })
        } else {
            Err(Error::MalformedMPI(
                format!("Unknown signature sexp: {:?}", self)).into())
        }
    }

    /// Casts this to a string.
    pub fn string(&self) -> Option<&String_> {
        match self {
            Sexp::String(ref s) => Some(s),
            _ => None,
        }
    }

    /// Casts this to a list.
    pub fn list(&self) -> Option<&[Sexp]> {
        match self {
            Sexp::List(ref s) => Some(s.as_slice()),
            _ => None,
        }
    }

    /// Writes a serialized version of the object to `o`.
    pub fn serialize(&self, o: &mut dyn std::io::Write) -> Result<()> {
        match self {
            Sexp::String(ref s) => s.serialize(o),
            Sexp::List(ref l) => {
                write!(o, "(")?;
                for sexp in l {
                    sexp.serialize(o)?;
                }
                write!(o, ")")?;
                Ok(())
            },
        }
    }

    /// Given an alist, selects by key and returns the value.
    fn get(&self, key: &[u8]) -> Result<Option<Vec<Sexp>>> {
        match self {
            Sexp::List(ref ll) => match ll.get(0) {
                Some(Sexp::String(ref tag)) =>
                    if tag.deref() == key {
                        Ok(Some(ll[1..].to_vec()))
                    } else {
                        Ok(None)
                    }
                _ =>
                    Err(Error::InvalidArgument(
                        format!("Malformed alist: {:?}", ll)).into()),
            },
            _ =>
                Err(Error::InvalidArgument(
                    format!("Malformed alist: {:?}", self)).into()),
        }
    }
}

impl TryFrom<&mpi::Ciphertext> for Sexp {
    type Error = anyhow::Error;

    /// Constructs an S-Expression representing `ciphertext`.
    ///
    /// The resulting expression is suitable for gpg-agent's `INQUIRE
    /// CIPHERTEXT` inquiry.
    fn try_from(ciphertext: &mpi::Ciphertext) -> Result<Self> {
        use openpgp::crypto::mpi::Ciphertext::*;
        match ciphertext {
            RSA { ref c } =>
                Ok(Sexp::List(vec![
                    Sexp::String("enc-val".into()),
                    Sexp::List(vec![
                        Sexp::String("rsa".into()),
                        Sexp::List(vec![
                            Sexp::String("a".into()),
                            Sexp::String(c.value().into())])])])),

            &ElGamal { ref e, ref c } =>
                Ok(Sexp::List(vec![
                    Sexp::String("enc-val".into()),
                    Sexp::List(vec![
                        Sexp::String("elg".into()),
                        Sexp::List(vec![
                            Sexp::String("a".into()),
                            Sexp::String(e.value().into())]),
                        Sexp::List(vec![
                            Sexp::String("b".into()),
                            Sexp::String(c.value().into())])])])),

            &ECDH { ref e, ref key } =>
                Ok(Sexp::List(vec![
                    Sexp::String("enc-val".into()),
                    Sexp::List(vec![
                        Sexp::String("ecdh".into()),
                        Sexp::List(vec![
                            Sexp::String("s".into()),
                            Sexp::String(key.as_ref().into())]),
                        Sexp::List(vec![
                            Sexp::String("e".into()),
                            Sexp::String(e.value().into())])])])),

            // crypto::mpi::Ciphertext is non_exhaustive, match on &_ to handle
            // future additions.
            &Unknown { .. } | &_ =>
                Err(Error::InvalidArgument(
                    format!("Don't know how to convert {:?}", ciphertext))
                    .into()),
        }
    }
}

#[cfg(test)]
impl Arbitrary for Sexp {
    fn arbitrary(g: &mut Gen) -> Self {
        if f32::arbitrary(g) < 0.7 {
            Sexp::String(String_::arbitrary(g))
        } else {
            let mut v = Vec::new();
            for _ in 0..usize::arbitrary(g) % 3 {
                v.push(Sexp::arbitrary(g));
            }
            Sexp::List(v)
        }
    }
}

/// A string.
///
/// A string can optionally have a display hint.
#[derive(Clone, PartialEq, Eq)]
pub struct String_(Box<[u8]>, Option<Box<[u8]>>);

impl fmt::Debug for String_ {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fn bstring(f: &mut fmt::Formatter, buf: &[u8]) -> fmt::Result {
            write!(f, "b\"")?;
            for &b in buf {
                match b {
                    0..=31 | 128..=255 =>
                        write!(f, "\\x{:02x}", b)?,
                    0x22 => // "
                        write!(f, "\\\"")?,
                    0x5c => // \
                        write!(f, "\\\\")?,
                    _ =>
                        write!(f, "{}", b as char)?,
                }
            }
            write!(f, "\"")
        }

        if let Some(hint) = self.display_hint() {
            write!(f, "[")?;
            bstring(f, hint)?;
            write!(f, "]")?;
        }
        bstring(f, &self.0)
    }
}

impl String_ {
    /// Constructs a new *Simple String*.
    pub fn new<S>(s: S) -> Self
        where S: Into<Box<[u8]>>
    {
        Self(s.into(), None)
    }

    /// Constructs a new *String*.
    pub fn with_display_hint<S, T>(s: S, display_hint: T) -> Self
        where S: Into<Box<[u8]>>, T: Into<Box<[u8]>>
    {
        Self(s.into(), Some(display_hint.into()))
    }

    /// Gets a reference to this *String*'s display hint, if any.
    pub fn display_hint(&self) -> Option<&[u8]> {
        self.1.as_ref().map(|b| b.as_ref())
    }

    /// Writes a serialized version of the object to `o`.
    pub fn serialize(&self, o: &mut dyn std::io::Write) -> Result<()> {
        if let Some(display) = self.display_hint() {
            write!(o, "[{}:", display.len())?;
            o.write_all(display)?;
            write!(o, "]")?;
        }
        write!(o, "{}:", self.len())?;
        o.write_all(self)?;
        Ok(())
    }
}

impl From<&str> for String_ {
    fn from(b: &str) -> Self {
        Self::new(b.as_bytes().to_vec())
    }
}

impl From<&[u8]> for String_ {
    fn from(b: &[u8]) -> Self {
        Self::new(b.to_vec())
    }
}

impl Deref for String_ {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
impl Arbitrary for String_ {
    fn arbitrary(g: &mut Gen) -> Self {
        if bool::arbitrary(g) {
            Self::new(Vec::arbitrary(g).into_boxed_slice())
        } else {
            Self::with_display_hint(Vec::arbitrary(g).into_boxed_slice(),
                                    Vec::arbitrary(g).into_boxed_slice())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openpgp::parse::Parse;

    quickcheck::quickcheck! {
        fn roundtrip(s: Sexp) -> bool {
            let mut buf = Vec::new();
            s.serialize(&mut buf).unwrap();
            let t = Sexp::from_bytes(&buf).unwrap();
            assert_eq!(s, t);
            true
        }
    }

    #[test]
    fn to_signature() {
        use openpgp::crypto::mpi::Signature::*;
        assert!(matches!(
            Sexp::from_bytes(
                crate::tests::file("sexp/dsa-signature.sexp")).unwrap()
                    .to_signature().unwrap(),
                DSA { .. }
        ));
        assert!(matches!(
            Sexp::from_bytes(
                crate::tests::file("sexp/ecdsa-signature.sexp")).unwrap()
                    .to_signature().unwrap(),
                ECDSA { .. }
        ));
        assert!(matches!(
            Sexp::from_bytes(
                crate::tests::file("sexp/eddsa-signature.sexp")).unwrap()
                    .to_signature().unwrap(),
                EdDSA { .. }
        ));
        assert!(matches!(
            Sexp::from_bytes(
                crate::tests::file("sexp/rsa-signature.sexp")).unwrap()
                    .to_signature().unwrap(),
                RSA { .. }
        ));
    }
}
