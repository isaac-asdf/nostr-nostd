// #![no_std]
//! Implementation of [Nostr](https://nostr.com/) note creation for a #![no_std] environment.
//! An example project using an esp32 can be seen [here](https://github.com/isaac-asdf/esp32-nostr-client).
//!
//! # Example
//! ```
//! use nostr_nostd::{Note, String};
//! const PRIVKEY: &str = "a5084b35a58e3e1a26f5efb46cb9dbada73191526aa6d11bccb590cbeb2d8fa3";
//! let content: String<100> = String::from("Hello, World!");
//! let tag: String<150> = String::from(r#"["relay", "wss://relay.example.com/"]"#);
//! // aux_rand should be generated from a random number generator
//! // required to keep PRIVKEY secure with Schnorr signatures
//! let aux_rand = [0; 32];
//! let note = Note::new()
//!     .content(content)
//!     .add_tag(tag)
//!     .created_at(1686880020)
//!     .build(PRIVKEY, aux_rand)
//!     .unwrap();
//! let msg = note.serialize_to_relay();
//! ```
//!
pub use heapless::{String, Vec};
use secp256k1::{self, ffi::types::AlignedType, KeyPair, Message};
use sha2::{Digest, Sha256};

pub mod errors;
pub mod nip04;
mod parse_json;
pub mod relay_responses;

const TAG_SIZE: usize = 150;
const NOTE_SIZE: usize = 100;

/// Defined by the [nostr protocol](https://github.com/nostr-protocol/nips/tree/master#event-kinds)
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum NoteKinds {
    /// For most short text based notes
    ShortNote = 1,
    /// DM
    DM = 4,
    /// Ephemeral event for authentication to relay
    Auth = 22242,
}

impl TryFrom<u16> for NoteKinds {
    type Error = errors::Error;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(NoteKinds::ShortNote),
            4 => Ok(NoteKinds::DM),
            22242 => Ok(NoteKinds::Auth),
            _ => Err(errors::Error::UnknownKind),
        }
    }
}

impl NoteKinds {
    pub fn serialize(&self) -> [u8; 10] {
        // will ignore large bytes when serializing
        let mut buffer = [255_u8; 10];
        let mut idx = buffer.len();
        let mut n = *self as u32;

        while n > 0 && idx > 0 {
            idx -= 1;
            buffer[idx] = b'0' + (n % 10) as u8;
            n /= 10;
        }

        buffer
    }
}

/// Representation of Nostr Note
#[derive(Debug, PartialEq)]
pub struct Note {
    /// ID of note
    id: [u8; 64],
    /// Derived from privkey, refers to note creator
    pubkey: [u8; 64],
    /// Unix timestamp
    created_at: u32,
    /// Default to kind 1
    kind: NoteKinds,
    tags: Vec<String<TAG_SIZE>, 5>,
    content: Option<String<NOTE_SIZE>>,
    sig: [u8; 128],
}

/// NoteBuilder has had `.created_at()` called and is ready for `.build()`
pub struct TimeSet;
/// NoteBuilder is waiting for `.created_at()` prior to `.build()`
pub struct TimeNotSet;

/// Impl for tags which can had an additional tag added.
/// ie, not implemented for FiveTags but implemented for all others
pub trait AddTag {
    type Next: TagCount;
    // Add a generic parameter for the return type, bounded by TagCount
    fn next(self) -> Self::Next;
}
/// Number of tags added
pub trait TagCount {}
/// No tags have been added
pub struct ZeroTags;
/// One tag has been added
pub struct OneTag;
/// Two tags have been added
pub struct TwoTags;
/// Three tags have been added
pub struct ThreeTags;
/// Four tags have been added
pub struct FourTags;
/// Five tags have been added
pub struct FiveTags;

impl TagCount for ZeroTags {}
impl TagCount for OneTag {}
impl TagCount for TwoTags {}
impl TagCount for ThreeTags {}
impl TagCount for FourTags {}
impl TagCount for FiveTags {}

impl AddTag for ZeroTags {
    type Next = OneTag;
    // Implement the next method to return a new MyType instance
    fn next(self) -> OneTag {
        OneTag
    }
}
impl AddTag for OneTag {
    type Next = TwoTags;
    fn next(self) -> TwoTags {
        TwoTags
    }
}
impl AddTag for TwoTags {
    type Next = ThreeTags;
    fn next(self) -> ThreeTags {
        ThreeTags
    }
}
impl AddTag for ThreeTags {
    type Next = FourTags;
    fn next(self) -> FourTags {
        FourTags
    }
}
impl AddTag for FourTags {
    type Next = FiveTags;
    fn next(self) -> FiveTags {
        FiveTags
    }
}

/// Used to track the addition of the time created and the number of tags added
pub struct BuildStatus<A, B> {
    time: A,
    tags: B,
}

/// Used to fill in the fields of a Note.
pub struct NoteBuilder<A, B> {
    build_status: BuildStatus<A, B>,
    note: Note,
}

impl<A, T, NextAddTag> NoteBuilder<A, T>
where
    T: AddTag<Next = NextAddTag>,
    NextAddTag: TagCount,
{
    /// Adds a new tag to the note.
    /// The maximum number of tags currently allowed is 5.
    /// Attempts to add too many tags will be a compilation error.
    ///
    /// # Example
    /// ```
    /// use nostr_nostd::{Note, String};
    /// const PRIVKEY: &str = "a5084b35a58e3e1a26f5efb46cb9dbada73191526aa6d11bccb590cbeb2d8fa3";
    /// let content: String<100> = String::from("i have tags");
    /// let tag: String<150> = String::from(r#"["relay", "wss://relay.example.com/"]"#);
    /// let note = Note::new()
    ///     .content(content)
    ///     .add_tag(tag)
    ///     .created_at(1690076405)
    ///     .build(PRIVKEY, [0; 32]);
    /// ```

    pub fn add_tag(mut self, tag: String<TAG_SIZE>) -> NoteBuilder<A, NextAddTag> {
        let next_tags = self.build_status.tags.next();
        self.note
            .tags
            .push(tag)
            .expect("AddTag impl error, should be impossible to err here");

        NoteBuilder {
            build_status: BuildStatus {
                time: self.build_status.time,
                tags: next_tags,
            },
            note: self.note,
        }
    }
}

impl<A, B> NoteBuilder<A, B> {
    /// Sets the "kind" field of the note
    pub fn set_kind(mut self, kind: NoteKinds) -> Self {
        self.note.kind = kind;
        self
    }

    /// Sets the "content" field of Note
    pub fn content(mut self, content: String<100>) -> Self {
        self.note.content = Some(content);
        self
    }
}

impl<A> NoteBuilder<TimeNotSet, A> {
    /// Must be called prior to build() to set the time of the note
    pub fn created_at(mut self, created_at: u32) -> NoteBuilder<TimeSet, A> {
        self.note.created_at = created_at;
        NoteBuilder {
            build_status: BuildStatus {
                time: TimeSet,
                tags: self.build_status.tags,
            },
            note: self.note,
        }
    }
}

impl<A> NoteBuilder<TimeSet, A> {
    pub fn build(mut self, privkey: &str, aux_rnd: [u8; 32]) -> Result<Note, errors::Error> {
        self.note.set_pubkey(privkey)?;
        self.note.set_id()?;
        self.note.set_sig(privkey, &aux_rnd)?;
        Ok(self.note)
    }
}

impl Note {
    /// Returns a new Note
    /// # Arguments
    ///
    /// * `content` - data to be included in "content" field
    /// * `aux_rnd` - MUST be unique for each note created to avoid leaking private key
    /// * `created_at` - Unix timestamp for note creation time
    ///
    pub fn new() -> NoteBuilder<TimeNotSet, ZeroTags> {
        NoteBuilder {
            build_status: BuildStatus {
                time: TimeNotSet,
                tags: ZeroTags,
            },
            note: Note {
                id: [0; 64],
                pubkey: [0; 64],
                created_at: 0,
                kind: NoteKinds::ShortNote,
                tags: Vec::new(),
                content: None,
                sig: [0; 128],
            },
        }
    }

    fn timestamp_bytes(&self) -> [u8; 10] {
        // thanks to ChatGPT for the below code :)
        let mut buffer = [255_u8; 10];
        let mut idx = buffer.len();
        let mut n = self.created_at;

        while n > 0 && idx > 0 {
            idx -= 1;
            buffer[idx] = b'0' + (n % 10) as u8;
            n /= 10;
        }

        buffer
    }

    fn to_hash_str(&self) -> ([u8; 1536], usize) {
        let mut hash_str = [0; 1536];
        let mut count = 0;
        br#"[0,""#.iter().for_each(|bs| {
            hash_str[count] = *bs;
            count += 1;
        });
        self.pubkey.iter().for_each(|bs| {
            hash_str[count] = *bs;
            count += 1;
        });
        br#"","#.iter().for_each(|bs| {
            hash_str[count] = *bs;
            count += 1;
        });
        self.timestamp_bytes().iter().for_each(|bs| {
            if *bs != 255 {
                hash_str[count] = *bs;
                count += 1;
            }
        });
        hash_str[count] = 44; // 44 = ,
        count += 1;
        self.kind.serialize().iter().for_each(|bs| {
            if *bs != 255 {
                hash_str[count] = *bs;
                count += 1;
            }
        });
        hash_str[count] = 44; // 44 = ,
        count += 1;
        // tags
        br#"["#.iter().for_each(|bs| {
            hash_str[count] = *bs;
            count += 1;
        });
        self.tags.iter().for_each(|tag| {
            tag.as_bytes().iter().for_each(|bs| {
                hash_str[count] = *bs;
                count += 1;
            })
        });
        br#"],""#.iter().for_each(|bs| {
            hash_str[count] = *bs;
            count += 1;
        });
        if let Some(content) = &self.content {
            content.as_bytes().iter().for_each(|bs| {
                hash_str[count] = *bs;
                count += 1;
            });
        }
        br#""]"#.iter().for_each(|bs| {
            hash_str[count] = *bs;
            count += 1;
        });
        (hash_str, count)
    }

    fn set_pubkey(&mut self, privkey: &str) -> Result<(), errors::Error> {
        let mut buf = [AlignedType::zeroed(); 64];
        let sig_obj = secp256k1::Secp256k1::preallocated_new(&mut buf)
            .map_err(|_| errors::Error::InternalPubkeyError)?;
        let key_pair = KeyPair::from_seckey_str(&sig_obj, privkey)
            .map_err(|_| errors::Error::InvalidPrivkey)?;
        let pubkey = &key_pair.public_key().serialize()[1..33];
        base16ct::lower::encode(pubkey, &mut self.pubkey)
            .map_err(|_| errors::Error::InternalPubkeyError)?;
        Ok(())
    }

    fn set_id(&mut self) -> Result<(), errors::Error> {
        let (remaining, len) = self.to_hash_str();
        let mut hasher = Sha256::new();
        hasher.update(&remaining[..len]);
        let results = hasher.finalize();
        base16ct::lower::encode(&results, &mut self.id)
            .map_err(|_| errors::Error::InternalPubkeyError)?;
        Ok(())
    }

    fn set_sig(&mut self, privkey: &str, aux_rnd: &[u8; 32]) -> Result<(), errors::Error> {
        // figure out what size we need and why
        let mut buf = [AlignedType::zeroed(); 64];
        let sig_obj = secp256k1::Secp256k1::preallocated_new(&mut buf)
            .map_err(|_| errors::Error::InternalSigningError)?;

        let mut msg = [0_u8; 32];
        base16ct::lower::decode(&self.id, &mut msg)
            .map_err(|_| errors::Error::InternalSigningError)?;

        let message = Message::from_slice(&msg).map_err(|_| errors::Error::InternalSigningError)?;
        let key_pair = KeyPair::from_seckey_str(&sig_obj, privkey)
            .map_err(|_| errors::Error::InvalidPrivkey)?;
        let sig = sig_obj.sign_schnorr_with_aux_rand(&message, &key_pair, aux_rnd);
        base16ct::lower::encode(sig.as_ref(), &mut self.sig)
            .map_err(|_| errors::Error::InternalSigningError)?;
        Ok(())
    }

    fn to_json(&self) -> Vec<u8, 1000> {
        let mut output: Vec<u8, 1000> = Vec::new();
        br#"{"content":""#.iter().for_each(|bs| {
            // handle result?
            output
                .push(*bs)
                .expect("Impossible due to size constraints of content, tags");
        });
        if let Some(content) = &self.content {
            content.as_bytes().iter().for_each(|bs| {
                output
                    .push(*bs)
                    .expect("Impossible due to size constraints of content, tags");
            });
        }
        br#"","created_at":"#.iter().for_each(|bs| {
            output
                .push(*bs)
                .expect("Impossible due to size constraints of content, tags");
        });
        self.timestamp_bytes().iter().for_each(|bs| {
            if *bs != 255 {
                output
                    .push(*bs)
                    .expect("Impossible due to size constraints of content, tags");
            }
        });
        br#","id":""#.iter().for_each(|bs| {
            output
                .push(*bs)
                .expect("Impossible due to size constraints of content, tags");
        });
        self.id.iter().for_each(|bs| {
            output
                .push(*bs)
                .expect("Impossible due to size constraints of content, tags");
        });
        br#"","kind":"#.iter().for_each(|bs| {
            output
                .push(*bs)
                .expect("Impossible due to size constraints of content, tags");
        });
        self.kind.serialize().iter().for_each(|bs| {
            if *bs != 255 {
                output
                    .push(*bs)
                    .expect("Impossible due to size constraints of content, tags");
            }
        });
        br#","pubkey":""#.iter().for_each(|bs| {
            output
                .push(*bs)
                .expect("Impossible due to size constraints of content, tags");
        });
        self.pubkey.iter().for_each(|bs| {
            output
                .push(*bs)
                .expect("Impossible due to size constraints of content, tags");
        });
        br#"","sig":""#.iter().for_each(|bs| {
            output
                .push(*bs)
                .expect("Impossible due to size constraints of content, tags");
        });
        self.sig.iter().for_each(|bs| {
            output
                .push(*bs)
                .expect("Impossible due to size constraints of content, tags");
        });
        br#"","tags":["#.iter().for_each(|bs| {
            output
                .push(*bs)
                .expect("Impossible due to size constraints of content, tags");
        });
        self.tags.iter().for_each(|tag| {
            tag.as_bytes().iter().for_each(|bs| {
                output
                    .push(*bs)
                    .expect("Impossible due to size constraints of content, tags");
            })
        });
        br#"]}"#.iter().for_each(|bs| {
            output
                .push(*bs)
                .expect("Impossible due to size constraints of content, tags");
        });

        output
    }

    /// Serializes the note as ["EVENT", {note}]
    pub fn serialize_to_relay(self) -> Vec<u8, 1000> {
        let mut output: Vec<u8, 1000> = Vec::new();
        // fill in output
        br#"["EVENT","#.iter().for_each(|bs| {
            output
                .push(*bs)
                .expect("Impossible due to size constraints of content, tags");
        });
        let json = self.to_json();
        json.iter().for_each(|bs| {
            output
                .push(*bs)
                .expect("Impossible due to size constraints of content, tags");
        });
        output
            .push(93)
            .expect("Impossible due to size constraints of content, tags");
        output
    }

    /// Serializes the note as ["AUTH", {note}]
    /// For use with NoteKinds::Auth
    pub fn send_auth_to_relay(self) -> Vec<u8, 1000> {
        let mut output: Vec<u8, 1000> = Vec::new();
        // fill in output
        br#"["AUTH","#.iter().for_each(|bs| {
            output
                .push(*bs)
                .expect("Impossible due to size constraints of content, tags");
        });
        let json = self.to_json();
        json.iter().for_each(|bs| {
            output
                .push(*bs)
                .expect("Impossible due to size constraints of content, tags");
        });
        output
            .push(93)
            .expect("Impossible due to size constraints of content, tags");
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PRIVKEY: &str = "a5084b35a58e3e1a26f5efb46cb9dbada73191526aa6d11bccb590cbeb2d8fa3";

    fn get_note() -> Note {
        Note::new()
            .content("esptest".into())
            .created_at(1686880020)
            .build(PRIVKEY, [0; 32])
            .expect("infallible")
    }

    #[test]
    fn pubkey_test() {
        let note = get_note();
        let pubkey = note.pubkey;
        assert_eq!(
            pubkey,
            *b"098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf"
        );
    }

    #[test]
    fn id_test() {
        let note = get_note();
        let id = note.id;
        assert_eq!(
            id,
            *b"b515da91ac5df638fae0a6e658e03acc1dda6152dd2107d02d5702ccfcf927e8"
        );
    }

    #[test]
    fn timestamp_test() {
        let note = get_note();
        let hash_correct = *b"1686880020";
        let ts = note.timestamp_bytes();
        assert_eq!(ts, hash_correct);
    }

    #[test]
    fn hashstr_test() {
        let note = get_note();
        let hash_correct = br#"[0,"098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf",1686880020,1,[],"esptest"]"#;
        let (hashed, len) = note.to_hash_str();
        let hashed = &hashed[..len];
        assert_eq!(hashed, hash_correct);
    }

    #[test]
    fn json_test() {
        let output =  br#"{"content":"esptest","created_at":1686880020,"id":"b515da91ac5df638fae0a6e658e03acc1dda6152dd2107d02d5702ccfcf927e8","kind":1,"pubkey":"098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf","sig":"89a4f1ad4b65371e6c3167ea8cb13e73cf64dd5ee71224b1edd8c32ad817af2312202cadb2f22f35d599793e8b1c66b3979d4030f1e7a252098da4a4e0c48fab","tags":[]}"#;
        let note = get_note();
        let msg = note.to_json();
        assert_eq!(&msg, output);
    }

    #[test]
    fn serialize_to_relay_test() {
        let output =  br#"["EVENT",{"content":"esptest","created_at":1686880020,"id":"b515da91ac5df638fae0a6e658e03acc1dda6152dd2107d02d5702ccfcf927e8","kind":1,"pubkey":"098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf","sig":"89a4f1ad4b65371e6c3167ea8cb13e73cf64dd5ee71224b1edd8c32ad817af2312202cadb2f22f35d599793e8b1c66b3979d4030f1e7a252098da4a4e0c48fab","tags":[]}]"#;
        let note = get_note();
        let msg = note.serialize_to_relay();
        assert_eq!(&msg, output);
    }

    #[test]
    fn test_from_json() {
        let json = r#"{"content":"esptest","created_at":1686880020,"id":"b515da91ac5df638fae0a6e658e03acc1dda6152dd2107d02d5702ccfcf927e8","kind":1,"pubkey":"098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf","sig":"89a4f1ad4b65371e6c3167ea8cb13e73cf64dd5ee71224b1edd8c32ad817af2312202cadb2f22f35d599793e8b1c66b3979d4030f1e7a252098da4a4e0c48fab","tags":[]"#;
        let note = Note::try_from(json).expect("infallible");
        let expected_note = get_note();
        assert_eq!(note, expected_note);
    }
}
