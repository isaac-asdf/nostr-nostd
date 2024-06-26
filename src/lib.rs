#![no_std]
//! Implementation of [Nostr](https://nostr.com/) for a #![no_std] environment. It supports note creation and parsing relay responses.
//! An example project using an esp32 can be seen [here](https://github.com/isaac-asdf/esp32-nostr-client).
//!
//! # Example
//! ```
//! use nostr_nostd::{Note, String, ClientMsgKinds};
//! let privkey = "a5084b35a58e3e1a26f5efb46cb9dbada73191526aa6d11bccb590cbeb2d8fa3";
//! let content: String<400> = String::from("Hello, World!");
//! let tag: String<150> = String::from("relay,wss://relay.example.com/");
//! // aux_rand should be generated from a random number generator
//! // required to keep PRIVKEY secure with Schnorr signatures
//! let aux_rand = [0; 32];
//! let note = Note::new_builder(privkey)
//!     .unwrap()
//!     .content(content)
//!     .add_tag(tag)
//!     .build(1686880020, aux_rand)
//!     .unwrap();
//! let msg = note.serialize_to_relay(ClientMsgKinds::Event);
//! ```
//!

pub use heapless::{String, Vec};
use relay_responses::AuthMessage;
use secp256k1::{
    self, ffi::types::AlignedType, schnorr::Signature, KeyPair, Message, XOnlyPublicKey,
};
use sha2::{Digest, Sha256};
use utils::to_decimal_str;

pub mod errors;
mod nip04;
mod parse_json;
pub mod query;
pub mod relay_responses;
mod utils;

const TAG_SIZE: usize = 150;
const NOTE_SIZE: usize = 400;
const MAX_DM_SIZE: usize = 400;

/// Defined by the [nostr protocol](https://github.com/nostr-protocol/nips/tree/master#event-kinds)
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum NoteKinds {
    /// For most short text based notes
    ShortNote,
    /// DM
    DM,
    /// IOT Event,
    IOT,
    /// Ephemeral event for authentication to relay
    Auth,
    /// Regular Events (must be between 1000 and <=9999)
    Regular(u16),
    /// Replacabe event (must be between 10000 and <20000)
    Replaceable(u16),
    /// Ephemeral event (must be between 20000 and <30000)
    Ephemeral(u16),
    /// Parameterized Replacabe event (must be between 30000 and <40000)
    ParameterizedReplaceable(u16),
    /// Custom
    Custom(u16),
}

impl NoteKinds {
    pub fn serialize(&self) -> String<10> {
        // will ignore large bytes when serializing
        let n: u16 = match self {
            NoteKinds::ShortNote => 1,
            NoteKinds::DM => 4,
            NoteKinds::IOT => 5732,
            NoteKinds::Auth => 22242,
            NoteKinds::Regular(val) => *val,
            NoteKinds::Replaceable(val) => *val,
            NoteKinds::Ephemeral(val) => *val,
            NoteKinds::ParameterizedReplaceable(val) => *val,
            NoteKinds::Custom(val) => *val,
        };

        to_decimal_str(n as u32)
    }
}

impl From<u16> for NoteKinds {
    fn from(value: u16) -> Self {
        match value {
            1 => NoteKinds::ShortNote,
            4 => NoteKinds::DM,
            5732 => NoteKinds::IOT,
            22242 => NoteKinds::Auth,
            x if (1_000..10_000).contains(&x) => NoteKinds::Regular(x as u16),
            x if (10_000..20_000).contains(&x) => NoteKinds::Replaceable(x as u16),
            x if (20_000..30_000).contains(&x) => NoteKinds::Ephemeral(x as u16),
            x if (30_000..40_000).contains(&x) => NoteKinds::ParameterizedReplaceable(x as u16),
            x => NoteKinds::Custom(x),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ClientMsgKinds {
    Event,
    Req,
    Auth,
    Close,
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
    #[inline]
    fn next(self) -> OneTag {
        OneTag
    }
}
impl AddTag for OneTag {
    type Next = TwoTags;
    #[inline]
    fn next(self) -> TwoTags {
        TwoTags
    }
}
impl AddTag for TwoTags {
    type Next = ThreeTags;
    #[inline]
    fn next(self) -> ThreeTags {
        ThreeTags
    }
}
impl AddTag for ThreeTags {
    type Next = FourTags;
    #[inline]
    fn next(self) -> FourTags {
        FourTags
    }
}
impl AddTag for FourTags {
    type Next = FiveTags;
    #[inline]
    fn next(self) -> FiveTags {
        FiveTags
    }
}

/// Used to track the addition of the time created and the number of tags added
pub struct BuildStatus<B> {
    tags: B,
}

/// Used to fill in the fields of a Note.
pub struct NoteBuilder<B> {
    keypair: KeyPair,
    build_status: BuildStatus<B>,
    note: Note,
}

impl<T, NextAddTag> NoteBuilder<T>
where
    T: AddTag<Next = NextAddTag>,
    NextAddTag: TagCount,
{
    /// Adds a new tag to the note.
    /// The maximum number of tags currently allowed is 5.
    /// Attempts to add too many tags will be a compilation error.
    #[inline]
    pub fn add_tag(mut self, tag: String<TAG_SIZE>) -> NoteBuilder<NextAddTag> {
        let next_tags = self.build_status.tags.next();
        self.note
            .tags
            .push(tag)
            .expect("AddTag impl error, should be impossible to err here");

        NoteBuilder {
            build_status: BuildStatus { tags: next_tags },
            keypair: self.keypair,
            note: self.note,
        }
    }
}

impl<B> NoteBuilder<B> {
    /// Sets the "kind" field of the note
    pub fn set_kind(mut self, kind: NoteKinds) -> Self {
        self.note.kind = kind;
        self
    }

    /// Sets the "content" field of Note
    pub fn content(mut self, content: String<NOTE_SIZE>) -> Self {
        self.note.content = Some(content);
        self
    }
}

impl NoteBuilder<ZeroTags> {
    /// Creates an auth note per NIP42
    #[inline]
    pub fn create_auth(
        mut self,
        auth: &AuthMessage,
        relay: &str,
    ) -> Result<NoteBuilder<TwoTags>, errors::Error> {
        let mut tags = Vec::new();
        let mut challenge_string: String<TAG_SIZE> = String::from("challenge,");
        challenge_string
            .push_str(&auth.challenge_string)
            .map_err(|_| errors::Error::ContentOverflow)?;
        tags.push(challenge_string).expect("impossible");
        let mut relay_str: String<TAG_SIZE> = String::from("relay,");
        relay_str
            .push_str(relay)
            .map_err(|_| errors::Error::ContentOverflow)?;
        tags.push(relay_str).expect("impossible");
        self.note.tags = tags;
        self.note.kind = NoteKinds::Auth;
        Ok(NoteBuilder {
            keypair: self.keypair,
            note: self.note,
            build_status: BuildStatus { tags: TwoTags },
        })
    }

    /// Sets the "content" field according to NIP04 and adds the tag for receiver pubkey.
    /// iv should be generated from a random source
    #[inline]
    pub fn create_dm(
        mut self,
        content: &str,
        rcvr_pubkey: &str,
        iv: [u8; 16],
    ) -> Result<NoteBuilder<OneTag>, errors::Error> {
        let mut msg = [0_u8; 32];
        base16ct::lower::decode(&rcvr_pubkey, &mut msg)
            .map_err(|_| errors::Error::InvalidPubkey)?;
        let pubkey = XOnlyPublicKey::from_slice(&msg).map_err(|_| errors::Error::InvalidPubkey)?;
        let encrypted = nip04::encrypt(&self.keypair.secret_key(), &pubkey, content, iv)?;
        self.note.content = Some(encrypted);
        let mut tag = String::from("p,");
        tag.push_str(rcvr_pubkey).expect("impossible");
        Ok(self.add_tag(tag))
    }
}

impl<A> NoteBuilder<A> {
    /// Set the 'created_at' and sign the note.
    #[inline]
    pub fn build(mut self, created_at: u32, aux_rnd: [u8; 32]) -> Result<Note, errors::Error> {
        self.note.created_at = created_at;
        self.note.set_pubkey(&self.keypair.x_only_public_key().0)?;
        self.note.set_id()?;
        self.note.set_sig(&self.keypair, &aux_rnd)?;
        Ok(self.note)
    }
}

impl Note {
    /// Returns a NoteBuilder, can error if the privkey is invalid
    #[inline]
    pub fn new_builder(privkey: &str) -> Result<NoteBuilder<ZeroTags>, errors::Error> {
        let mut buf = [AlignedType::zeroed(); 64];
        let sig_obj = secp256k1::Secp256k1::preallocated_new(&mut buf)
            .map_err(|_| errors::Error::Secp256k1Error)?;
        let key_pair: KeyPair = KeyPair::from_seckey_str(&sig_obj, privkey)
            .map_err(|_| errors::Error::InvalidPrivkey)?;
        Ok(NoteBuilder {
            build_status: BuildStatus { tags: ZeroTags },
            keypair: key_pair,
            note: Note {
                id: [0; 64],
                pubkey: [0; 64],
                created_at: 0,
                kind: NoteKinds::ShortNote,
                tags: Vec::new(),
                content: None,
                sig: [0; 128],
            },
        })
    }

    fn timestamp_bytes(&self) -> String<10> {
        to_decimal_str(self.created_at)
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
        self.timestamp_bytes().chars().for_each(|bs| {
            hash_str[count] = bs as u8;
            count += 1;
        });
        hash_str[count] = 44; // 44 = ,
        count += 1;
        self.kind.serialize().chars().for_each(|bs| {
            hash_str[count] = bs as u8;
            count += 1;
        });
        hash_str[count] = 44; // 44 = ,
        count += 1;
        // tags
        br#"["#.iter().for_each(|bs| {
            hash_str[count] = *bs;
            count += 1;
        });
        let mut tags_present = false;
        self.tags.iter().for_each(|tag| {
            // add opening [
            hash_str[count] = 91;
            count += 1;
            tag.split(",").for_each(|element| {
                // add opening "
                hash_str[count] = 34;
                count += 1;
                element.as_bytes().iter().for_each(|bs| {
                    hash_str[count] = *bs;
                    count += 1;
                });
                // add closing "
                hash_str[count] = 34;
                count += 1;
                // add , separator back in
                hash_str[count] = 44;
                count += 1;
            });
            // remove last comma
            count -= 1;
            // add closing ]
            hash_str[count] = 93;
            count += 1;

            // add closing ,
            hash_str[count] = 44;
            count += 1;
            tags_present = true;
        });
        if tags_present {
            // remove last comma
            count -= 1;
        }
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

    fn set_pubkey(&mut self, pubkey: &XOnlyPublicKey) -> Result<(), errors::Error> {
        let pubkey = &pubkey.serialize();
        base16ct::lower::encode(pubkey, &mut self.pubkey)
            .map_err(|_| errors::Error::EncodeError)?;
        Ok(())
    }

    fn set_id(&mut self) -> Result<(), errors::Error> {
        let (remaining, len) = self.to_hash_str();
        let mut hasher = Sha256::new();
        hasher.update(&remaining[..len]);
        let results = hasher.finalize();
        base16ct::lower::encode(&results, &mut self.id).map_err(|_| errors::Error::EncodeError)?;
        Ok(())
    }

    fn set_sig(&mut self, key_pair: &KeyPair, aux_rnd: &[u8; 32]) -> Result<(), errors::Error> {
        // figure out what size we need and why
        let mut buf = [AlignedType::zeroed(); 64];
        let sig_obj = secp256k1::Secp256k1::preallocated_new(&mut buf)
            .map_err(|_| errors::Error::Secp256k1Error)?;

        let mut msg = [0_u8; 32];
        base16ct::lower::decode(&self.id, &mut msg)
            .map_err(|_| errors::Error::InternalSigningError)?;

        let message = Message::from_slice(&msg).map_err(|_| errors::Error::InternalSigningError)?;

        let sig = sig_obj.sign_schnorr_with_aux_rand(&message, key_pair, aux_rnd);
        base16ct::lower::encode(sig.as_ref(), &mut self.sig)
            .map_err(|_| errors::Error::EncodeError)?;
        Ok(())
    }

    /// Validates the events signature
    pub fn validate_signature(&self) -> Result<(), errors::Error> {
        let mut buf = [AlignedType::zeroed(); 64];
        let sig_obj = secp256k1::Secp256k1::preallocated_new(&mut buf)
            .map_err(|_| errors::Error::Secp256k1Error)?;

        let mut msg = [0_u8; 32];
        base16ct::lower::decode(&self.id, &mut msg)
            .map_err(|_| errors::Error::InternalSigningError)
            .expect("1");

        let message = Message::from_slice(&msg)
            .map_err(|_| errors::Error::InternalSigningError)
            .expect("2");
        let mut msg = [0_u8; 64];
        base16ct::lower::decode(&self.sig, &mut msg)
            .map_err(|_| errors::Error::InternalSigningError)
            .expect("5");
        let sig = Signature::from_slice(&msg)
            .map_err(|_| errors::Error::InternalSigningError)
            .expect("3");

        let mut msg = [0_u8; 32];
        base16ct::lower::decode(&self.pubkey, &mut msg)
            .map_err(|_| errors::Error::InternalSigningError)
            .expect("1");
        let pubkey = XOnlyPublicKey::from_slice(&msg)
            .map_err(|_| errors::Error::InternalSigningError)
            .expect("4");

        sig_obj
            .verify_schnorr(&sig, &message, &pubkey)
            .map_err(|_| errors::Error::InvalidSignature)
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
        self.timestamp_bytes().chars().for_each(|bs| {
            output
                .push(bs as u8)
                .expect("Impossible due to size constraints of content, tags");
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
        self.kind.serialize().chars().for_each(|bs| {
            output
                .push(bs as u8)
                .expect("Impossible due to size constraints of content, tags");
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
        let mut tags_present = false;
        self.tags.iter().for_each(|tag| {
            // add opening [
            output.push(91).expect("impossible");
            tag.split(",").for_each(|element| {
                // add opening "
                output.push(34).expect("impossible");
                element.as_bytes().iter().for_each(|bs| {
                    output.push(*bs).expect("impossible");
                });
                // add closing "
                output.push(34).expect("impossible");
                // add a comma separator
                output.push(44).expect("impossible");
            });
            // remove last comma
            output.pop().expect("impossible");
            // add closing ]
            output.push(93).expect("impossible");
            // add a comma separator
            output.push(44).expect("impossible");
            tags_present = true;
        });
        if tags_present {
            // remove last comma
            output.pop().expect("impossible");
        }
        br#"]}"#.iter().for_each(|bs| {
            output
                .push(*bs)
                .expect("Impossible due to size constraints of content, tags");
        });

        output
    }

    /// Serializes the note for sending to relay
    #[inline]
    pub fn serialize_to_relay(self, msg_type: ClientMsgKinds) -> Vec<u8, 1000> {
        let wire_lead = match msg_type {
            ClientMsgKinds::Event => r#"["EVENT","#,
            ClientMsgKinds::Req => r#"["REQ","#,
            ClientMsgKinds::Auth => r#"["AUTH","#,
            ClientMsgKinds::Close => r#"["CLOSE","#,
        };
        let mut output: Vec<u8, 1000> = Vec::new();
        // fill in output
        wire_lead.as_bytes().iter().for_each(|bs| {
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

    /// Get associated values with a given tag name.
    /// Returns up to 5 instances for the searched for label.
    #[inline]
    pub fn get_tag(&self, tag: &str) -> Result<Vec<Vec<&str, 5>, 5>, errors::Error> {
        let mut search_tag: String<10> = String::from(tag);
        search_tag
            .push_str(",")
            .map_err(|_| errors::Error::TagNameTooLong)?;
        Ok(self
            .tags
            .iter()
            .filter(|my_tag| my_tag.starts_with(search_tag.as_str()))
            // each tag will look like tag_name,val1,val2,etc...
            .map(|tag| {
                let mut splits = tag.split(",");
                // remove tag_name from splits
                splits.next();
                splits.collect()
            })
            .collect())
    }

    /// Decode an encrypted DM
    #[inline]
    pub fn read_dm(&self, privkey: &str) -> Result<String<MAX_DM_SIZE>, errors::Error> {
        let mut buf = [AlignedType::zeroed(); 64];
        let sig_obj = secp256k1::Secp256k1::preallocated_new(&mut buf)
            .map_err(|_| errors::Error::Secp256k1Error)?;
        let key_pair: KeyPair = KeyPair::from_seckey_str(&sig_obj, privkey)
            .map_err(|_| errors::Error::InvalidPrivkey)?;
        let sk = key_pair.secret_key();
        let pk_tag = self.get_tag("p")?;
        let pk_tag = *pk_tag
            .first()
            .ok_or(errors::Error::MalformedContent)?
            .first()
            .ok_or(errors::Error::MalformedContent)?;
        let mut msg = [0_u8; 32];
        base16ct::lower::decode(&pk_tag, &mut msg).map_err(|_| errors::Error::EncodeError)?;
        let pk = XOnlyPublicKey::from_slice(&msg).map_err(|_| errors::Error::InvalidPubkey)?;
        nip04::decrypt(
            &sk,
            &pk,
            self.content
                .as_ref()
                .ok_or(errors::Error::MalformedContent)?
                .as_str(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PRIVKEY: &str = "a5084b35a58e3e1a26f5efb46cb9dbada73191526aa6d11bccb590cbeb2d8fa3";

    fn get_note() -> Note {
        Note::new_builder(PRIVKEY)
            .unwrap()
            .content("esptest".into())
            .build(1686880020, [0; 32])
            .expect("infallible")
    }

    #[test]
    fn test_note_with_tag() {
        let note = Note::new_builder(PRIVKEY)
            .unwrap()
            .content("esptest".into())
            .add_tag("l,bitcoin".into())
            .build(1686880020, [0; 32])
            .expect("infallible");
        let test = note.serialize_to_relay(ClientMsgKinds::Event);
        let expected = br#"["EVENT",{"content":"esptest","created_at":1686880020,"id":"f5a693c9a4add3739a4186c0422f925981f75cb1f7a0adfc48852e54973415a6","kind":1,"pubkey":"098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf","sig":"ff68b2c739f6d19df47c5ae5f150895e11876458afcf8bf169636e55c2b6cce1230d0c54ce9869b555b3395018c1efdad5b4c5a4afbc2748e1f8c3a34da787ec","tags":[["l","bitcoin"]]}]"#;
        assert_eq!(test, expected);
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
        let ts = note.timestamp_bytes();
        assert_eq!(ts, String::<10>::from("1686880020"));
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
    fn json_sig_invalid() {
        let json = r#"{"content":"esptest","created_at":1686880020,"id":"b515da91ac5df638fae0a6e658e03acc1dda6152dd2107d02d5702ccfcf927e8","kind":1,"pubkey":"098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf","sig":"89a4f1ad4b65371e6c3167ea8cb13e73cf64dd5ee71224b1edd8c32ad817af2312202cadb2f22f35d599793e8b1c66b3979d4030f1e7a252098da4a4e0c48fab","tags":[]"#;
        let note = Note::try_from(json);
        assert!(note.is_ok());

        let json = r#"{"content":"esptest","created_at":1686880020,"id":"c515da91ac5df638fae0a6e658e03acc1dda6152dd2107d02d5702ccfcf927e8","kind":1,"pubkey":"098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf","sig":"89a4f1ad4b65371e6c3167ea8cb13e73cf64dd5ee71224b1edd8c32ad817af2312202cadb2f22f35d599793e8b1c66b3979d4030f1e7a252098da4a4e0c48fab","tags":[]"#;
        let note = Note::try_from(json);
        assert_eq!(note, Err(errors::Error::InvalidSignature))
    }

    #[test]
    fn serialize_to_relay_test() {
        let output =  br#"["EVENT",{"content":"esptest","created_at":1686880020,"id":"b515da91ac5df638fae0a6e658e03acc1dda6152dd2107d02d5702ccfcf927e8","kind":1,"pubkey":"098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf","sig":"89a4f1ad4b65371e6c3167ea8cb13e73cf64dd5ee71224b1edd8c32ad817af2312202cadb2f22f35d599793e8b1c66b3979d4030f1e7a252098da4a4e0c48fab","tags":[]}]"#;
        let note = get_note();
        let msg = note.serialize_to_relay(ClientMsgKinds::Event);
        assert_eq!(&msg, output);
    }

    #[test]
    fn test_from_json() {
        let json = r#"{"content":"esptest","created_at":1686880020,"id":"b515da91ac5df638fae0a6e658e03acc1dda6152dd2107d02d5702ccfcf927e8","kind":1,"pubkey":"098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf","sig":"89a4f1ad4b65371e6c3167ea8cb13e73cf64dd5ee71224b1edd8c32ad817af2312202cadb2f22f35d599793e8b1c66b3979d4030f1e7a252098da4a4e0c48fab","tags":[]"#;
        let note = Note::try_from(json).expect("infallible");
        let expected_note = get_note();
        assert_eq!(note, expected_note);
    }

    #[test]
    fn test_tags() {
        let dm_rcv: &str = r#"{"content":"sZhES/uuV1uMmt9neb6OQw6mykdLYerAnTN+LodleSI=?iv=eM0mGFqFhxmmMwE4YPsQMQ==","created_at":1691110186,"id":"517a5f0f29f5037d763bbd5fbe96c9082c1d39eca917aa22b514c5effc36bab9","kind":4,"pubkey":"ed984a5438492bdc75860aad15a59f8e2f858792824d615401fb49d79c2087b0","sig":"3097de7d5070b892b81b245a5b276eccd7cb283a29a934a71af4960188e55e87d639b774cc331eb9f94ea7c46373c52b8ab39bfee75fe4bb11a1dd4c187e1f3e","tags":[["p","098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf"]]}"#;
        let note = Note::try_from(dm_rcv).unwrap();

        let tags = note.get_tag("p").unwrap();
        let pubkey = tags.first().unwrap().first().unwrap();
        assert_eq!(
            *pubkey,
            "098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf"
        );
    }

    #[test]
    fn test_get_tag() {
        let mut tags = Vec::new();
        tags.push(String::from("p,test_pubkey")).unwrap();
        let note = Note {
            id: [0; 64],
            pubkey: [0; 64],
            created_at: 0,
            kind: NoteKinds::DM,
            tags,
            content: None,
            sig: [0; 128],
        };
        let tags = note.get_tag("p").unwrap();
        let pubkey = tags.first().unwrap().first().unwrap();
        assert_eq!(*pubkey, "test_pubkey");
    }

    #[test]
    fn test_get_two_tags() {
        let mut tags = Vec::new();
        tags.push(String::from("l,labeled,another label")).unwrap();
        tags.push(String::from("l,ignore the other label")).unwrap();
        let note = Note {
            id: [0; 64],
            pubkey: [0; 64],
            created_at: 0,
            kind: NoteKinds::DM,
            tags,
            content: None,
            sig: [0; 128],
        };
        let binding = note.get_tag("l").unwrap();
        let mut tags = binding.iter();
        let label = tags.next().unwrap();
        let mut labels = label.iter();
        assert_eq!(*labels.next().unwrap(), "labeled");
        assert_eq!(*labels.next().unwrap(), "another label");

        let label = tags.next().unwrap();
        let mut labels = label.iter();
        assert_eq!(*labels.next().unwrap(), "ignore the other label");
    }

    #[test]
    fn test_auth_msg() {
        let note = Note::new_builder(PRIVKEY)
            .unwrap()
            .create_auth(
                &AuthMessage {
                    challenge_string: "challenge_me".into(),
                },
                "wss://relay.damus.io",
            )
            .unwrap()
            .build(1691712199, [0; 32])
            .unwrap();

        let expected = br#"{"content":"","created_at":1691712199,"id":"762b497576a41636c41eb5c74c0eb80894ecb2444c3e5117da0d00d9870d914a","kind":22242,"pubkey":"098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf","sig":"afb892c683222936537ac1ea1ecdade47adf572e96773dfc6ca021d929d3485ecd7d086b14503e545312f61bd8ffdbd48887cd27b3ab2e4f70aab62a4a1afd1b","tags":[["challenge","challenge_me"],["relay","wss://relay.damus.io"]]}"#;
        assert_eq!(note.to_json(), expected);
    }
}
