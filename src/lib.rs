#![no_std]
//! Implementation of [Nostr](https://nostr.com/) note creation for a no_std environment.
//! Example project on an esp32 can be seen [here](https://github.com/isaac-asdf/esp32-nostr-client).
//!
//! # Examples
//! ```
//! use nostr_nostd::Note;
//! const PRIVKEY: &str = "a5084b35a58e3e1a26f5efb46cb9dbada73191526aa6d11bccb590cbeb2d8fa3";
//! let note = Note::new(PRIVKEY, "test note", 1686880020, [0; 32]);
//! let (msg, len) = note.serialize_to_relay();
//! let msg = &msg[0..len];
//! ```
//!
use heapless::String;
use secp256k1::{self, ffi::types::AlignedType, KeyPair, Message};
use sha2::{Digest, Sha256};

/// Defined in [nost-protocol](https://github.com/nostr-protocol/nips/tree/master#event-kinds)
#[derive(Copy, Clone)]
pub enum NoteKinds {
    /// For most short text based notes
    ShortNote = 1,
    /// Ephemeral event for authentication to relay
    Auth = 22242,
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
pub struct Note {
    /// ID of note
    id: [u8; 64],
    /// Derived from privkey, refers to note creator
    pubkey: [u8; 64],
    /// Unix timestamp
    created_at: u32,
    /// Hardcoded to kind 1
    kind: NoteKinds,
    content: String<64>,
    sig: [u8; 128],
}

impl Note {
    /// Returns a note used for authenticating to a relay
    pub fn auth_note(privkey: &str, created_at: u32, aux_rnd: [u8; 32]) -> Self {
        let mut note = Note {
            id: [0; 64],
            pubkey: [0; 64],
            created_at,
            kind: NoteKinds::Auth,
            content: "".into(),
            sig: [0; 128],
        };
        note.set_pubkey(privkey);
        note.set_id();
        note.set_sig(privkey, &aux_rnd);
        note
    }

    /// Returns a new Note
    /// # Arguments
    ///
    /// * `content` - data to be included in "content" field
    /// * `aux_rnd` - MUST be unique for each note created to avoid leaking private key
    /// * `created_at` - Unix timestamp for note creation time
    ///
    pub fn new(privkey: &str, content: &str, created_at: u32, aux_rnd: [u8; 32]) -> Self {
        let mut note = Note {
            id: [0; 64],
            pubkey: [0; 64],
            created_at,
            kind: NoteKinds::ShortNote,
            content: content.into(),
            sig: [0; 128],
        };
        note.set_pubkey(privkey);
        note.set_id();
        note.set_sig(privkey, &aux_rnd);
        note
    }

    fn timestamp_bytes(&self) -> [u8; 10] {
        // thanks to ChatGPT for the below code :)
        let mut buffer = [0_u8; 10];
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
            hash_str[count] = *bs;
            count += 1;
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
        br#"[],""#.iter().for_each(|bs| {
            hash_str[count] = *bs;
            count += 1;
        });
        self.content.as_bytes().iter().for_each(|bs| {
            hash_str[count] = *bs;
            count += 1;
        });
        br#""]"#.iter().for_each(|bs| {
            hash_str[count] = *bs;
            count += 1;
        });
        (hash_str, count)
    }

    fn set_pubkey(&mut self, privkey: &str) {
        let mut buf = [AlignedType::zeroed(); 64];
        let sig_obj = secp256k1::Secp256k1::preallocated_new(&mut buf).unwrap();
        let key_pair = KeyPair::from_seckey_str(&sig_obj, privkey).expect("priv key failed");
        let pubkey = &key_pair.public_key().serialize()[1..33];
        base16ct::lower::encode(pubkey, &mut self.pubkey).expect("encode error");
    }

    fn set_id(&mut self) {
        let (remaining, len) = self.to_hash_str();
        let mut hasher = Sha256::new();
        hasher.update(&remaining[..len]);
        let results = hasher.finalize();
        base16ct::lower::encode(&results, &mut self.id).expect("encode error");
    }

    // todo: return signing error
    fn set_sig(&mut self, privkey: &str, aux_rnd: &[u8; 32]) {
        // figure out what size we need and why
        let mut buf = [AlignedType::zeroed(); 64];
        let sig_obj = secp256k1::Secp256k1::preallocated_new(&mut buf).unwrap();

        let mut msg = [0_u8; 32];
        base16ct::lower::decode(&self.id, &mut msg).expect("encode error");

        let message = Message::from_slice(&msg).expect("32 bytes");
        let key_pair = KeyPair::from_seckey_str(&sig_obj, privkey).expect("priv key failed");
        let sig = sig_obj.sign_schnorr_with_aux_rand(&message, &key_pair, aux_rnd);
        base16ct::lower::encode(sig.as_ref(), &mut self.sig).expect("encode error");
    }

    fn to_json(&self) -> ([u8; 1200], usize) {
        let mut output = [0; 1200];
        let mut count = 0;
        br#"{"content":""#.iter().for_each(|bs| {
            output[count] = *bs;
            count += 1;
        });
        self.content.as_bytes().iter().for_each(|bs| {
            output[count] = *bs;
            count += 1;
        });
        br#"","created_at":"#.iter().for_each(|bs| {
            output[count] = *bs;
            count += 1;
        });
        self.timestamp_bytes().iter().for_each(|bs| {
            output[count] = *bs;
            count += 1;
        });
        br#","id":""#.iter().for_each(|bs| {
            output[count] = *bs;
            count += 1;
        });
        self.id.iter().for_each(|bs| {
            output[count] = *bs;
            count += 1;
        });
        br#"","kind":"#.iter().for_each(|bs| {
            output[count] = *bs;
            count += 1;
        });
        self.kind.serialize().iter().for_each(|bs| {
            if *bs != 255 {
                output[count] = *bs;
                count += 1;
            }
        });
        br#","pubkey":""#.iter().for_each(|bs| {
            output[count] = *bs;
            count += 1;
        });
        self.pubkey.iter().for_each(|bs| {
            output[count] = *bs;
            count += 1;
        });
        br#"","sig":""#.iter().for_each(|bs| {
            output[count] = *bs;
            count += 1;
        });
        self.sig.iter().for_each(|bs| {
            output[count] = *bs;
            count += 1;
        });
        br#"","tags":[]}"#.iter().for_each(|bs| {
            output[count] = *bs;
            count += 1;
        });

        (output, count)
    }

    /// Serializes the note so it can sent to a relay
    /// # Returns
    ///
    /// * `[u8; 1000]` - lower case hex encoded byte array of note, to be sent to relay
    /// * `usize` - length of the buffer used
    pub fn serialize_to_relay(&self) -> ([u8; 1000], usize) {
        let mut output = [0; 1000];
        let mut count = 0;
        // fill in output
        br#"["EVENT","#.iter().for_each(|bs| {
            output[count] = *bs;
            count += 1;
        });
        let json = self.to_json();
        for i in 0..json.1 {
            output[count] = json.0[i];
            count += 1;
        }
        output[count] = 93; // 93 == ] character
        count += 1;

        (output, count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PRIVKEY: &str = "a5084b35a58e3e1a26f5efb46cb9dbada73191526aa6d11bccb590cbeb2d8fa3";

    #[test]
    fn pubkey_test() {
        let note = Note::new(PRIVKEY, "esptest", 1686880020, [0; 32]);
        let pubkey = note.pubkey;
        assert_eq!(
            pubkey,
            *b"098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf"
        );
    }

    #[test]
    fn id_test() {
        let note = Note::new(PRIVKEY, "esptest", 1686880020, [0; 32]);
        let id = note.id;
        assert_eq!(
            id,
            *b"b515da91ac5df638fae0a6e658e03acc1dda6152dd2107d02d5702ccfcf927e8"
        );
    }

    #[test]
    fn timestamp_test() {
        let note = Note::new(PRIVKEY, "esptest", 1686880020, [0; 32]);
        let hash_correct = *b"1686880020";
        let ts = note.timestamp_bytes();
        assert_eq!(ts, hash_correct);
    }

    #[test]
    fn hashstr_test() {
        let note = Note::new(PRIVKEY, "esptest", 1686880020, [0; 32]);
        let hash_correct = br#"[0,"098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf",1686880020,1,[],"esptest"]"#;
        let (hashed, len) = note.to_hash_str();
        let hashed = &hashed[..len];
        assert_eq!(hashed, hash_correct);
    }

    #[test]
    fn json_test() {
        let output =  br#"{"content":"esptest","created_at":1686880020,"id":"b515da91ac5df638fae0a6e658e03acc1dda6152dd2107d02d5702ccfcf927e8","kind":1,"pubkey":"098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf","sig":"89a4f1ad4b65371e6c3167ea8cb13e73cf64dd5ee71224b1edd8c32ad817af2312202cadb2f22f35d599793e8b1c66b3979d4030f1e7a252098da4a4e0c48fab","tags":[]}"#;
        let note = Note::new(PRIVKEY, "esptest", 1686880020, [0; 32]);
        let (msg, len) = note.to_json();
        assert_eq!(&msg[0..len], output);
    }

    #[test]
    fn serialize_to_relay_test() {
        let output =  br#"["EVENT",{"content":"esptest","created_at":1686880020,"id":"b515da91ac5df638fae0a6e658e03acc1dda6152dd2107d02d5702ccfcf927e8","kind":1,"pubkey":"098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf","sig":"89a4f1ad4b65371e6c3167ea8cb13e73cf64dd5ee71224b1edd8c32ad817af2312202cadb2f22f35d599793e8b1c66b3979d4030f1e7a252098da4a4e0c48fab","tags":[]}]"#;
        let note = Note::new(PRIVKEY, "esptest", 1686880020, [0; 32]);
        let (msg, len) = note.serialize_to_relay();
        assert_eq!(&msg[0..len], output);
    }
}
