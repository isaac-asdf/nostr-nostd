#![no_std]
use heapless::String;
use secp256k1::{self, ffi::types::AlignedType, KeyPair, Message};
use sha2::{Digest, Sha256};

pub enum NoteKinds {
    ShortNote,
}

impl NoteKinds {
    pub fn to_bytes(&self) -> [u8; 1] {
        match self {
            Self::ShortNote => *b"1",
        }
    }
}

pub struct Note {
    id: [u8; 64],
    pubkey: [u8; 64],
    created_at: [u8; 10],
    kind: NoteKinds,
    content: String<64>,
    sig: [u8; 128],
}

impl Note {
    pub fn new(privkey: &str, content: &str) -> Self {
        let mut note = Note {
            id: [0; 64],
            pubkey: *b"098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf",
            created_at: *b"1686880020",
            kind: NoteKinds::ShortNote,
            content: content.into(),
            sig: [0; 128],
        };
        note.set_id();
        note.set_sig(privkey);
        note
    }

    fn to_hash_str(&self) -> [u8; 1536] {
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
        self.created_at.iter().for_each(|bs| {
            hash_str[count] = *bs;
            count += 1;
        });
        b",".iter().for_each(|bs| {
            hash_str[count] = *bs;
            count += 1;
        });
        self.kind.to_bytes().iter().for_each(|bs| {
            hash_str[count] = *bs;
            count += 1;
        });
        count += 1;
        b",".iter().for_each(|bs| {
            hash_str[count] = *bs;
            count += 1;
        });
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
        hash_str
    }

    fn set_id(&mut self) {
        let remaining = self.to_hash_str();
        let to_print = unsafe { core::str::from_utf8_unchecked(&remaining[..remaining.len() - 1]) };
        // Finish can be called as many times as desired to get mutliple copies of the
        // output.
        let mut hasher = Sha256::new();
        hasher.update(to_print);
        let results = hasher.finalize();
        base16ct::lower::encode(&results, &mut self.id).expect("encode error");
    }

    // todo: return signing error
    fn set_sig(&mut self, privkey: &str) {
        // figure out what size we need and why
        let mut buf = [AlignedType::zeroed(); 500];
        let sig_obj = secp256k1::Secp256k1::preallocated_new(&mut buf).unwrap();

        let message = Message::from_slice(&self.id[0..32]).expect("32 bytes");
        let key_pair = KeyPair::from_seckey_str(&sig_obj, privkey).expect("priv key failed");
        let sig = sig_obj.sign_schnorr_no_aux_rand(&message, &key_pair);
        base16ct::lower::encode(sig.as_ref(), &mut self.sig).expect("encode error");
    }

    fn to_json(&self) -> [u8; 1200] {
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
        self.created_at.iter().for_each(|bs| {
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
        self.kind.to_bytes().iter().for_each(|bs| {
            output[count] = *bs;
            count += 1;
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

        output
    }

    pub fn to_relay(&self) -> [u8; 1535] {
        let mut output = [0; 1535];
        let mut count = 0;
        // fill in output
        br#"["EVENT","#.iter().for_each(|bs| {
            output[count] = *bs;
            count += 1;
        });
        self.to_json().iter().for_each(|bs| {
            output[count] = *bs;
            count += 1;
        });
        br#"]"#.iter().for_each(|bs| {
            output[count] = *bs;
            count += 1;
        });

        output
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {
        assert!(true);
    }
}
