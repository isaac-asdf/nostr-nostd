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
        self.created_at.iter().for_each(|bs| {
            hash_str[count] = *bs;
            count += 1;
        });
        hash_str[count] = 44; // 44 = ,
        count += 1;
        self.kind.to_bytes().iter().for_each(|bs| {
            hash_str[count] = *bs;
            count += 1;
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

    fn set_id(&mut self) {
        let (remaining, len) = self.to_hash_str();
        // let to_print = unsafe { core::str::from_utf8_unchecked(&remaining[..len]) };
        // Finish can be called as many times as desired to get mutliple copies of the
        // output.
        let mut hasher = Sha256::new();
        hasher.update(&remaining[..len]);
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

        (output, count)
    }

    pub fn to_relay(&self) -> ([u8; 1000], usize) {
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
    fn id_test() {
        let note = Note::new(PRIVKEY, "esptest");
        let id = note.id;
        assert_eq!(
            id,
            *b"b515da91ac5df638fae0a6e658e03acc1dda6152dd2107d02d5702ccfcf927e8"
        );
    }

    #[test]
    fn hashstr_test() {
        let note = Note::new(PRIVKEY, "esptest");
        let hash_correct = br#"[0,"098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf",1686880020,1,[],"esptest"]"#;
        let (hashed, len) = note.to_hash_str();
        let hashed = &hashed[..len];
        assert_eq!(hashed, hash_correct);
    }

    // #[test]
    // fn sig_test() {
    //     let note = Note::new(PRIVKEY, "esptest");
    //     let sig = b"eca27038afc8b1946acfcb3ace9ef4885b15b008507c0e84ea782b3dc222b8f9f1ebfd10c67a57d750315afaef8a77e93cc00836e29d6f662482fb43a93c14b4";
    //     assert_eq!(note.sig, *sig);
    // }

    // #[test]
    // fn to_relay_test() {
    //     let output =  br#"["EVENT",{"content":"esptest","created_at":1686880020,"id":"1a892186182fc21b33dab71c62b9aeab2df926b905db7e10e671b65d78e6a019","kind":1,"pubkey":"098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf","sig":"eca27038afc8b1946acfcb3ace9ef4885b15b008507c0e84ea782b3dc222b8f9f1ebfd10c67a57d750315afaef8a77e93cc00836e29d6f662482fb43a93c14b4","tags":[]}]"#;
    //     let note = Note::new(PRIVKEY, "esptest");
    //     let (msg, len) = note.to_relay();
    //     assert_eq!(&msg[0..len], output);
    // }
}
