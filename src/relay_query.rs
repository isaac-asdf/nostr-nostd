//! Build queries to get events from relays
//!
//! ["REQ", <subscription_id>, <filters JSON>...]
//! where <subscription_id> is an arbitrary, non-empty string of max length 64 chars
//!
//! generic query looks like:
//! {
//!  "ids":
//!  "authors":
//!  "kinds":
//!  "#e":
//!  "#p":
//!  "since":
//!  "until":
//!  "limit":
//!}
//!

use heapless::Vec;
use secp256k1::{ffi::types::AlignedType, KeyPair};

use crate::errors;

const QUERY_VEC_LEN: usize = 5;
pub struct Query {
    /// a list of event ids or prefixes
    pub ids: Vec<[u8; 32], QUERY_VEC_LEN>,
    /// a list of pubkeys or prefixes, the pubkey of an event must be one of these
    pub authors: Vec<[u8; 32], QUERY_VEC_LEN>,
    /// a list of a kind numbers
    pub kinds: Vec<u16, QUERY_VEC_LEN>,
    /// a list of event ids that are referenced in an "e" tag
    pub ref_events: Vec<[u8; 32], QUERY_VEC_LEN>,
    /// a list of pubkeys that are referenced in a "p" tag
    pub ref_pks: Vec<[u8; 32], QUERY_VEC_LEN>,
    /// an integer unix timestamp in seconds, events must be newer than this to pass
    pub since: Option<u32>,
    /// an integer unix timestamp in seconds, events must be older than this to pass
    pub until: Option<u32>,
    /// maximum number of events to be returned in the initial query
    pub limit: Option<u32>,
}

impl Query {
    #[inline]
    pub fn new() -> Self {
        Query {
            ids: Vec::new(),
            authors: Vec::new(),
            kinds: Vec::new(),
            ref_events: Vec::new(),
            ref_pks: Vec::new(),
            since: None,
            until: None,
            limit: None,
        }
    }

    #[inline]
    pub fn get_my_dms(&mut self, privkey: &str) -> Result<(), errors::Error> {
        let mut buf = [AlignedType::zeroed(); 64];
        let sig_obj = secp256k1::Secp256k1::preallocated_new(&mut buf)
            .map_err(|_| errors::Error::Secp256k1Error)?;
        let key_pair: KeyPair = KeyPair::from_seckey_str(&sig_obj, privkey)
            .map_err(|_| errors::Error::InvalidPrivkey)?;
        let pubkey = key_pair.x_only_public_key().0;
        let pubkey = &pubkey.serialize();
        let mut msg = [0_u8; 32];
        base16ct::lower::encode(pubkey, &mut msg).map_err(|_| errors::Error::EncodeError)?;
        self.ref_pks
            .push(msg)
            .map_err(|_| errors::Error::QueryBuilderOverflow)?;
        Ok(())
    }

    fn to_json(self) -> Result<[u8; 1000], errors::Error> {
        // todo
        Ok([0; 1000])
    }

    /// Serializes the note for sending to relay
    #[inline]
    pub fn serialize_to_relay(self) -> Result<Vec<u8, 1000>, errors::Error> {
        let mut output: Vec<u8, 1000> = Vec::new();
        // fill in output
        r#"["REQ","#.as_bytes().iter().try_for_each(|bs| {
            output
                .push(*bs)
                .map_err(|_| errors::Error::QueryBuilderOverflow)?;
            Ok(())
        })?;
        let json = self.to_json()?;
        json.iter().try_for_each(|bs| {
            output
                .push(*bs)
                .map_err(|_| errors::Error::QueryBuilderOverflow)?;
            Ok(())
        })?;
        output
            .push(93)
            .map_err(|_| errors::Error::QueryBuilderOverflow)?;
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PRIVKEY: &str = "a5084b35a58e3e1a26f5efb46cb9dbada73191526aa6d11bccb590cbeb2d8fa3";

    #[test]
    fn test_dms() {
        let mut query = Query::new();
        query.get_my_dms(PRIVKEY).unwrap();
        let query = query.serialize_to_relay().unwrap();
        let expected = br#"["REQ",]"#;
        assert_eq!(query, expected);
    }
}
