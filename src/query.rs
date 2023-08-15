//! Build queries to get events from relays
//!
//! - where `subscription_id` is an arbitrary, non-empty string of max length 64 chars
//!
//! # Example
//! ```
//! use nostr_nostd::query::Query;
//!     let mut query = Query::new();
//! query
//!     .authors
//!     .push(*b"098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf")
//!     .unwrap();
//! let msg = query.serialize_to_relay("test_subscription_1").unwrap();
//! // can send msg to relay, and event will be returned as a list of: ["EVENT","test_subscription_1",{event_1_json}],etc...
//! ```

use heapless::Vec;
use secp256k1::{ffi::types::AlignedType, KeyPair};

use crate::{errors, utils::to_decimal_str, NoteKinds};

const QUERY_VEC_LEN: usize = 5;

/// Get a `CLOSE` message to send to the relay to end a previously started subscription
pub fn close_subscription(id: &str) -> Vec<u8, 100> {
    let mut output: Vec<u8, 100> = Vec::new();
    br#"["CLOSE",""#.iter().for_each(|b| output.push(*b).unwrap());
    id.chars().for_each(|b| output.push(b as u8).unwrap());
    br#""]"#.iter().for_each(|b| output.push(*b).unwrap());
    output
}
pub struct Query {
    /// a list of event ids or prefixes
    pub ids: Vec<[u8; 64], QUERY_VEC_LEN>,
    /// a list of pubkeys or prefixes, the pubkey of an event must be one of these
    pub authors: Vec<[u8; 64], QUERY_VEC_LEN>,
    /// a list of a kind numbers
    pub kinds: Vec<NoteKinds, QUERY_VEC_LEN>,
    /// a list of event ids that are referenced in an "e" tag
    pub ref_events: Vec<[u8; 64], QUERY_VEC_LEN>,
    /// a list of pubkeys that are referenced in a "p" tag
    pub ref_pks: Vec<[u8; 64], QUERY_VEC_LEN>,
    /// an integer unix timestamp in seconds, events must be newer than this to pass
    pub since: Option<u32>,
    /// an integer unix timestamp in seconds, events must be older than this to pass
    pub until: Option<u32>,
    /// maximum number of events to be returned in the initial query
    pub limit: Option<u32>,
}

impl Query {
    /// Creates a new query with all fields initialized empty
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

    /// Sets #p tag and kind tag to search for NIP04 messages
    #[inline]
    pub fn get_my_dms(&mut self, privkey: &str) -> Result<(), errors::Error> {
        let mut buf = [AlignedType::zeroed(); 64];
        let sig_obj = secp256k1::Secp256k1::preallocated_new(&mut buf)
            .map_err(|_| errors::Error::Secp256k1Error)?;
        let key_pair: KeyPair = KeyPair::from_seckey_str(&sig_obj, privkey)
            .map_err(|_| errors::Error::InvalidPrivkey)?;
        let pubkey = key_pair.x_only_public_key().0;
        let pubkey = &pubkey.serialize();
        let mut msg = [0_u8; 64];
        base16ct::lower::encode(pubkey, &mut msg).map_err(|_| errors::Error::EncodeError)?;
        self.ref_pks
            .push(msg)
            .map_err(|_| errors::Error::QueryBuilderOverflow)?;
        self.kinds
            .push(NoteKinds::DM)
            .map_err(|_| errors::Error::QueryBuilderOverflow)?;
        Ok(())
    }

    fn to_json(self) -> Result<Vec<u8, 1000>, errors::Error> {
        let mut json = Vec::new();
        let mut remove_inner_list_comma = false;
        let mut add_obj_comma = false;
        json.push(123).expect("impossible"); // { char
        if self.ids.len() > 0 {
            br#""id":["#.iter().try_for_each(|b| {
                json.push(*b).map_err(|_| errors::Error::ContentOverflow)?;
                Ok(())
            })?;
            add_obj_comma = true;
        }
        self.ids.iter().try_for_each(|val| {
            // 34 = " char
            json.push(34).map_err(|_| errors::Error::ContentOverflow)?;
            val.iter().try_for_each(|b| {
                json.push(*b).map_err(|_| errors::Error::ContentOverflow)?;
                Ok(())
            })?;
            json.push(34).map_err(|_| errors::Error::ContentOverflow)?;
            remove_inner_list_comma = true;
            json.push(44).map_err(|_| errors::Error::ContentOverflow)?;
            Ok(())
        })?;
        if remove_inner_list_comma {
            json.pop();
            json.push(93).map_err(|_| errors::Error::ContentOverflow)?;
            remove_inner_list_comma = false;
        }
        if self.authors.len() > 0 {
            if add_obj_comma {
                json.push(44).map_err(|_| errors::Error::ContentOverflow)?;
            }
            br#""authors":["#.iter().try_for_each(|b| {
                json.push(*b).map_err(|_| errors::Error::ContentOverflow)?;
                Ok(())
            })?;
            add_obj_comma = true;
        }
        self.authors.iter().try_for_each(|val| {
            // 34 = " char
            json.push(34).map_err(|_| errors::Error::ContentOverflow)?;
            val.iter().try_for_each(|b| {
                json.push(*b).map_err(|_| errors::Error::ContentOverflow)?;
                Ok(())
            })?;
            json.push(34).map_err(|_| errors::Error::ContentOverflow)?;
            remove_inner_list_comma = true;
            json.push(44).map_err(|_| errors::Error::ContentOverflow)?;
            Ok(())
        })?;
        if remove_inner_list_comma {
            json.pop();
            json.push(93).map_err(|_| errors::Error::ContentOverflow)?;
            remove_inner_list_comma = false;
        }
        if self.ref_pks.len() > 0 {
            if add_obj_comma {
                json.push(44).map_err(|_| errors::Error::ContentOverflow)?;
            }
            br##""#p":["##.iter().try_for_each(|b| {
                json.push(*b).map_err(|_| errors::Error::ContentOverflow)?;
                Ok(())
            })?;
            add_obj_comma = true;
        }
        self.ref_pks.iter().try_for_each(|val| {
            // 34 = " char
            json.push(34).map_err(|_| errors::Error::ContentOverflow)?;
            val.iter().try_for_each(|b| {
                json.push(*b).map_err(|_| errors::Error::ContentOverflow)?;
                Ok(())
            })?;
            json.push(34).map_err(|_| errors::Error::ContentOverflow)?;
            remove_inner_list_comma = true;
            json.push(44).map_err(|_| errors::Error::ContentOverflow)?;
            Ok(())
        })?;
        if remove_inner_list_comma {
            json.pop();
            json.push(93).map_err(|_| errors::Error::ContentOverflow)?;
            remove_inner_list_comma = false;
        }
        if self.ref_events.len() > 0 {
            if add_obj_comma {
                json.push(44).map_err(|_| errors::Error::ContentOverflow)?;
            }
            br##""#e":["##.iter().try_for_each(|b| {
                json.push(*b).map_err(|_| errors::Error::ContentOverflow)?;
                Ok(())
            })?;
            add_obj_comma = true;
        }
        self.ref_events.iter().try_for_each(|val| {
            // 34 = " char
            json.push(34).map_err(|_| errors::Error::ContentOverflow)?;
            val.iter().try_for_each(|b| {
                json.push(*b).map_err(|_| errors::Error::ContentOverflow)?;
                Ok(())
            })?;
            remove_inner_list_comma = true;
            json.push(44).map_err(|_| errors::Error::ContentOverflow)?;
            Ok(())
        })?;
        if remove_inner_list_comma {
            json.pop();
            json.push(93).map_err(|_| errors::Error::ContentOverflow)?;
            remove_inner_list_comma = false;
        }
        if self.kinds.len() > 0 {
            if add_obj_comma {
                json.push(44).map_err(|_| errors::Error::ContentOverflow)?;
            }
            br#""kinds":["#.iter().try_for_each(|b| {
                json.push(*b).map_err(|_| errors::Error::ContentOverflow)?;
                Ok(())
            })?;
            add_obj_comma = true;
        }
        self.kinds.iter().try_for_each(|kind| {
            kind.serialize().chars().try_for_each(|b| {
                json.push(b as u8)
                    .map_err(|_| errors::Error::QueryBuilderOverflow)?;
                Ok(())
            })?;
            remove_inner_list_comma = true;
            json.push(44).map_err(|_| errors::Error::ContentOverflow)?;
            Ok(())
        })?;
        if remove_inner_list_comma {
            json.pop();
            json.push(93).map_err(|_| errors::Error::ContentOverflow)?;
            // remove_inner_list_comma = false;
        }

        if let Some(since) = self.since {
            if add_obj_comma {
                json.push(44).map_err(|_| errors::Error::ContentOverflow)?;
            }
            // add since
            br#""since":"#.iter().try_for_each(|b| {
                json.push(*b).map_err(|_| errors::Error::ContentOverflow)?;
                Ok(())
            })?;
            add_obj_comma = true;
            to_decimal_str(since).chars().try_for_each(|val| {
                json.push(val as u8)
                    .map_err(|_| errors::Error::ContentOverflow)?;
                Ok(())
            })?;
        }
        if let Some(until) = self.until {
            // add until
            if add_obj_comma {
                json.push(44).map_err(|_| errors::Error::ContentOverflow)?;
            }
            br#""until":"#.iter().try_for_each(|b| {
                json.push(*b).map_err(|_| errors::Error::ContentOverflow)?;
                Ok(())
            })?;
            add_obj_comma = true;
            to_decimal_str(until).chars().try_for_each(|val| {
                json.push(val as u8)
                    .map_err(|_| errors::Error::ContentOverflow)?;
                Ok(())
            })?;
        }

        if let Some(limit) = self.limit {
            // add limit
            if add_obj_comma {
                json.push(44).map_err(|_| errors::Error::ContentOverflow)?;
            }
            br#""limit":"#.iter().try_for_each(|b| {
                json.push(*b).map_err(|_| errors::Error::ContentOverflow)?;
                Ok(())
            })?;
            // add_obj_comma = true;
            to_decimal_str(limit).chars().try_for_each(|val| {
                json.push(val as u8)
                    .map_err(|_| errors::Error::ContentOverflow)?;
                Ok(())
            })?;
        }

        json.push(125).expect("impossible"); // } char
        Ok(json)
    }

    /// Serializes the note for sending to relay.
    /// Can error if too many tags/ids/events/etc have been supplied.
    /// - `subscription_id` will be included with returned events from relay
    /// - `subscription_id` length must be <= 64 characters
    #[inline]
    pub fn serialize_to_relay(self, subscription_id: &str) -> Result<Vec<u8, 1000>, errors::Error> {
        let mut output: Vec<u8, 1000> = Vec::new();
        // fill in output
        r#"["REQ",""#.as_bytes().iter().try_for_each(|bs| {
            output
                .push(*bs)
                .map_err(|_| errors::Error::QueryBuilderOverflow)?;
            Ok(())
        })?;
        subscription_id
            .chars()
            .for_each(|c| output.push(c as u8).expect("impossible"));
        // append ", to subscription id
        output.push(34).expect("impossible");
        output.push(44).expect("impossible");
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
        query
            .get_my_dms(PRIVKEY)
            .map_err(|_| errors::Error::ContentOverflow)
            .expect("test");
        let query = query
            .serialize_to_relay("my_dms")
            .map_err(|_| errors::Error::ContentOverflow)
            .expect("test");
        let expected = br##"["REQ","my_dms",{"#p":["098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf"],"kinds":[4]}]"##;
        assert_eq!(query, expected);
    }

    #[test]
    fn test_close() {
        let sub_id = "sub_1";
        let closed = close_subscription(sub_id);
        let expected = br#"["CLOSE","sub_1"]"#;
        assert_eq!(closed, expected);
    }

    #[test]
    fn test_multiple() {
        let mut query = Query {
            ids: Vec::new(),
            authors: Vec::new(),
            kinds: Vec::new(),
            ref_events: Vec::new(),
            ref_pks: Vec::new(),
            since: Some(10_000),
            until: Some(10_001),
            limit: Some(10),
        };
        query
            .ref_pks
            .push([97; 64])
            .map_err(|_| errors::Error::ContentOverflow)
            .expect("test");
        query
            .ref_pks
            .push([98; 64])
            .map_err(|_| errors::Error::ContentOverflow)
            .expect("test");
        query
            .kinds
            .push(NoteKinds::IOT)
            .map_err(|_| errors::Error::ContentOverflow)
            .expect("test");
        query
            .kinds
            .push(NoteKinds::Regular(1005))
            .map_err(|_| errors::Error::ContentOverflow)
            .expect("test");

        let query = query
            .serialize_to_relay("subscription_1")
            .map_err(|_| errors::Error::ContentOverflow)
            .expect("test");
        let expected = br##"["REQ","subscription_1",{"#p":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"kinds":[5732,1005],"since":10000,"until":10001,"limit":10}]"##;
        assert_eq!(query, expected);
    }
}
