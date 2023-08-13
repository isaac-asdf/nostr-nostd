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

use crate::{errors, NoteKinds};

const QUERY_VEC_LEN: usize = 5;
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
            br#""id":["#.iter().for_each(|b| {
                json.push(*b).unwrap();
            });
            add_obj_comma = true;
        }
        self.ids.iter().for_each(|val| {
            // 34 = " char
            json.push(34).unwrap();
            val.iter().for_each(|b| {
                json.push(*b).unwrap();
            });
            json.push(34).unwrap();
            remove_inner_list_comma = true;
            json.push(44).unwrap();
        });
        if remove_inner_list_comma {
            json.pop();
            json.push(93).unwrap();
            remove_inner_list_comma = false;
        }
        if self.authors.len() > 0 {
            if add_obj_comma {
                json.push(44).unwrap();
            }
            br#""authors":["#.iter().for_each(|b| {
                json.push(*b).unwrap();
            });
            add_obj_comma = true;
        }
        self.authors.iter().for_each(|val| {
            // 34 = " char
            json.push(34).unwrap();
            val.iter().for_each(|b| {
                json.push(*b).unwrap();
            });
            json.push(34).unwrap();
            remove_inner_list_comma = true;
            json.push(44).unwrap();
        });
        if remove_inner_list_comma {
            json.pop();
            json.push(93).unwrap();
            remove_inner_list_comma = false;
        }
        if self.ref_pks.len() > 0 {
            if add_obj_comma {
                json.push(44).unwrap();
            }
            br##""#p":["##.iter().for_each(|b| {
                json.push(*b).unwrap();
            });
            add_obj_comma = true;
        }
        self.ref_pks.iter().for_each(|val| {
            // 34 = " char
            json.push(34).unwrap();
            val.iter().for_each(|b| {
                json.push(*b).unwrap();
            });
            json.push(34).unwrap();
            remove_inner_list_comma = true;
            json.push(44).unwrap();
        });
        if remove_inner_list_comma {
            json.pop();
            json.push(93).unwrap();
            remove_inner_list_comma = false;
        }
        if self.ref_events.len() > 0 {
            if add_obj_comma {
                json.push(44).unwrap();
            }
            br##""#e":["##.iter().for_each(|b| {
                json.push(*b).unwrap();
            });
            add_obj_comma = true;
        }
        self.ref_events.iter().for_each(|val| {
            // 34 = " char
            json.push(34).unwrap();
            val.iter().for_each(|b| {
                json.push(*b).unwrap();
            });
            remove_inner_list_comma = true;
            json.push(44).unwrap();
        });
        if remove_inner_list_comma {
            json.pop();
            json.push(93).unwrap();
            remove_inner_list_comma = false;
        }
        if self.kinds.len() > 0 {
            if add_obj_comma {
                json.push(44).unwrap();
            }
            br#""kinds":["#.iter().for_each(|b| {
                json.push(*b).unwrap();
            });
            add_obj_comma = true;
        }
        self.kinds.iter().try_for_each(|kind| {
            kind.serialize().chars().try_for_each(|b| {
                json.push(b as u8)
                    .map_err(|_| errors::Error::QueryBuilderOverflow)?;
                Ok(())
            })?;
            remove_inner_list_comma = true;
            json.push(44).unwrap();
            Ok(())
        })?;
        if remove_inner_list_comma {
            json.pop();
            json.push(93).unwrap();
            remove_inner_list_comma = false;
        }

        json.push(125).expect("impossible"); // } char
        Ok(json)
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
        let expected = br##"["REQ",{"#p":["098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf"],"kinds":[4]}]"##;
        assert_eq!(query, expected);
    }

    #[test]
    fn test_multiple() {
        let mut query = Query {
            ids: Vec::new(),
            authors: Vec::new(),
            kinds: Vec::new(),
            ref_events: Vec::new(),
            ref_pks: Vec::new(),
            since: None,
            until: None,
            limit: None,
        };
        query.ref_pks.push([97; 64]).unwrap();
        query.ref_pks.push([98; 64]).unwrap();
        query.kinds.push(NoteKinds::IOT).unwrap();
        query.kinds.push(NoteKinds::Regular(1005)).unwrap();

        let query = query.serialize_to_relay().unwrap();
        let expected = br##"["REQ",{"#p":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"kinds":[5732,1005]}]"##;
        assert_eq!(query, expected);
    }
}
