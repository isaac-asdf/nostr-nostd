//! Handle messages from relays
//!
//! # Example
//! ```
//! use nostr_nostd::{Note, String, ClientMsgKinds,relay_responses};
//! use nostr_nostd::relay_responses::{AuthMessage, ResponseTypes};
//! let privkey = "a5084b35a58e3e1a26f5efb46cb9dbada73191526aa6d11bccb590cbeb2d8fa3";
//! let auth_msg_from_relay: &str = r#"["AUTH","encrypt this"]"#;
//! let msg_type = ResponseTypes::try_from(auth_msg_from_relay).unwrap();
//! let msg: AuthMessage = match msg_type {
//!     ResponseTypes::Auth => AuthMessage::try_from(auth_msg_from_relay).unwrap(),
//!     ResponseTypes::Count => panic!("handle other messages here"),
//!     ResponseTypes::Eose => panic!("handle other messages here"),
//!     ResponseTypes::Event => panic!("handle other messages here"),
//!     ResponseTypes::Notice => panic!("handle other messages here"),
//!     ResponseTypes::Ok => panic!("handle other messages here"),
//! };
//! // aux_rand should be generated from a random number generator
//! // required to keep PRIVKEY secure with Schnorr signatures
//! let aux_rand = [0; 32];
//! let note = Note::new_builder(privkey)
//!     .unwrap()
//!     .create_auth(&msg, "wss://relay.example.com")
//!     .unwrap()
//!     .build(1686880020, aux_rand)
//!     .unwrap();
//! let msg = note.serialize_to_relay(ClientMsgKinds::Auth);
//! ```
//!
use heapless::String;

use crate::{errors::Error, Note};
const CHALLENGE_STRING_SIZE: usize = 64;
const AUTH_STR: &str = r#"["AUTH","#;
const COUNT_STR: &str = r#"["COUNT","#;
const EOSE_STR: &str = r#"["EOSE","#;
const EVENT_STR: &str = r#"["EVENT","#;
const NOTICE_STR: &str = r#"["NOTICE","#;
const OK_STR: &str = r#"["OK","#;
#[derive(PartialEq, Debug)]
pub enum ResponseTypes {
    Auth,
    Count,
    Eose,
    Event,
    Notice,
    Ok,
}

#[derive(Debug, PartialEq)]
pub struct AuthMessage {
    pub challenge_string: String<CHALLENGE_STRING_SIZE>,
}

#[derive(Debug, PartialEq)]
pub struct CountMessage {
    pub subscription_id: String<64>,
    pub count: u16,
}

#[derive(Debug, PartialEq)]
pub struct EoseMessage {
    pub subscription_id: String<64>,
}

#[derive(Debug, PartialEq)]
pub struct EventMessage {
    pub subscription_id: String<64>,
    pub note: Note,
}

#[derive(Debug, PartialEq)]
pub struct NoticeMessage {
    pub message: String<180>,
}
#[derive(Debug, PartialEq)]
pub struct OkMessage {
    pub event_id: String<64>,
    pub accepted: bool,
    pub info: String<180>,
}

impl TryFrom<&str> for ResponseTypes {
    type Error = Error;
    fn try_from(value: &str) -> Result<ResponseTypes, Self::Error> {
        if value.starts_with(AUTH_STR) {
            Ok(Self::Auth)
        } else if value.starts_with(COUNT_STR) {
            Ok(Self::Count)
        } else if value.starts_with(EOSE_STR) {
            Ok(Self::Eose)
        } else if value.starts_with(EVENT_STR) {
            Ok(Self::Event)
        } else if value.starts_with(NOTICE_STR) {
            Ok(Self::Notice)
        } else if value.starts_with(OK_STR) {
            Ok(Self::Ok)
        } else {
            Err(Error::InvalidType)
        }
    }
}

impl TryFrom<&str> for AuthMessage {
    type Error = Error;
    fn try_from(value: &str) -> Result<AuthMessage, Self::Error> {
        let msg_type = ResponseTypes::try_from(value)?;
        if msg_type != ResponseTypes::Auth {
            Err(Error::TypeNotAccepted)
        } else {
            let start_index = AUTH_STR.len() + 2;
            let end_index = value.len() - 2; // Exclude the trailing '"]'

            if end_index - start_index > CHALLENGE_STRING_SIZE {
                return Err(Error::ContentOverflow);
            };

            // Extract the challenge string and create an AuthMessage
            let challenge_string = &value[start_index..end_index];
            Ok(AuthMessage {
                challenge_string: challenge_string.into(),
            })
        }
    }
}

impl TryFrom<&str> for CountMessage {
    type Error = Error;
    fn try_from(value: &str) -> Result<CountMessage, Self::Error> {
        let msg_type = ResponseTypes::try_from(value)?;
        if msg_type != ResponseTypes::Count {
            Err(Error::TypeNotAccepted)
        } else {
            let start_index = COUNT_STR.len() + 2;
            let end_index = start_index + 64; // an id is 64 characters

            if value.len() < end_index {
                return Err(Error::ContentOverflow);
            }

            // Extract the challenge string and create an AuthMessage
            let id = &value[start_index..end_index];
            let start_index = end_index + r#"", {"count": "#.len();
            let end_index = value.len() - r#"}]"#.len();
            let count_str = &value[start_index..end_index];
            let num = u16::from_str_radix(count_str, 10).map_err(|_| Error::MalformedContent)?;
            Ok(CountMessage {
                subscription_id: id.into(),
                count: num,
            })
        }
    }
}

impl TryFrom<&str> for EoseMessage {
    type Error = Error;
    fn try_from(value: &str) -> Result<EoseMessage, Self::Error> {
        let msg_type = ResponseTypes::try_from(value)?;
        if msg_type != ResponseTypes::Eose {
            Err(Error::TypeNotAccepted)
        } else {
            let start_index = EOSE_STR.len() + 2;
            let end_index = start_index + 64; // an id is 64 characters

            if value.len() < end_index {
                return Err(Error::ContentOverflow);
            }

            // Extract the challenge string and create an AuthMessage
            let id = &value[start_index..end_index];
            Ok(EoseMessage {
                subscription_id: id.into(),
            })
        }
    }
}

impl TryFrom<&str> for EventMessage {
    type Error = Error;
    fn try_from(value: &str) -> Result<EventMessage, Self::Error> {
        let msg_type = ResponseTypes::try_from(value)?;
        if msg_type != ResponseTypes::Event {
            Err(Error::TypeNotAccepted)
        } else {
            let start_index = EVENT_STR.len();
            let value = &value[start_index..];
            let subscription = value.split(",").next().ok_or(Error::EventNotValid)?;
            let subscription_id: String<64> = subscription[1..subscription.len() - 1].into();

            let end_index = value.len() - 2;
            if value.len() < end_index {
                return Err(Error::ContentOverflow);
            }
            let event_json = &value[subscription_id.len()..end_index];
            Ok(EventMessage {
                subscription_id,
                note: Note::try_from(event_json)?,
            })
        }
    }
}

impl TryFrom<&str> for NoticeMessage {
    type Error = Error;
    fn try_from(value: &str) -> Result<NoticeMessage, Self::Error> {
        let msg_type = ResponseTypes::try_from(value)?;
        if msg_type != ResponseTypes::Notice {
            Err(Error::TypeNotAccepted)
        } else {
            let start_index = COUNT_STR.len() + 3;
            let end_index = value.len() - 2;

            if value.len() < end_index {
                return Err(Error::ContentOverflow);
            }

            // Extract the challenge string and create an AuthMessage
            let msg = &value[start_index..end_index];
            Ok(NoticeMessage {
                message: msg.into(),
            })
        }
    }
}

impl TryFrom<&str> for OkMessage {
    type Error = Error;
    fn try_from(value: &str) -> Result<OkMessage, Self::Error> {
        let msg_type = ResponseTypes::try_from(value)?;
        if msg_type != ResponseTypes::Ok {
            Err(Error::TypeNotAccepted)
        } else {
            let start_index = OK_STR.len() + 2;
            let end_index = start_index + 64; // an id is 64 characters

            if value.len() < end_index {
                return Err(Error::ContentOverflow);
            }
            let id = &value[start_index..end_index];
            let start_index = end_index + 3;
            let end_index = start_index + 5;
            let true_false = &value[start_index..end_index];
            let accepted = if true_false == "false" {
                false
            } else if true_false == "true," {
                true
            } else {
                return Err(Error::MalformedContent);
            };
            let start_index = if accepted {
                end_index + 2
            } else {
                end_index + 3
            };
            let end_index = value.len() - 2;
            if value.len() < end_index {
                return Err(Error::ContentOverflow);
            }
            let info = &value[start_index..end_index];
            Ok(OkMessage {
                event_id: id.into(),
                accepted,
                info: info.into(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use heapless::Vec;

    use crate::Note;

    use super::*;
    const AUTH_MSG: &str = r#"["AUTH", "encrypt me"]"#;
    const COUNT_MSG: &str = r#"["COUNT", "b515da91ac5df638fae0a6e658e03acc1dda6152dd2107d02d5702ccfcf927e8", {"count": 5}]"#;
    const EOSE_MSG: &str =
        r#"["EOSE", "b515da91ac5df638fae0a6e658e03acc1dda6152dd2107d02d5702ccfcf927e8"]"#;
    const EVENT_MSG: &str = r#"["EVENT","sub_1", {"content":"esptest","created_at":1686880020,"id":"b515da91ac5df638fae0a6e658e03acc1dda6152dd2107d02d5702ccfcf927e8","kind":1,"pubkey":"098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf","sig":"89a4f1ad4b65371e6c3167ea8cb13e73cf64dd5ee71224b1edd8c32ad817af2312202cadb2f22f35d599793e8b1c66b3979d4030f1e7a252098da4a4e0c48fab","tags":[]}]"#;
    const NOTICE_MSG: &str = r#"["NOTICE", "restricted: we can't serve DMs to unauthenticated users, does your client implement NIP-42?"]"#;
    const OK_MSG: &str = r#"["OK", "b515da91ac5df638fae0a6e658e03acc1dda6152dd2107d02d5702ccfcf927e8", false, "duplicate event"]"#;

    #[test]
    fn test_auth() {
        let auth_type = ResponseTypes::try_from(AUTH_MSG);
        let auth_msg = AuthMessage::try_from(AUTH_MSG).expect("infallible");
        let expected_msg = "encrypt me";
        let expected_msg = AuthMessage {
            challenge_string: expected_msg.into(),
        };
        assert_eq!(Ok(ResponseTypes::Auth), auth_type);
        assert_eq!(auth_msg, expected_msg);
    }

    #[test]
    fn test_count() {
        let msg = CountMessage::try_from(COUNT_MSG).expect("infallible");
        let expected_count = CountMessage {
            subscription_id: "b515da91ac5df638fae0a6e658e03acc1dda6152dd2107d02d5702ccfcf927e8"
                .into(),
            count: 5,
        };
        assert_eq!(msg, expected_count);
    }

    #[test]
    fn test_notice() {
        let msg = NoticeMessage::try_from(NOTICE_MSG).expect("infallible");
        let expected_notice = NoticeMessage {
            message: "restricted: we can't serve DMs to unauthenticated users, does your client implement NIP-42?".into()
        };
        assert_eq!(msg, expected_notice);
    }

    #[test]
    fn test_eose() {
        let msg = EoseMessage::try_from(EOSE_MSG).expect("infallible");
        let expected_msg = EoseMessage {
            subscription_id: "b515da91ac5df638fae0a6e658e03acc1dda6152dd2107d02d5702ccfcf927e8"
                .into(),
        };
        assert_eq!(msg, expected_msg);
    }

    #[test]
    fn test_event() {
        let msg = EventMessage::try_from(EVENT_MSG).expect("infallible");
        let expected_event = Note {
            content: Some("esptest".into()),
            id: *b"b515da91ac5df638fae0a6e658e03acc1dda6152dd2107d02d5702ccfcf927e8",
            pubkey: *b"098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf",
            created_at: 1686880020,
            kind: crate::NoteKinds::ShortNote,
            tags: Vec::new(),
            sig: *b"89a4f1ad4b65371e6c3167ea8cb13e73cf64dd5ee71224b1edd8c32ad817af2312202cadb2f22f35d599793e8b1c66b3979d4030f1e7a252098da4a4e0c48fab",
        };
        let event_msg = EventMessage {
            subscription_id: "sub_1".into(),
            note: expected_event,
        };
        assert_eq!(msg, event_msg);
    }

    #[test]
    fn test_ok() {
        let msg = OkMessage::try_from(OK_MSG).expect("infallible");
        let expected_msg = OkMessage {
            event_id: "b515da91ac5df638fae0a6e658e03acc1dda6152dd2107d02d5702ccfcf927e8".into(),
            accepted: false,
            info: "duplicate event".into(),
        };
        assert_eq!(msg, expected_msg);
    }
}
