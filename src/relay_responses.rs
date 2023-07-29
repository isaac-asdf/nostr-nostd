use heapless::String;

use crate::errors::ResponseErrors;
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
struct AuthMessage {
    challenge_string: String<64>,
}

#[derive(Debug)]
struct CountMessage {
    subscription_id: [u8; 64],
    count: u32,
}

#[derive(Debug)]
struct EoseMessage {
    subscription_id: [u8; 64],
}

#[derive(Debug)]
struct EventMessage {
    subscription_id: [u8; 64],
    event_json: [u8; 1000],
}

#[derive(Debug)]
struct NoticeMessage {
    message: String<180>,
}
#[derive(Debug)]
struct OkMessage {
    event_id: [u8; 64],
    accepted: bool,
    info: String<180>,
}

impl TryFrom<&str> for ResponseTypes {
    type Error = ResponseErrors;
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
            Err(ResponseErrors::InvalidType)
        }
    }
}

impl TryFrom<&str> for AuthMessage {
    type Error = ResponseErrors;
    fn try_from(value: &str) -> Result<AuthMessage, Self::Error> {
        let msg_type = ResponseTypes::try_from(value)?;
        if msg_type != ResponseTypes::Auth {
            Err(ResponseErrors::TypeNotAccepted)
        } else {
            let start_index = AUTH_STR.len();
            let end_index = value.len() - 2; // Exclude the trailing '"]'

            // Extract the challenge string and create an AuthMessage
            let challenge_string = &value[start_index..end_index];
            Ok(AuthMessage {
                challenge_string: challenge_string.into(),
            })
        }
    }
}

impl TryFrom<&str> for CountMessage {
    type Error = ResponseErrors;
    fn try_from(value: &str) -> Result<CountMessage, Self::Error> {
        let msg_type = ResponseTypes::try_from(value)?;
        if msg_type != ResponseTypes::Count {
            Err(ResponseErrors::TypeNotAccepted)
        } else {
            // Implement parsing logic for CountMessage
            // ...
            unimplemented!()
        }
    }
}

impl TryFrom<&str> for EoseMessage {
    type Error = ResponseErrors;
    fn try_from(value: &str) -> Result<EoseMessage, Self::Error> {
        let msg_type = ResponseTypes::try_from(value)?;
        if msg_type != ResponseTypes::Eose {
            Err(ResponseErrors::TypeNotAccepted)
        } else {
            // Implement parsing logic for EoseMessage
            // ...
            unimplemented!()
        }
    }
}

impl TryFrom<&str> for EventMessage {
    type Error = ResponseErrors;
    fn try_from(value: &str) -> Result<EventMessage, Self::Error> {
        let msg_type = ResponseTypes::try_from(value)?;
        if msg_type != ResponseTypes::Event {
            Err(ResponseErrors::TypeNotAccepted)
        } else {
            // Implement parsing logic for EventMessage
            // ...
            unimplemented!()
        }
    }
}

impl TryFrom<&str> for NoticeMessage {
    type Error = ResponseErrors;
    fn try_from(value: &str) -> Result<NoticeMessage, Self::Error> {
        let msg_type = ResponseTypes::try_from(value)?;
        if msg_type != ResponseTypes::Notice {
            Err(ResponseErrors::TypeNotAccepted)
        } else {
            // Implement parsing logic for NoticeMessage
            // ...
            unimplemented!()
        }
    }
}

impl TryFrom<&str> for OkMessage {
    type Error = ResponseErrors;
    fn try_from(value: &str) -> Result<OkMessage, Self::Error> {
        let msg_type = ResponseTypes::try_from(value)?;
        if msg_type != ResponseTypes::Ok {
            Err(ResponseErrors::TypeNotAccepted)
        } else {
            // Implement parsing logic for OkMessage
            // ...
            unimplemented!()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const AUTH_MSG: &str = r#"["AUTH", "encrypt me"]"#;
    const COUNT_MSG: &str = r#"["COUNT", "b515da91ac5df638fae0a6e658e03acc1dda6152dd2107d02d5702ccfcf927e8",{"count": 5}]]"#;
    const EOSE_MSG: &str =
        r#"["EOSE", "b515da91ac5df638fae0a6e658e03acc1dda6152dd2107d02d5702ccfcf927e8"]"#;
    const EVENT_MSG: &str = r#"["EVENT", {"content":"esptest","created_at":1686880020,"id":"b515da91ac5df638fae0a6e658e03acc1dda6152dd2107d02d5702ccfcf927e8","kind":1,"pubkey":"098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf","sig":"89a4f1ad4b65371e6c3167ea8cb13e73cf64dd5ee71224b1edd8c32ad817af2312202cadb2f22f35d599793e8b1c66b3979d4030f1e7a252098da4a4e0c48fab","tags":[]}]"#;
    const NOTICE_MSG: &str = r#"["NOTICE", "restricted: we can't serve DMs to unauthenticated users, does your client implement NIP-42?"]"#;
    const OK_MSG: &str = r#"["OK", "b515da91ac5df638fae0a6e658e03acc1dda6152dd2107d02d5702ccfcf927e8", false, "duplicate event"]"#;

    #[test]
    fn test_auth() {
        let auth_type = ResponseTypes::try_from(AUTH_MSG);
        let auth_msg = AuthMessage::try_from(AUTH_MSG).unwrap();
        let expected_msg = "encrypt me";
        let expected_msg = AuthMessage {
            challenge_string: expected_msg.into(),
        };
        assert_eq!(Ok(ResponseTypes::Auth), auth_type);
        assert_eq!(auth_msg, expected_msg);
    }

    #[test]
    fn test_get_message() {
        let message = ResponseTypes::try_from(AUTH_MSG);
        if let Ok(msg) = message {
            match msg {
                ResponseTypes::Auth => todo!(),
                ResponseTypes::Count => todo!(),
                ResponseTypes::Eose => todo!(),
                ResponseTypes::Event => todo!(),
                ResponseTypes::Notice => todo!(),
                ResponseTypes::Ok => todo!(),
            }
        }
    }
}
