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

trait MessageData {
    type Message: IsMessage;
    fn get_message(self) -> Self::Message;
}
trait IsMessage {}

#[derive(Debug)]
struct AuthMessage {
    challenge_string: String<64>,
}
impl IsMessage for AuthMessage {}
impl MessageData for AuthMessage {
    type Message = AuthMessage;

    fn get_message(self) -> Self::Message {
        todo!()
    }
}

impl TryFrom<&str> for AuthMessage {
    type Error = ResponseErrors;
    fn try_from(value: &str) -> Result<AuthMessage, Self::Error> {
        Ok(AuthMessage {
            challenge_string: String::new(),
        })
    }
}

#[derive(Debug)]
struct CountMessage {
    subscription_id: [u8; 64],
    count: u32,
}
impl IsMessage for CountMessage {}
impl MessageData for CountMessage {
    type Message = CountMessage;
    fn get_message(self) -> Self::Message {
        todo!()
    }
}

#[derive(Debug)]
struct EoseMessage {
    subscription_id: [u8; 64],
}
impl IsMessage for EoseMessage {}
impl MessageData for EoseMessage {
    type Message = EoseMessage;
    fn get_message(self) -> Self::Message {
        todo!()
    }
}

#[derive(Debug)]
struct EventMessage {
    subscription_id: [u8; 64],
    event_json: [u8; 1000],
}
impl IsMessage for EventMessage {}
impl MessageData for EventMessage {
    type Message = EventMessage;
    fn get_message(self) -> Self::Message {
        todo!()
    }
}

#[derive(Debug)]
struct NoticeMessage {
    message: String<180>,
}
impl IsMessage for NoticeMessage {}
impl MessageData for NoticeMessage {
    type Message = NoticeMessage;
    fn get_message(self) -> Self::Message {
        todo!()
    }
}

#[derive(Debug)]
struct OkMessage {
    event_id: [u8; 64],
    accepted: bool,
    info: String<180>,
}
impl IsMessage for OkMessage {}
impl MessageData for OkMessage {
    type Message = OkMessage;
    fn get_message(self) -> Self::Message {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth() {
        let msg = r#"["AUTH,"encrypt me"]"#;
        assert_eq!(Ok(ResponseTypes::Auth), ResponseTypes::try_from(msg));
    }
}
