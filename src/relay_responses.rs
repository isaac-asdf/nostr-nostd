use heapless::String;

use crate::errors::ResponseErrors;

#[derive(PartialEq, Debug)]
enum ResponseTypes {
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
        match value {
            r#"["AUTH""# => Ok(Self::Auth),
            r#"["COUNT""# => Ok(Self::Count),
            r#"["EOSE""# => Ok(Self::Eose),
            r#"["EVENT""# => Ok(Self::Event),
            r#"["NOTICE""# => Ok(Self::Notice),
            r#"["OK""# => Ok(Self::Ok),
            _ => Err(ResponseErrors::InvalidType),
        }
    }
}

struct AuthMessage {
    challenge_string: String<64>,
}

impl TryFrom<&str> for AuthMessage {
    type Error = ResponseErrors;
    fn try_from(value: &str) -> Result<AuthMessage, Self::Error> {
        Ok(AuthMessage {
            challenge_string: String::new(),
        })
    }
}

struct CountMessage {
    subscription_id: [u8; 64],
    count: u32,
}

struct EoseMessage {
    subscription_id: [u8; 64],
}

struct EventMessage {
    subscription_id: [u8; 64],
    event_json: [u8; 1000],
}

struct NoticeMessage {
    message: String<180>,
}

struct OkMessage {
    event_id: [u8; 64],
    accepted: bool,
    info: String<180>,
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth() {
        let msg = r#"["AUTH""#;
        assert_eq!(Ok(ResponseTypes::Auth), ResponseTypes::try_from(msg));
    }
}
