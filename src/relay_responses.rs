use crate::errors::ResponseErrors;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth() {
        let msg = r#"["AUTH""#;
    }
}
