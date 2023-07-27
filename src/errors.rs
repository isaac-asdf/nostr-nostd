use core::fmt;

pub enum ResponseErrors {
    InvalidType,
}

impl fmt::Debug for ResponseErrors {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            errors::ResponseErrors::InvalidType => write!(f, "InvalidType"),
        }
    }
}
