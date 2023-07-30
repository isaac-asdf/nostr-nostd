#[derive(PartialEq, Debug)]
pub enum ResponseErrors {
    InvalidType,
    TypeNotAccepted,
    MalformedContent,
    ContentOverflow,
}
