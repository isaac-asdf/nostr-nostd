#[derive(PartialEq, Debug)]
pub enum Error {
    InvalidType,
    TypeNotAccepted,
    MalformedContent,
    ContentOverflow,
    EventNotValid,
}
