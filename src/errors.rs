#[derive(PartialEq, Debug)]
pub enum Error {
    UnknownKind,
    InvalidType,
    TypeNotAccepted,
    MalformedContent,
    ContentOverflow,
    EventNotValid,
    EventMissingField,
    TooManyTags,
}
