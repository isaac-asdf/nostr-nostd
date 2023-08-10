#[derive(PartialEq, Debug)]
pub enum Error {
    InvalidPubkey,
    InvalidPrivkey,
    InternalPubkeyError,
    InternalSigningError,
    TagNameTooLong,
    UnknownKind,
    InvalidType,
    TypeNotAccepted,
    MalformedContent,
    ContentOverflow,
    EventNotValid,
    EventMissingField,
    TooManyTags,
    InternalError,
}
