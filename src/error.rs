use std::error;
use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    Foo,
    CommitsDontAdd,
    InvalidCredential,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let error_message = match self {
            Error::Foo => "foo",
            Error::CommitsDontAdd => "Commits don't add up properly",
            Error::InvalidCredential => "Credential is invalid",
        };
        write!(f, "{}", error_message)
    }
}

#[test]
fn test_error() {
    fn foo() -> Result<u32> {
        Err(Error::Foo)
    }

    let x = foo();
    assert!(x.is_err());
    assert_eq!(x.err(), Some(Error::Foo));
}
