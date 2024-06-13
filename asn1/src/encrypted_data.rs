use der::asn1::OctetString;
use der::Sequence;

/// ```text
/// EncryptedData   ::= SEQUENCE {
///         etype   [0] Int32 -- EncryptionType --,
///         kvno    [1] UInt32 OPTIONAL,
///         cipher  [2] OCTET STRING -- ciphertext
/// }
/// ````
#[derive(Debug, Eq, PartialEq, Sequence)]
pub(crate) struct EncryptedData {
    #[asn1(context_specific = "0")]
    etype: i32,
    #[asn1(context_specific = "1")]
    kvno: u32,
    #[asn1(context_specific = "2")]
    cipher: OctetString,
}
