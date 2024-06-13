use crate::kerberos_string::KerberosString;
use crate::kerberos_time::KerberosTime;
use crate::microseconds::Microseconds;
use crate::principal_name::PrincipalName;
use crate::realm::Realm;
use der::asn1::OctetString;
use der::{Decode, DecodeValue, EncodeValue, FixedTag, Sequence, Tag, TagNumber};

/// ```text
/// KRB-ERROR       ::= [APPLICATION 30] SEQUENCE {
///            pvno            [0] INTEGER (5),
///            msg-type        [1] INTEGER (30),
///            ctime           [2] KerberosTime OPTIONAL,
///            cusec           [3] Microseconds OPTIONAL,
///            stime           [4] KerberosTime,
///            susec           [5] Microseconds,
///            error-code      [6] Int32,
///            crealm          [7] Realm OPTIONAL,
///            cname           [8] PrincipalName OPTIONAL,
///            realm           [9] Realm -- service realm --,
///            sname           [10] PrincipalName -- service name --,
///            e-text          [11] KerberosString OPTIONAL,
///            e-data          [12] OCTET STRING OPTIONAL
///    }
/// ```
#[derive(Debug, Eq, PartialEq, Sequence)]
pub(crate) struct KrbError {
    #[asn1(context_specific = "0")]
    pub(crate) pvno: u8,
    #[asn1(context_specific = "1")]
    pub(crate) msg_type: u8,
    #[asn1(context_specific = "2", optional = "true")]
    pub(crate) ctime: Option<KerberosTime>,
    #[asn1(context_specific = "3", optional = "true")]
    pub(crate) cusec: Option<Microseconds>,
    #[asn1(context_specific = "4")]
    pub(crate) stime: KerberosTime,
    #[asn1(context_specific = "5")]
    pub(crate) susec: Microseconds,
    #[asn1(context_specific = "6")]
    pub(crate) error_code: i32,
    #[asn1(context_specific = "7", optional = "true")]
    pub(crate) crealm: Option<Realm>,
    #[asn1(context_specific = "8", optional = "true")]
    pub(crate) cname: Option<PrincipalName>,
    #[asn1(context_specific = "9")]
    pub(crate) service_realm: Realm,
    #[asn1(context_specific = "10")]
    pub(crate) service_name: PrincipalName,
    #[asn1(context_specific = "11", optional = "true")]
    pub(crate) error_text: Option<KerberosString>,
    #[asn1(context_specific = "12", optional = "true")]
    pub(crate) error_data: Option<OctetString>,
}

#[derive(Debug, Eq, PartialEq)]
struct TaggedKrbError(KrbError);

//impl<'a> ::der::Decode<'a> for KrbError {
//    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
//        let tag: der::Tag = decoder.decode()?;
//        let _len: der::Length = decoder.decode()?;
//
//        match tag {
//            Tag::Application {
//                constructed: true,
//                number: TagNumber::N30,
//            } => {
//                let e: KrbError = decoder.decode()?;
//                Ok(e)
//            }
//            _ => Err(der::Error::from(der::ErrorKind::TagUnexpected {
//                expected: None,
//                actual: tag,
//            })),
//        }
//    }
//}

impl FixedTag for TaggedKrbError {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::N30,
    };
}

impl<'a> DecodeValue<'a> for TaggedKrbError {
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, _header: der::Header) -> der::Result<Self> {
        let e: KrbError = KrbError::decode(reader)?;
        Ok(Self(e))
    }
}

impl<'a> EncodeValue for TaggedKrbError {
    fn value_len(&self) -> der::Result<der::Length> {
        KrbError::value_len(&self.0)
    }
    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        KrbError::encode_value(&self.0, encoder)
    }
}

#[cfg(test)]
mod tests {
    use crate::kerberos_time::KerberosTime;
    use crate::krb_error::TaggedKrbError;
    use crate::constants::{KrbMessageType, KrbErrorCode};
    use der::DateTime;
    use der::Decode;

    #[test]
    fn krb_err_response_too_big() {
        let blob = "7e5a3058a003020105a10302011ea411180f32303234303631323131343830355aa505020301dc66a603020134a90c1b0a41464f524553542e4144aa1f301da003020102a11630141b066b72627467741b0a41464f524553542e4144";
        let blob = hex::decode(blob).expect("");
        let e = TaggedKrbError::from_der(&blob).expect("Failed to decode");

        assert_eq!(e.0.pvno, 5);
        assert_eq!(e.0.msg_type, KrbMessageType::KrbError.into());
        assert_eq!(
            e.0.stime,
            KerberosTime::from_date_time(
                DateTime::new(2024, 06, 12, 11, 48, 05).expect("Failed to build datetime")
            )
        );
        assert_eq!(e.0.susec, 121958);
        assert_eq!(e.0.error_code, KrbErrorCode::KrbErrResponseTooBig.into());
        assert_eq!(e.0.service_realm.0.as_str(), "AFOREST.AD");
        assert_eq!(e.0.service_name.name_type, 2);
        assert_eq!(e.0.service_name.name_string[0].0.as_str(), "krbtgt");
        assert_eq!(e.0.service_name.name_string[1].0.as_str(), "AFOREST.AD");
    }

    #[test]
    fn krb_err_preauth_required() {}
}
