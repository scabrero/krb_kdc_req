use der::asn1::GeneralizedTime;
use der::asn1::Ia5String;
use der::asn1::OctetString;
use der::flagset::{flags, FlagSet};
use der::DecodeValue;
use der::EncodeValue;
use der::FixedTag;
use der::Sequence;
use der::Tag;
use der::TagNumber;

flags! {
    /// ```text
    /// KerberosFlags   ::= BIT STRING (SIZE (32..MAX))
    ///                     -- minimum number of bits shall be sent,
    ///                     -- but no fewer than 32
    /// ````
    #[repr(u32)]
    enum KerberosFlags: u32 {
        Reserved        = 1 << 0,
        Forwardable     = 1 << 1,
        Forwarded       = 1 << 2,
        Proxiable       = 1 << 3,
        Proxy           = 1 << 4,
        AllowPostdate   = 1 << 5,
        Postdated       = 1 << 6,
        Unused7         = 1 << 7,
        Renewable       = 1 << 8,
        Unused9         = 1 << 9,
        Unused10        = 1 << 10,
        OptHardwareAuth = 1 << 11,
        Unused12        = 1 << 12,
        Unused13        = 1 << 13,
        Unused14        = 1 << 14,
        Canonicalize    = 1 << 15,
        Unused16        = 1 << 16,
        Unused17        = 1 << 17,
        Unused18        = 1 << 18,
        Unused19        = 1 << 19,
        Unused20        = 1 << 20,
        Unused21        = 1 << 21,
        Unused22        = 1 << 22,
        Unused23        = 1 << 23,
        Unused24        = 1 << 24,
        Unused25        = 1 << 25,
        // -- 26 was unused in 1510
        DisableTransitedCheck = 1 << 26,
        RenewableOk     = 1 << 27,
        EncTktInSkey    = 1 << 28,
        Unused29        = 1 << 29,
        Renew           = 1 << 30,
        Validate        = 1 << 31
    }
}

/// ```text
/// KDCOptions      ::= KerberosFlags
/// ````
type KdcOptions = FlagSet<KerberosFlags>;

/// ```text
/// KerberosString  ::= GeneralString (IA5String)
/// ````
#[derive(Debug, Eq, PartialEq)]
struct KerberosString(Ia5String);

impl FixedTag for KerberosString {
    const TAG: Tag = Tag::GeneralString;
}

impl<'a> DecodeValue<'a> for KerberosString {
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, header: der::Header) -> der::Result<Self> {
        let r: Ia5String = der::asn1::Ia5String::decode_value(reader, header)?;
        Ok(Self(r))
    }
}

impl<'a> EncodeValue for KerberosString {
    fn value_len(&self) -> der::Result<der::Length> {
        Ia5String::value_len(&self.0)
    }
    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        Ia5String::encode_value(&self.0, encoder)
    }
}

/// ```text
///   PrincipalName   ::= SEQUENCE {
///           name-type       [0] Int32,
///           name-string     [1] SEQUENCE OF KerberosString
///   }
/// ````
#[derive(Debug, Eq, PartialEq, Sequence)]
struct PrincipalName {
    #[asn1(context_specific = "0")]
    name_type: i32,
    #[asn1(context_specific = "1")]
    name_string: Vec<KerberosString>,
}

/// ```text
/// Realm           ::= KerberosString
/// ````
type Realm = KerberosString;

/// ```text
/// KerberosTime    ::= GeneralizedTime
/// ````
type KerberosTime = GeneralizedTime;

/// ```text
/// HostAddress     ::= SEQUENCE  {
///         addr-type       [0] Int32,
///         address         [1] OCTET STRING
/// }
/// ````
#[derive(Debug, Eq, PartialEq, Sequence)]
struct HostAddress {
    #[asn1(context_specific = "0")]
    addr_type: i32,
    #[asn1(context_specific = "1")]
    address: OctetString,
}

/// ```text
/// HostAddresses   ::= SEQUENCE OF HostAddress
/// ````
type HostAddresses = Vec<HostAddress>;

/// ```text
/// EncryptedData   ::= SEQUENCE {
///         etype   [0] Int32 -- EncryptionType --,
///         kvno    [1] UInt32 OPTIONAL,
///         cipher  [2] OCTET STRING -- ciphertext
/// }
/// ````
#[derive(Debug, Eq, PartialEq, Sequence)]
struct EncryptedData {
    #[asn1(context_specific = "0")]
    etype: i32,
    #[asn1(context_specific = "1")]
    kvno: u32,
    #[asn1(context_specific = "2")]
    cipher: OctetString,
}

/// ```text
/// Ticket          ::= [APPLICATION 1] SEQUENCE {
///         tkt-vno         [0] INTEGER (5),
///         realm           [1] Realm,
///         sname           [2] PrincipalName,
///         enc-part        [3] EncryptedData -- EncTicketPart
/// }
/// ````
#[derive(Debug, Eq, PartialEq, Sequence)]
struct Ticket {
    #[asn1(context_specific = "0")]
    tkt_vno: i8,
    #[asn1(context_specific = "1")]
    realm: Realm,
    #[asn1(context_specific = "2")]
    sname: PrincipalName,
    #[asn1(context_specific = "3")]
    enc_part: EncryptedData,
}

#[derive(Debug, Eq, PartialEq)]
struct TaggedTicket(Ticket);

impl FixedTag for TaggedTicket {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::N1,
    };
}

impl<'a> DecodeValue<'a> for TaggedTicket {
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, header: der::Header) -> der::Result<Self> {
        let t: Ticket = Ticket::decode_value(reader, header)?;
        Ok(Self(t))
    }
}

impl<'a> EncodeValue for TaggedTicket {
    fn value_len(&self) -> der::Result<der::Length> {
        Ticket::value_len(&self.0)
    }
    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        Ticket::encode_value(&self.0, encoder)
    }
}

/// ```text
/// PA-DATA         ::= SEQUENCE {
///         -- NOTE: first tag is [1], not [0]
///         padata-type     [1] Int32,
///         padata-value    [2] OCTET STRING -- might be encoded AP-REQ
/// }
/// ````
#[derive(Debug, Eq, PartialEq, Sequence)]
struct PaData {
    #[asn1(context_specific = "1")]
    padata_type: u32,
    #[asn1(context_specific = "2")]
    padata_value: OctetString,
}

/// ```text
/// KDC-REQ-BODY    ::= SEQUENCE {
///         kdc-options             [0] KDCOptions,
///         cname                   [1] PrincipalName OPTIONAL
///                                     -- Used only in AS-REQ --,
///         realm                   [2] Realm
///                                     -- Server's realm
///                                     -- Also client's in AS-REQ --,
///         sname                   [3] PrincipalName OPTIONAL,
///         from                    [4] KerberosTime OPTIONAL,
///         till                    [5] KerberosTime,
///         rtime                   [6] KerberosTime OPTIONAL,
///         nonce                   [7] UInt32,
///         etype                   [8] SEQUENCE OF Int32 -- EncryptionType
///                                     -- in preference order --,
///         addresses               [9] HostAddresses OPTIONAL,
///         enc-authorization-data  [10] EncryptedData OPTIONAL
///                                     -- AuthorizationData --,
///         additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
///                                         -- NOTE: not empty
/// }
/// ```
#[derive(Debug, Eq, PartialEq, Sequence)]
struct KdcReqBody {
    #[asn1(context_specific = "0")]
    kdc_options: KdcOptions,
    #[asn1(context_specific = "1", optional = "true")]
    cname: Option<PrincipalName>,
    #[asn1(context_specific = "2")]
    realm: Realm,
    #[asn1(context_specific = "3", optional = "true")]
    sname: Option<PrincipalName>,
    #[asn1(context_specific = "4", optional = "true")]
    from: Option<KerberosTime>,
    #[asn1(context_specific = "5")]
    till: KerberosTime,
    #[asn1(context_specific = "6", optional = "true")]
    rtime: Option<KerberosTime>,
    #[asn1(context_specific = "7")]
    nonce: u32,
    #[asn1(context_specific = "8")]
    etype: Vec<i32>,
    #[asn1(context_specific = "9", optional = "true")]
    addresses: Option<HostAddresses>,
    #[asn1(context_specific = "10", optional = "true")]
    enc_authorization_data: Option<EncryptedData>,
    #[asn1(context_specific = "11", optional = "true")]
    additional_tickets: Option<Vec<TaggedTicket>>,
}

/// ```text
/// KDC-REQ         ::= SEQUENCE {
///         -- NOTE: first tag is [1], not [0]
///         pvno            [1] INTEGER (5) ,
///         msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
///         padata          [3] SEQUENCE OF PA-DATA OPTIONAL
///                             -- NOTE: not empty --,
///         req-body        [4] KDC-REQ-BODY
/// }
/// ```
#[derive(Debug, Eq, PartialEq, Sequence)]
struct KdcReq {
    #[asn1(context_specific = "1")]
    pvno: u8,
    #[asn1(context_specific = "2")]
    msg_type: u8,
    #[asn1(context_specific = "3", optional = "true")]
    padata: Option<Vec<PaData>>,
    #[asn1(context_specific = "4")]
    req_body: KdcReqBody,
}

#[derive(Debug, Eq, PartialEq)]
enum KrbKdcReq {
    AsReq(KdcReq),
    TgsReq(KdcReq),
}

impl<'a> ::der::Decode<'a> for KrbKdcReq {
    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        let tag: der::Tag = decoder.decode()?;
        let _len: der::Length = decoder.decode()?;

        match tag {
            Tag::Application {
                constructed: true,
                number: TagNumber::N10,
            } => {
                let kdc_req: KdcReq = decoder.decode()?;
                Ok(KrbKdcReq::AsReq(kdc_req))
            }
            Tag::Application {
                constructed: true,
                number: TagNumber::N12,
            } => {
                let kdc_req: KdcReq = decoder.decode()?;
                Ok(KrbKdcReq::TgsReq(kdc_req))
            }
            _ => Err(der::Error::from(der::ErrorKind::TagUnexpected {
                expected: None,
                actual: tag,
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use base64::prelude::*;
    use der::{DateTime, Decode};
    use der::asn1::OctetString;
    use core::iter::zip;

    struct TestPaData {
        padata_type: u32,
        padata_value: Vec<u8>,
    }

    struct TestAsReq {
        blob: Vec<u8>,
        principal: String,
        realm: String,
        padata: Vec<TestPaData>,
        kdc_options: FlagSet<KerberosFlags>,
        from: Option<KerberosTime>,
        till: KerberosTime,
        rtime: Option<KerberosTime>,
        nonce: u32,
        etype: Vec<i32>,
        addresses: Option<Vec<(i32,OctetString)>>,
    }

    fn verify_as_req(asreq: &KdcReq, tasreq: &TestAsReq) {
        assert_eq!(asreq.pvno, 5);
        assert_eq!(asreq.msg_type, 10);

        let pa = asreq.padata.as_ref().unwrap();
        assert_eq!(pa.len(), tasreq.padata.len());
        let iter = zip(pa, &tasreq.padata);
        for (pa, tpa) in iter {
            assert_eq!(pa.padata_type, tpa.padata_type);
            assert_eq!(pa.padata_value.as_bytes(), tpa.padata_value);
        }

        let bits = asreq.req_body.kdc_options;
        assert_eq!(bits, tasreq.kdc_options);

        let ref cname = &asreq.req_body.cname.as_ref().unwrap();
        assert_eq!(cname.name_type, 1);
        assert_eq!(cname.name_string[0].0.to_string(), tasreq.principal);

        assert_eq!(asreq.req_body.realm.0.to_string(), tasreq.realm);

        let ref sname = &asreq.req_body.sname.as_ref().unwrap();
        assert_eq!(sname.name_type, 2);
        assert_eq!(sname.name_string[0].0.to_string(), "krbtgt");
        assert_eq!(sname.name_string[1].0.to_string(), tasreq.realm);

        if let Some(trtime) = tasreq.rtime {
            let rtime = asreq.req_body.rtime.expect("rtime must be there");
            assert_eq!(rtime, trtime);
        } else {
            assert!(asreq.req_body.rtime.is_none());
        }

        assert_eq!(asreq.req_body.till, tasreq.till);

        if let Some(tfrom) = tasreq.from {
            let from = asreq.req_body.from.expect("from must be there");
            assert_eq!(from, tfrom);
        } else {
            assert!(asreq.req_body.from.is_none());
        }

        assert_eq!(asreq.req_body.nonce, tasreq.nonce);
        assert_eq!(asreq.req_body.etype, tasreq.etype);

        if let Some(taddrs) = &tasreq.addresses {
            let addrs = asreq.req_body.addresses.as_ref().expect("addresses must be there");
            assert_eq!(addrs.len(), taddrs.len());

            let iter = zip(addrs, taddrs);
            for (addr, taddr) in iter {
                assert_eq!(addr.addr_type, taddr.0);
                assert_eq!(addr.address, taddr.1);
            }
        } else {
            assert!(asreq.req_body.addresses.is_none());
        }
    }

    #[test]
    fn krb_kdc_req_parse() {
        let samples: Vec<TestAsReq> = vec![
            TestAsReq {
                blob: b"aoGyMIGvoQMCAQWiAwIBCqMaMBgwCqEEAgIAlqICBAAwCqEEAgIAlaICBACkgYYwgYOgBwMFAAAAABChFDASoAMCAQGhCzAJGwd3aWxsaWFtogsbCUtLRENQLkRFVqMeMBygAwIBAqEVMBMbBmtyYnRndBsJS0tEQ1AuREVWpREYDzIwMjQwNDE3MDQxNTQ5WqcGAgR/vaeuqBowGAIBEgIBEQIBFAIBEwIBEAIBFwIBGQIBGg==".to_vec(),
                principal: "william".to_string(),
                realm: "KKDCP.DEV".to_string(),
                padata: vec![
                    TestPaData {
                        padata_type: 150,
                        padata_value: vec![],
                    },
                    TestPaData {
                        padata_type: 149,
                        padata_value: vec![],
                    }
                ],
                kdc_options: KerberosFlags::RenewableOk.into(),
                from: None,
                till: KerberosTime::from_date_time(DateTime::new(2024, 04, 17, 04, 15, 49).expect("Failed to build DateTime")),
                rtime: None,
                nonce: 2143135662,
                etype: vec![18, 17, 20, 19, 16, 23, 25, 26],
                addresses: None,
            },
            TestAsReq {
                blob: b"aoH/MIH8oQMCAQWiAwIBCqMtMCswCqEEAgIAlqICBAAwCqEEAgIAlaICBAAwEaEEAgIAgKIJBAcwBaADAQH/pIHAMIG9oAcDBQBQAQAQoRIwEKADAgEBoQkwBxsFdXNlcjGiDBsKQUZPUkVTVC5BRKMfMB2gAwIBAqEWMBQbBmtyYnRndBsKQUZPUkVTVC5BRKURGA8yMDI0MDYxMjE0NTEwOVqnBgIEWGFV3agUMBICARQCARMCARICARECARoCARmpPjA8MA2gAwIBAqEGBATAqAFkMA2gAwIBAqEGBASsEQABMA2gAwIBAqEGBATAqGUBMA2gAwIBAqEGBAQKldZa".to_vec(),
                principal: "user1".to_string(),
                realm: "AFOREST.AD".to_string(),
                padata: vec![
                    TestPaData {
                        padata_type: 150,
                        padata_value: vec![],
                    },
                    TestPaData {
                        padata_type: 149,
                        padata_value: vec![],
                    },
                    TestPaData {
                        padata_type: 128,
                        padata_value: vec![0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff],
                    }
                ],
                kdc_options: KerberosFlags::RenewableOk | KerberosFlags::Forwardable | KerberosFlags::Canonicalize | KerberosFlags::Proxiable,
                from: None,
                till: KerberosTime::from_date_time(DateTime::new(2024, 06, 12, 14, 51, 09).expect("Failed to build DateTime")),
                rtime: None,
                nonce: 1482773981,
                etype: vec![20, 19, 18, 17, 26, 25],
                addresses: Some(vec![
                    (2, OctetString::new(vec![0xc0, 0xa8, 0x01, 0x64]).expect("Failed to build octet string")),
                    (2, OctetString::new(vec![0xAC, 0x11, 0x00, 0x01]).expect("Failed to build octet string")),
                    (2, OctetString::new(vec![0xC0, 0xA8, 0x65, 0x01]).expect("Failed to build octet string")),
                    (2, OctetString::new(vec![0x0A, 0x95, 0xD6, 0x5A]).expect("Failed to build octet string"))
                ]),
            }
        ];

        for sample in samples {
            let blob = BASE64_STANDARD
                .decode(&sample.blob)
                .expect("Failed to decode sample");
            let message = KrbKdcReq::from_der(&blob).expect("Failed to decode");
            match message {
                KrbKdcReq::AsReq(asreq) => verify_as_req(&asreq, &sample),
                KrbKdcReq::TgsReq(_) => todo!(),
            }
        }
    }
}
