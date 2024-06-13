use crate::kdc_req::KdcReq;
use der::{Tag, TagNumber};

/// ```text
/// AS-REQ          ::= [APPLICATION 10] KDC-REQ
/// TGS-REQ         ::= [APPLICATION 12] KDC-REQ
/// ```
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum KrbKdcReq {
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
    use crate::kdc_req::KdcReq;
    use crate::kerberos_flags::KerberosFlags;
    use crate::kerberos_time::KerberosTime;
    use crate::krb_kdc_req::KrbKdcReq;
    use crate::constants::KrbMessageType;
    use base64::prelude::*;
    use core::iter::zip;
    use der::asn1::OctetString;
    use der::flagset::FlagSet;
    use der::DateTime;
    use der::Decode;

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
        addresses: Option<Vec<(i32, OctetString)>>,
    }

    fn verify_as_req(asreq: &KdcReq, tasreq: &TestAsReq) {
        assert_eq!(asreq.pvno, 5);
        assert_eq!(asreq.msg_type, KrbMessageType::KrbAsReq.into());

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
            let addrs = asreq
                .req_body
                .addresses
                .as_ref()
                .expect("addresses must be there");
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
