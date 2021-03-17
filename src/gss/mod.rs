//! This module contains support for GSS.

const SPNEGOID: &str = "1.3.6.1.5.5.2";
const NTLMSSPMECHTYPEOID: &str = "1.3.6.1.4.1.311.2.2.10";

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NegTokenInit {
    oid: Vec<u32>,
    data: NegTokenInitData,
}

impl NegTokenInit {
    pub fn new() -> Self {
        let oid = object_id_str_to_int_vec(SPNEGOID);
        let nltmoid = object_id_str_to_int_vec(NTLMSSPMECHTYPEOID);

        NegTokenInit {
            oid,
            data: NegTokenInitData::new(nltmoid),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NegTokenInitData {
    /// The list of authentication mechanisms that are available, by OID
    mech_types: Vec<Vec<u32>>,
    /// This field SHOULD be omitted by the sender.
    req_flags: BitString,
    /// The optimistic mechanism token.
    mech_token: Vec<u8>,
    /// The message integrity code (MIC) token
    mech_token_mic: Vec<u8>,
}

impl NegTokenInitData {
    pub fn new(ntlmoid: Vec<u32>) -> Self {
        NegTokenInitData {
            mech_types: vec![ntlmoid],
            req_flags: BitString::default(),
            mech_token: Vec::new(),
            mech_token_mic: Vec::new(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BitString {
    bytes: Vec<u8>,
    bit_length: u32,
}

impl BitString {
    pub fn default() -> Self {
        BitString {
            bytes: Vec::new(),
            bit_length: 0,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NegTokenResp {
    state: u32,
    supported_mech: Vec<u32>,
    response_token: Vec<u8>,
    mech_list_mic: Vec<u8>,
}

pub fn object_id_str_to_int_vec(oid: &str) -> Vec<u32> {
    oid.split('.')
        .map(|n| match n.parse::<u32>() {
            Ok(id) => id,
            Err(err) => panic!("Could not parse ASN1 OID: {}", err),
        })
        .collect::<Vec<u32>>()
}
