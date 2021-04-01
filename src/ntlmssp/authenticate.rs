//! The AUTHENTICATE_MESSAGE defines an NTLM authenticate message that is sent from the client
//! to the server after the CHALLENGE_MESSAGE is processed by the client.

use super::{AVPair, DomainNameFields, Version, WorkstationFields};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Authenticate {
    /// LmChallengeResponseFields (8 bytes): A field containing LmChallengeResponse information.
    ///
    /// If the client chooses to send an LmChallengeResponse to the server, the fields are set.
    ///
    /// Otherwise, if the client chooses not to send an LmChallengeResponse to the server,
    /// the fields take the following values:
    /// - LmChallengeResponseLen and LmChallengeResponseMaxLen MUST be set to zero on transmission.
    /// - LmChallengeResponseBufferOffset field SHOULD be set to the offset from the beginning of
    /// the AUTHENTICATE_MESSAGE to where the LmChallengeResponse would be in Payload if it was present.
    pub lm_challenge_response_fields: LmChallengeResponseFields,
    /// NtChallengeResponseFields (8 bytes): A field containing NtChallengeResponse information.
    ///
    /// If the client chooses to send an NtChallengeResponse to the server, the fields are set.
    ///
    /// Otherwise, if the client chooses not to send an NtChallengeResponse to the server,
    /// the fields take the following values:
    /// - NtChallengeResponseLen, and NtChallengeResponseMaxLen MUST be set to zero on transmission.
    /// - NtChallengeResponseBufferOffset field SHOULD be set to the offset from the beginning of the
    ///   AUTHENTICATE_MESSAGE to where the NtChallengeResponse would be in Payload if it was present.
    pub nt_challenge_response_fields: NtChallengeResponseFields,
    /// DomainNameFields (8 bytes): A field containing DomainName information.
    ///
    /// If the client chooses to send a DomainName to the server, the fields are set.
    ///
    /// Otherwise, if the client chooses not to send a DomainName to the server,
    /// the fields take the following values:
    /// - DomainNameLen and DomainNameMaxLen MUST be set to zero on transmission.
    /// - DomainNameBufferOffset field SHOULD be set to the offset from the beginning
    /// of the AUTHENTICATE_MESSAGE to where the DomainName would be in Payload if it was present.
    pub domain_name_fields: DomainNameFields,
    /// UserNameFields (8 bytes): A field containing UserName information.
    ///
    /// If the client chooses to send a UserName to the server, the fields are set.
    ///
    /// Otherwise, if the client chooses not to send a UserName to the server,
    /// the fields take the following values:
    /// - UserNameLen and UserNameMaxLen MUST be set to zero on transmission.
    /// - UserNameBufferOffset field SHOULD be set to the offset from the beginning of the
    ///   AUTHENTICATE_MESSAGE to where the UserName would be in Payload if it were present.
    pub user_name_fields: UserNameFields,
    /// WorkstationFields (8 bytes): A field containing Workstation information.
    ///
    /// If the client chooses to send a Workstation to the server, the fields are set.
    ///
    /// Othewise, if the client chooses not to send a Workstation to the server,
    /// the fields take the following values:
    /// - WorkstationLen and WorkstationMaxLen MUST be set to zero on transmission.
    /// - WorkstationBufferOffset field SHOULD be set to the offset from the beginning
    ///   of the AUTHENTICATE_MESSAGE to where the Workstation would be in Payload if it was present.
    pub workstation_fields: WorkstationFields,
    /// EncryptedRandomSessionKeyFields (8 bytes): A field containing EncryptedRandomSessionKey information.
    ///
    /// If the NTLMSSP_NEGOTIATE_KEY_EXCH flag is set in NegotiateFlags, indicating that an
    /// EncryptedRandomSessionKey is supplied, the fields are set.
    ///
    /// Otherwise, if the NTLMSSP_NEGOTIATE_KEY_EXCH flag is not set in NegotiateFlags, indicating that an
    /// EncryptedRandomSessionKey is not supplied, the fields take the following values, and must be
    /// ignored upon receipt:
    /// - EncryptedRandomSessionKeyLen and EncryptedRandomSessionKeyMaxLen SHOULD be set to zero on transmission.
    /// - EncryptedRandomSessionKeyBufferOffset field SHOULD be set to the offset from the beginning of the
    ///   AUTHENTICATE_MESSAGE to where the EncryptedRandomSessionKey would be in Payload if it was present.
    pub encrypted_random_session_key_fields: EncryptedRandomSessionKeyFields,
    /// NegotiateFlags (4 bytes): In connectionless mode, a NEGOTIATE structure that contains a set of
    /// flags and represents the conclusion of negotiation—the choices the client has made from the
    /// options the server offered in the CHALLENGE_MESSAGE. In connection-oriented mode, a NEGOTIATE
    /// structure that contains the set of bit flags negotiated in the previous messages.
    /// The values for the negotiate flags should be taken from the Corresponding bitflag struct.
    pub negotiate_flags: Vec<u8>,
    /// Version (8 bytes): A VERSION structure that is populated only when the NTLMSSP_NEGOTIATE_VERSION
    /// flag is set in the NegotiateFlags field. This structure is used for debugging purposes only.
    /// In normal protocol messages, it is ignored and does not affect the NTLM message processing.
    pub version: Version,
    /// MIC (16 bytes): The message integrity for the NTLM NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE, and AUTHENTICATE_MESSAGE.
    pub mic: Vec<u8>,
    /// Payload (variable): A byte array that contains the data referred to by the LmChallengeResponseBufferOffset,
    /// NtChallengeResponseBufferOffset, DomainNameBufferOffset, UserNameBufferOffset, WorkstationBufferOffset,
    /// and EncryptedRandomSessionKeyBufferOffset message fields. Payload data can be present in any order within
    /// the Payload field, with variable-length padding before or after the data. The data that can be present
    /// in the Payload field of this message, in no particular order.
    pub payload: Payload,
}

impl Authenticate {
    /// Creates a new instance of the NTLM Authenticate message.
    pub fn default() -> Self {
        Authenticate {
            lm_challenge_response_fields: LmChallengeResponseFields::default(),
            nt_challenge_response_fields: NtChallengeResponseFields::default(),
            domain_name_fields: DomainNameFields::default(),
            user_name_fields: UserNameFields::default(),
            workstation_fields: WorkstationFields::default(),
            encrypted_random_session_key_fields: EncryptedRandomSessionKeyFields::default(),
            negotiate_flags: Vec::new(),
            version: Version::default(),
            mic: Vec::new(),
            payload: Payload::default(),
        }
    }
}

/// LmChallengeResponseFields (8 bytes): A field containing LmChallengeResponse information.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LmChallengeResponseFields {
    /// LmChallengeResponseLen (2 bytes): A 16-bit unsigned integer that defines the size,
    /// in bytes, of LmChallengeResponse in Payload.
    pub lm_challenge_response_len: Vec<u8>,
    /// LmChallengeResponseMaxLen (2 bytes): A 16-bit unsigned integer that SHOULD be set
    /// to the value of LmChallengeResponseLen and MUST be ignored on receipt.
    pub lm_challenge_response_max_len: Vec<u8>,
    /// LmChallengeResponseBufferOffset (4 bytes): A 32-bit unsigned integer that defines
    /// the offset, in bytes, from the beginning of the AUTHENTICATE_MESSAGE to
    /// LmChallengeResponse in Payload.
    pub lm_challenge_response_buffer_offset: Vec<u8>,
}

impl LmChallengeResponseFields {
    /// Creates a new instance of Lm Challenge Response Fields.
    pub fn default() -> Self {
        LmChallengeResponseFields {
            lm_challenge_response_len: Vec::new(),
            lm_challenge_response_max_len: Vec::new(),
            lm_challenge_response_buffer_offset: Vec::new(),
        }
    }
}

/// NtChallengeResponseFields (8 bytes): A field containing NtChallengeResponse information.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NtChallengeResponseFields {
    /// NtChallengeResponseLen (2 bytes): A 16-bit unsigned integer that defines the size,
    /// in bytes, of NtChallengeResponse in Payload.
    pub nt_challenge_response_len: Vec<u8>,
    /// NtChallengeResponseMaxLen (2 bytes): A 16-bit unsigned integer that SHOULD be set
    /// to the value of NtChallengeResponseLen and MUST be ignored on receipt.
    pub nt_challenge_response_max_len: Vec<u8>,
    /// NtChallengeResponseBufferOffset (4 bytes): A 32-bit unsigned integer that
    /// defines the offset, in bytes, from the beginning of the AUTHENTICATE_MESSAGE to
    /// NtChallengeResponse in Payload.
    pub nt_challenge_response_buffer_offset: Vec<u8>,
}

impl NtChallengeResponseFields {
    /// Creates a new instance of the NT Challenge Response Fields.
    pub fn default() -> Self {
        NtChallengeResponseFields {
            nt_challenge_response_len: Vec::new(),
            nt_challenge_response_max_len: Vec::new(),
            nt_challenge_response_buffer_offset: Vec::new(),
        }
    }
}

/// UserNameFields (8 bytes): A field containing UserName information.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UserNameFields {
    /// UserNameLen (2 bytes): A 16-bit unsigned integer that defines the size,
    /// in bytes, of UserName in Payload, not including a NULL terminator.
    pub user_name_len: Vec<u8>,
    /// UserNameMaxLen (2 bytes): A 16-bit unsigned integer that SHOULD
    /// be set to the value of UserNameLen and MUST be ignored on receipt.
    pub user_name_max_len: Vec<u8>,
    /// UserNameBufferOffset (4 bytes): A 32-bit unsigned integer that defines the offset,
    /// in bytes, from the beginning of the AUTHENTICATE_MESSAGE to UserName in Payload.
    /// If the UserName to be sent contains a Unicode string, the values of UserNameBufferOffset
    /// and UserNameLen MUST be multiples of 2.
    pub user_name_buffer_offset: Vec<u8>,
}

impl UserNameFields {
    /// Creates a new intance of user name fields.
    pub fn default() -> Self {
        UserNameFields {
            user_name_len: Vec::new(),
            user_name_max_len: Vec::new(),
            user_name_buffer_offset: Vec::new(),
        }
    }
}

/// EncryptedRandomSessionKeyFields (8 bytes): A field containing EncryptedRandomSessionKey information.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EncryptedRandomSessionKeyFields {
    /// EncryptedRandomSessionKeyLen (2 bytes): A 16-bit unsigned integer that
    /// defines the size, in bytes, of EncryptedRandomSessionKey in Payload.
    pub encrypted_random_session_key_len: Vec<u8>,
    /// EncryptedRandomSessionKeyMaxLen (2 bytes): A 16-bit unsigned integer
    /// that SHOULD be set to the value of EncryptedRandomSessionKeyLen and
    /// MUST be ignored on receipt.
    pub encrypted_random_session_key_max_len: Vec<u8>,
    ///  EncryptedRandomSessionKeyBufferOffset (4 bytes): A 32-bit unsigned
    /// integer that defines the offset, in bytes, from the beginning of the
    /// AUTHENTICATE_MESSAGE to EncryptedRandomSessionKey in Payload.
    pub encrypted_random_session_key_buffer_offset: Vec<u8>,
}

impl EncryptedRandomSessionKeyFields {
    /// Creates a new instance of Encrypted Random Session Key Fields.
    pub fn default() -> Self {
        EncryptedRandomSessionKeyFields {
            encrypted_random_session_key_len: Vec::new(),
            encrypted_random_session_key_max_len: Vec::new(),
            encrypted_random_session_key_buffer_offset: Vec::new(),
        }
    }
}

/// Payload (variable): A byte array that contains the data referred to by the LmChallengeResponseBufferOffset,
/// NtChallengeResponseBufferOffset, DomainNameBufferOffset, UserNameBufferOffset, WorkstationBufferOffset,
/// and EncryptedRandomSessionKeyBufferOffset message fields. Payload data can be present in any order within
/// the Payload field, with variable-length padding before or after the data. The data that can be present in
/// the Payload field of this message, in no particular order.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Payload {
    /// LmChallengeResponse (variable): An LM_RESPONSE structure or an LMv2_RESPONSE structure
    /// that contains the computed LM response to the challenge. If NTLM v2 authentication is configured,
    /// then LmChallengeResponse MUST be an LMv2_RESPONSE structure. Otherwise, it MUST be an LM_RESPONSE structure.
    pub lm_challenge_response: Vec<u8>,
    /// NtChallengeResponse (variable): An NTLM_RESPONSE structure or NTLMv2_RESPONSE structure that contains the
    /// computed NT response to the challenge. If NTLM v2 authentication is configured, NtChallengeResponse
    /// MUST be an NTLMv2_RESPONSE. Otherwise, it MUST be an NTLM_RESPONSE.
    pub nt_challenge_response: NTLMv2Response,
    /// DomainName (variable): The domain or computer name hosting the user account.
    /// DomainName MUST be encoded in the negotiated character set.
    pub domain_name: Vec<u8>,
    /// UserName (variable): The name of the user to be authenticated.
    /// UserName MUST be encoded in the negotiated character set.
    pub user_name: Vec<u8>,
    /// Workstation (variable): The name of the computer to which the user is logged on.
    /// Workstation MUST be encoded in the negotiated character set.
    pub workstation: Vec<u8>,
    /// EncryptedRandomSessionKey (variable): The client's encrypted random session key.
    pub encrypted_random_session_key: Vec<u8>,
}

impl Payload {
    /// Creates a new instance of the NTLM Authenticate Payload.
    pub fn default() -> Self {
        Payload {
            lm_challenge_response: Vec::new(),
            nt_challenge_response: NTLMv2Response::default(),
            domain_name: Vec::new(),
            user_name: Vec::new(),
            workstation: Vec::new(),
            encrypted_random_session_key: Vec::new(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NTLMv2Response {
    /// Response (16 bytes): A 16-byte array of unsigned char that contains the
    /// client's NTChallengeResponse. Response corresponds to the NTProofStr variable.
    pub response: Vec<u8>,
    /// NTLMv2_CLIENT_CHALLENGE (variable): A variable-length byte array, that contains
    /// the ClientChallenge. ChallengeFromClient corresponds to the temp variable.
    pub ntlmv2_client_challenge: NTLMv2ClientChallenge,
}

impl NTLMv2Response {
    pub fn default() -> Self {
        NTLMv2Response {
            response: Vec::new(),
            ntlmv2_client_challenge: NTLMv2ClientChallenge::default(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NTLMv2ClientChallenge {
    /// RespType (1 byte): An 8-bit unsigned char that
    /// contains the current version of the challenge response type.
    /// This field MUST be 0x01.
    pub resp_type: Vec<u8>,
    /// HiRespType (1 byte): An 8-bit unsigned char that contains
    /// the maximum supported version of the challenge response type.
    /// This field MUST be 0x01.
    pub hi_resp_type: Vec<u8>,
    /// Reserved1 (2 bytes): A 16-bit unsigned integer that SHOULD
    /// be 0x0000 and MUST be ignored on receipt.
    pub reserved1: Vec<u8>,
    /// Reserved2 (4 bytes): A 32-bit unsigned integer that SHOULD
    /// be 0x00000000 and MUST be ignored on receipt.
    pub reserved2: Vec<u8>,
    /// TimeStamp (8 bytes): A 64-bit unsigned integer that contains
    /// the current system time, represented as the number of 100
    /// nanosecond ticks elapsed since midnight of January 1, 1601 (UTC).
    pub time_stamp: Vec<u8>,
    /// ChallengeFromClient (8 bytes): An 8-byte array of unsigned char
    /// that contains the client's ClientChallenge.
    pub challenge_from_client: Vec<u8>,
    /// Reserved3 (4 bytes): A 32-bit unsigned integer that SHOULD
    /// be 0x00000000 and MUST be ignored on receipt.
    pub reserved3: Vec<u8>,
    /// AvPairs (variable): A byte array that contains a sequence of
    /// AV_PAIR structures. The sequence contains the server-naming
    /// context and is terminated by an AV_PAIR structure with an AvId field of MsvAvEOL.
    pub av_pairs: Vec<AVPair>,
}

impl NTLMv2ClientChallenge {
    pub fn default() -> Self {
        NTLMv2ClientChallenge {
            resp_type: vec![1],
            hi_resp_type: vec![1],
            reserved1: vec![0; 2],
            reserved2: vec![0; 4],
            time_stamp: vec![0; 8],
            challenge_from_client: b"\x22\x10\x50\xcd\x22\xf4\xa4\x14".to_vec(),
            reserved3: vec![0; 4],
            av_pairs: Vec::new(),
        }
    }
}
