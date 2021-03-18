//! During NTLM authentication, each of the following flags is a possible value of the
//! NegotiateFlags field of the NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE, and AUTHENTICATE_MESSAGE,
//! unless otherwise noted. These flags define client or server NTLM capabilities supported by the sender.

bitflags! {
    struct NegotiateFlags: u32 {
        /// W (1 bit): If set, requests 56-bit encryption. If the client sends NTLMSSP_NEGOTIATE_SEAL
        /// or NTLMSSP_NEGOTIATE_SIGN with NTLMSSP_NEGOTIATE_56 to the server in the NEGOTIATE_MESSAGE,
        /// the server MUST return NTLMSSP_NEGOTIATE_56 to the client in the CHALLENGE_MESSAGE.
        /// Otherwise it is ignored. If both NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 are requested
        /// and supported by the client and server, NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 will
        /// both be returned to the client. Clients and servers that set NTLMSSP_NEGOTIATE_SEAL SHOULD
        /// set NTLMSSP_NEGOTIATE_56 if it is supported. An alternate name for this field is NTLMSSP_NEGOTIATE_56.
        const NEG_56 = 0b1000_0000_0000_0000_0000_0000_0000_0000;
        /// V (1 bit): If set, requests an explicit key exchange. This capability SHOULD be used because it
        /// improves security for message integrity or confidentiality. An alternate name for this field is
        /// NTLMSSP_NEGOTIATE_KEY_EXCH.
        const NEG_KEY_EXCH = 0b0100_0000_0000_0000_0000_0000_0000_0000;
        /// U (1 bit): If set, requests 128-bit session key negotiation. An alternate name for this field
        /// is NTLMSSP_NEGOTIATE_128. If the client sends NTLMSSP_NEGOTIATE_128 to the server in the NEGOTIATE_MESSAGE,
        /// the server MUST return NTLMSSP_NEGOTIATE_128 to the client in the CHALLENGE_MESSAGE only if the client
        /// sets NTLMSSP_NEGOTIATE_SEAL or NTLMSSP_NEGOTIATE_SIGN. Otherwise it is ignored.
        /// If both NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 are requested and supported by the client and server,
        /// NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 will both be returned to the client. Clients and servers that
        /// set NTLMSSP_NEGOTIATE_SEAL SHOULD set NTLMSSP_NEGOTIATE_128 if it is supported. An alternate name for this
        /// field is NTLMSSP_NEGOTIATE_128.
        const NEG_128 = 0b0010_0000_0000_0000_0000_0000_0000_0000;
        /// THREE ZERO BITS HERE
        /// T (1 bit): If set, requests the protocol version number. The data corresponding to this flag is provided
        /// in the Version field of the NEGOTIATE_MESSAGE, the CHALLENGE_MESSAGE, and the AUTHENTICATE_MESSAGE.
        /// An alternate name for this field is NTLMSSP_NEGOTIATE_VERSION.
        const NEG_VERSION = 0b0000_0010_0000_0000_0000_0000_0000_0000;
        /// ONE ZERO BIT HERE
        /// S (1 bit): If set, indicates that the TargetInfo fields in the CHALLENGE_MESSAGE are populated.
        /// An alternate name for this field is NTLMSSP_NEGOTIATE_TARGET_INFO.
        const NEG_TARGET_INFO = 0b0000_0000_1000_0000_0000_0000_0000_0000;
        /// R (1 bit): If set, requests the usage of the LMOWF. An alternate name for this field is
        /// NTLMSSP_REQUEST_NON_NT_SESSION_KEY.
        const REQ_NON_NT_SESSION_KEY = 0b0000_0000_0100_0000_0000_0000_0000_0000;
        /// One ZERO BIT HERE
        /// Q (1 bit): If set, requests an identify level token. An alternate name for this field is
        /// NTLMSSP_NEGOTIATE_IDENTIFY.
        const NEG_IDENTIFY = 0b0000_0000_0001_0000_0000_0000_0000_0000;
        /// P (1 bit): If set, requests usage of the NTLM v2 session security. NTLM v2 session security
        /// is a misnomer because it is not NTLM v2. It is NTLM v1 using the extended session security that
        /// is also in NTLM v2. NTLMSSP_NEGOTIATE_LM_KEY and NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are
        /// mutually exclusive. If both NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY and NTLMSSP_NEGOTIATE_LM_KEY
        /// are requested, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY alone MUST be returned to the client.
        /// NTLM v2 authentication session key generation MUST be supported by both the client and the DC
        /// in order to be used, and extended session security signing and sealing requires support from the
        /// client and the server in order to be used. An alternate name for this field is
        /// NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.
        const NEG_EXTENDED_SESSION_SEC = 0b0000_0000_0000_1000_0000_0000_0000_0000;
        /// One ZERO BIT HERE
        /// O (1 bit): If set, TargetName MUST be a server name. The data corresponding to this flag is
        /// provided by the server in the TargetName field of the CHALLENGE_MESSAGE. If this bit is set,
        /// then NTLMSSP_TARGET_TYPE_DOMAIN MUST NOT be set. This flag MUST be ignored in the NEGOTIATE_MESSAGE
        /// and the AUTHENTICATE_MESSAGE. An alternate name for this field is NTLMSSP_TARGET_TYPE_SERVER.
        const TARGET_TYPE_SERVER = 0b0000_0000_0000_0010_0000_0000_0000_0000;
        /// N (1 bit): If set, TargetName MUST be a domain name. The data corresponding to this flag is
        /// provided by the server in the TargetName field of the CHALLENGE_MESSAGE. If set, then
        /// NTLMSSP_TARGET_TYPE_SERVER MUST NOT be set. This flag MUST be ignored in the NEGOTIATE_MESSAGE
        /// and the AUTHENTICATE_MESSAGE. An alternate name for this field is NTLMSSP_TARGET_TYPE_DOMAIN.
        const TARGET_TYPE_DOMAIN = 0b0000_0000_0000_0001_0000_0000_0000_0000;
        /// M (1 bit): If set, a session key is generated regardless of the states of NTLMSSP_NEGOTIATE_SIGN
        /// and NTLMSSP_NEGOTIATE_SEAL. A session key MUST always exist to generate the MIC in the authenticate message.
        /// NTLMSSP_NEGOTIATE_ALWAYS_SIGN MUST be set in the NEGOTIATE_MESSAGE to the server and the CHALLENGE_MESSAGE
        /// to the client. NTLMSSP_NEGOTIATE_ALWAYS_SIGN is overridden by NTLMSSP_NEGOTIATE_SIGN and NTLMSSP_NEGOTIATE_SEAL,
        /// if they are supported. An alternate name for this field is NTLMSSP_NEGOTIATE_ALWAYS_SIGN.
        const NEG_ALWAYS_SIGN = 0b0000_0000_0000_0000_1000_0000_0000_0000;
        /// One ZERO BIT HERE
        /// L (1 bit):  This flag indicates whether the Workstation field is present. If this flag is not set,
        /// the Workstation field MUST be ignored. If this flag is set, the length of the Workstation field
        /// specifies whether the workstation name is nonempty or not. An alternate name for this field
        /// is NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED.
        const NEG_OEM_WORKSTATION_SUPPLIED = 0b0000_0000_0000_0000_0010_0000_0000_0000;
        /// K (1 bit): If set, the domain name is provided. An alternate name for this field is NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED.
        const NEG_OEM_DOMAIN_SUPPLIED = 0b0000_0000_0000_0000_0001_0000_0000_0000;
        /// J (1 bit): If set, the connection SHOULD be anonymous.
        const ANONYMOUS = 0b0000_0000_0000_0000_0000_1000_0000_0000;
        /// One ZERO BIT HERE
        /// H (1 bit): If set, requests usage of the NTLM v1 session security protocol. NTLMSSP_NEGOTIATE_NTLM MUST be set
        /// in the NEGOTIATE_MESSAGE to the server and the CHALLENGE_MESSAGE to the client. An alternate name for this
        /// field is NTLMSSP_NEGOTIATE_NTLM.
        const NEG_NTLM = 0b0000_0000_0000_0000_0000_0010_0000_0000;
        /// One ZERO BIT HERE
        /// G (1 bit): If set, requests LAN Manager (LM) session key computation. NTLMSSP_NEGOTIATE_LM_KEY and
        /// NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are mutually exclusive. If both NTLMSSP_NEGOTIATE_LM_KEY
        /// and NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are requested, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        /// alone MUST be returned to the client. NTLM v2 authentication session key generation MUST be supported by
        /// both the client and the DC in order to be used, and extended session security signing and sealing requires
        /// support from the client and the server to be used. An alternate name for this field is NTLMSSP_NEGOTIATE_LM_KEY.
        const NEG_LM_KEY = 0b0000_0000_0000_0000_0000_0000_1000_0000;
        /// F (1 bit): If set, requests connectionless authentication. If NTLMSSP_NEGOTIATE_DATAGRAM is set, then
        /// NTLMSSP_NEGOTIATE_KEY_EXCH MUST always be set in the AUTHENTICATE_MESSAGE to the server and the
        /// CHALLENGE_MESSAGE to the client. An alternate name for this field is NTLMSSP_NEGOTIATE_DATAGRAM.
        const NEG_DATAGRAM = 0b0000_0000_0000_0000_0000_0000_0100_0000;
        /// E (1 bit): If set, requests session key negotiation for message confidentiality.
        /// If the client sends NTLMSSP_NEGOTIATE_SEAL to the server in the NEGOTIATE_MESSAGE,
        /// the server MUST return NTLMSSP_NEGOTIATE_SEAL to the client in the CHALLENGE_MESSAGE.
        /// Clients and servers that set NTLMSSP_NEGOTIATE_SEAL SHOULD always set NTLMSSP_NEGOTIATE_56 and
        /// NTLMSSP_NEGOTIATE_128, if they are supported. An alternate name for this field is NTLMSSP_NEGOTIATE_SEAL.
        const NEG_SEAL = 0b0000_0000_0000_0000_0000_0000_0010_0000;
        /// D (1 bit): If set, requests session key negotiation for message signatures.
        /// If the client sends NTLMSSP_NEGOTIATE_SIGN to the server in the NEGOTIATE_MESSAGE,
        /// the server MUST return NTLMSSP_NEGOTIATE_SIGN to the client in the CHALLENGE_MESSAGE.
        /// An alternate name for this field is NTLMSSP_NEGOTIATE_SIGN.
        const NEG_SIGN = 0b0000_0000_0000_0000_0000_0000_0001_0000;
        /// ONE ZERO BIT HERE
        /// C (1 bit): If set, a TargetName field of the CHALLENGE_MESSAGE MUST be supplied.
        /// An alternate name for this field is NTLMSSP_REQUEST_TARGET.
        const REQ_TARGET = 0b0000_0000_0000_0000_0000_0000_0000_0100;
        /// B (1 bit): If set, requests OEM character set encoding. An alternate name for
        /// this field is NTLM_NEGOTIATE_OEM. See bit A for details.
        /// The A and B bits are evaluated together as follows:
        /// A==1: The choice of character set encoding MUST be Unicode.
        /// A==0 and B==1: The choice of character set encoding MUST be OEM.
        /// A==0 and B==0: The protocol MUST return SEC_E_INVALID_TOKEN.
        const NEG_OEM = 0b0000_0000_0000_0000_0000_0000_0000_0010;
        /// A (1 bit): If set, requests Unicode character set encoding.
        /// An alternate name for this field is NTLMSSP_NEGOTIATE_UNICODE.
        /// The A and B bits are evaluated together as follows:
        /// A==1: The choice of character set encoding MUST be Unicode.
        /// A==0 and B==1: The choice of character set encoding MUST be OEM.
        /// A==0 and B==0: The protocol MUST return SEC_E_INVALID_TOKEN.
        const NEG_UNICODE = 0b0000_0000_0000_0000_0000_0000_0000_0001;
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn add_flags() {
        let flags = NegotiateFlags::NEG_56
            | NegotiateFlags::NEG_KEY_EXCH
            | NegotiateFlags::NEG_128
            | NegotiateFlags::NEG_VERSION
            | NegotiateFlags::NEG_EXTENDED_SESSION_SEC
            | NegotiateFlags::NEG_ALWAYS_SIGN
            | NegotiateFlags::NEG_NTLM
            | NegotiateFlags::NEG_LM_KEY
            | NegotiateFlags::NEG_SIGN
            | NegotiateFlags::REQ_TARGET
            | NegotiateFlags::NEG_OEM
            | NegotiateFlags::NEG_UNICODE;
        assert_eq!(flags.bits().to_be_bytes().to_vec(), vec![226, 8, 130, 151]);
    }
}
