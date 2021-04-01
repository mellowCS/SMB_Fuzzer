use ntlmssp::{AVPair, AvId};

use crate::{
    format::encoder::security_blob_encoder::encode_authenticate_blob,
    gss,
    ntlmssp::{self, authenticate::NTLMv2Response, negotiate_flags::NegotiateFlags, MessageType},
};

const LM_CHALLENGE_RESPONSE_OFFSET: &[u8; 4] = b"\x58\x00\x00\x00";
const NTLM_CHALLENGE_RESPONSE_OFFSET: &[u8; 4] = b"\x70\x00\x00\x00";
const DEFAULT_GSS_PREFIX: &[u8; 16] =
    b"\xa1\x82\x01\x52\x30\x82\x01\x4e\xa2\x82\x01\x4a\x04\x82\x01\x46";

/// Builds a working default session setup 2 request security buffer.
pub fn build_session_setup_2_request_security_buffer(
    server_challenge_struct: ntlmssp::challenge::Challenge,
) -> gss::NegTokenResp {
    let mut neg_token_response = gss::NegTokenResp::default();
    let mut ntlm_header = ntlmssp::Header::default();
    let authenticate = build_authenticate_message(server_challenge_struct);

    let message_type = MessageType::Authenticate(Box::new(authenticate));
    ntlm_header.message_type = message_type.unpack_byte_code();
    ntlm_header.message = Some(message_type);
    neg_token_response.state = DEFAULT_GSS_PREFIX.to_vec();
    neg_token_response.response_token = encode_authenticate_blob(ntlm_header);

    neg_token_response
}

/// Builds a working default ntlmv2 authenticate message.
pub fn build_authenticate_message(
    server_challenge_struct: ntlmssp::challenge::Challenge,
) -> ntlmssp::authenticate::Authenticate {
    let mut authenticate = ntlmssp::authenticate::Authenticate::default();

    authenticate.payload.lm_challenge_response = vec![0; 24];
    authenticate
        .lm_challenge_response_fields
        .lm_challenge_response_len = b"\x18\x00".to_vec();
    authenticate
        .lm_challenge_response_fields
        .lm_challenge_response_max_len = b"\x18\x00".to_vec();
    authenticate
        .lm_challenge_response_fields
        .lm_challenge_response_buffer_offset = LM_CHALLENGE_RESPONSE_OFFSET.to_vec();

    let mut ntlmv2_response = build_ntlmv2_response(get_server_time(&server_challenge_struct));
    authenticate
        .nt_challenge_response_fields
        .nt_challenge_response_len = calculate_ntlmv2_challenge_size(&ntlmv2_response);
    authenticate
        .nt_challenge_response_fields
        .nt_challenge_response_max_len = authenticate
        .nt_challenge_response_fields
        .nt_challenge_response_len
        .clone();
    authenticate
        .nt_challenge_response_fields
        .nt_challenge_response_buffer_offset = NTLM_CHALLENGE_RESPONSE_OFFSET.to_vec();

    authenticate.payload.domain_name =
        b"\x57\x00\x4f\x00\x52\x00\x4b\x00\x47\x00\x52\x00\x4f\x00\x55\x00\x50\x00".to_vec();
    authenticate.domain_name_fields.domain_name_len = b"\x12\x00".to_vec();
    authenticate.domain_name_fields.domain_name_max_len = b"\x12\x00".to_vec();
    authenticate.domain_name_fields.domain_name_buffer_offset = b"\x28\x01\x00\x00".to_vec();

    authenticate.payload.user_name = b"\x74\x00\x6f\x00\x6d\x00".to_vec();
    authenticate.user_name_fields.user_name_len = b"\x06\x00".to_vec();
    authenticate.user_name_fields.user_name_max_len = b"\x06\x00".to_vec();
    authenticate.user_name_fields.user_name_buffer_offset = b"\x3a\x01\x00\x00".to_vec();

    authenticate.payload.workstation = b"\x54\x00\x4f\x00\x4d\x00".to_vec();
    authenticate.workstation_fields.workstation_len = b"\x06\x00".to_vec();
    authenticate.workstation_fields.workstation_max_len = b"\x06\x00".to_vec();
    authenticate.workstation_fields.workstation_buffer_offset = b"\x40\x01\x00\x00".to_vec();

    authenticate
        .encrypted_random_session_key_fields
        .encrypted_random_session_key_len = vec![0; 2];
    authenticate
        .encrypted_random_session_key_fields
        .encrypted_random_session_key_max_len = vec![0; 2];
    authenticate
        .encrypted_random_session_key_fields
        .encrypted_random_session_key_buffer_offset = b"\x46\x01\x00\x00".to_vec();

    let flags =
        { NegotiateFlags::NEG_NTLM | NegotiateFlags::NEG_UNICODE | NegotiateFlags::NEG_VERSION };

    authenticate.negotiate_flags = flags.bits().to_le_bytes().to_vec();

    authenticate.version.product_major_version = vec![6];
    authenticate.version.product_minor_version = vec![1];
    authenticate.version.product_build = vec![0; 2];
    authenticate.version.ntlm_revision_current = vec![15, 0, 0, 0];

    authenticate.mic = vec![0; 16];

    ntlmv2_response.response = vec![0; 16];

    authenticate.mic = vec![0; 16];

    authenticate.payload.nt_challenge_response = ntlmv2_response;

    authenticate
}

/// Calculates the size of the ntlmv2 challenge and returns it as a 2 byte little endian vector.
pub fn calculate_ntlmv2_challenge_size(ntlmv2_response: &NTLMv2Response) -> Vec<u8> {
    let mut size: u16 = 44;
    for pair in ntlmv2_response.ntlmv2_client_challenge.av_pairs.iter() {
        size += (4 + pair.value.len()) as u16;
    }

    size.to_le_bytes().to_vec()
}

/// Builds the NTLMv2 client challenge.
pub fn build_ntlmv2_response(server_time_stamp: Vec<u8>) -> NTLMv2Response {
    let mut response = NTLMv2Response::default();
    response.ntlmv2_client_challenge.time_stamp = server_time_stamp.clone();
    let mut nb_domain_name = AVPair::default();
    nb_domain_name.av_id = Some(AvId::MsvAvNbDomainName);
    nb_domain_name.av_len = b"\x16\x00".to_vec();
    nb_domain_name.value =
        b"\x52\x00\x41\x00\x53\x00\x50\x00\x42\x00\x45\x00\x52\x00\x52\x00\x59\x00\x50\x00\x49\x00"
            .to_vec();

    let mut nb_computer_name = AVPair::default();
    nb_computer_name.av_id = Some(AvId::MsvAvNbComputerName);
    nb_computer_name.av_len = b"\x16\x00".to_vec();
    nb_computer_name.value =
        b"\x52\x00\x41\x00\x53\x00\x50\x00\x42\x00\x45\x00\x52\x00\x52\x00\x59\x00\x50\x00\x49\x00"
            .to_vec();

    let mut dns_domain_name = AVPair::default();
    dns_domain_name.av_id = Some(AvId::MsvAvDnsDomainName);
    dns_domain_name.av_len = b"\x02\x00".to_vec();
    dns_domain_name.value = vec![0; 2];

    let mut dns_computer_name = AVPair::default();
    dns_computer_name.av_id = Some(AvId::MsvAvDnsComputerName);
    dns_computer_name.av_len = b"\x16\x00".to_vec();
    dns_computer_name.value =
        b"\x72\x00\x61\x00\x73\x00\x70\x00\x62\x00\x65\x00\x72\x00\x72\x00\x79\x00\x70\x00\x69\x00"
            .to_vec();

    let mut time_stamp = AVPair::default();
    time_stamp.av_id = Some(AvId::MsvAvTimeStamp);
    time_stamp.av_len = b"\x08\x00".to_vec();
    time_stamp.value = server_time_stamp;

    let mut target = AVPair::default();
    target.av_id = Some(AvId::MsvAvTargetName);
    target.av_len = b"\x24\x00".to_vec();
    target.value = b"\x63\x00\x69\x00\x66\x00\x73\x00\x2f\x00\x31\x00\x39\x00\x32\x00\x2e\x00\
                     \x31\x00\x36\x00\x38\x00\x2e\x00\x30\x00\x2e\x00\x31\x00\x37\x00\x31\x00"
        .to_vec();

    let mut eol = AVPair::default();
    eol.av_id = Some(AvId::MsvAvEOL);
    eol.av_len = vec![0; 2];

    response.ntlmv2_client_challenge.av_pairs = vec![
        nb_domain_name,
        nb_computer_name,
        dns_domain_name,
        dns_computer_name,
        time_stamp,
        target,
        eol,
    ];

    response
}

/// Gets the time stamp from the ntlmv2 server challenge.
pub fn get_server_time(challenge: &ntlmssp::challenge::Challenge) -> Vec<u8> {
    for pair in challenge.payload.target_info.iter() {
        if let ntlmssp::AvId::MsvAvTimeStamp = pair.av_id.clone().unwrap() {
            return pair.value.clone();
        }
    }

    panic!("Missing timestamp from server challenge.");
}
