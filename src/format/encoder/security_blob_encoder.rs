use ntlmssp::MessageType;

use crate::{
    gss,
    ntlmssp::{self, authenticate::NTLMv2ClientChallenge, AVPair},
};

/// Serializes the challenge's target info.
pub fn encode_challenge_target_info(target_info: Vec<AVPair>, proof: bool) -> Vec<u8> {
    let mut encoded: Vec<u8> = Vec::new();

    for av_pair in target_info.into_iter() {
        encoded.append(&mut av_pair.av_id.unwrap().unpack_byte_code());
        encoded.append(&mut av_pair.av_len.clone());
        encoded.append(&mut av_pair.value.clone());
    }

    if proof && encoded.is_empty() {
        encoded.truncate(encoded.len() - 4);
    }

    encoded
}

/// Serializes the whole authentication blob.
pub fn encode_authenticate_blob(mut ntlm_header: ntlmssp::Header) -> Vec<u8> {
    let mut encoded: Vec<u8> = Vec::new();

    let auth = match ntlm_header.message.unwrap() {
        MessageType::Authenticate(authenticate) => authenticate,
        _ => panic!("Invalid message type for authentication encoding."),
    };
    encoded.append(&mut ntlm_header.signature);
    encoded.append(&mut ntlm_header.message_type);
    encoded.append(&mut encode_authenticate_message(*auth));

    encoded
}

/// Serializes the authentication gss token.
pub fn encode_security_authentication(mut token: gss::NegTokenResp) -> Vec<u8> {
    let mut encoded: Vec<u8> = Vec::new();

    encoded.append(&mut token.state);
    encoded.append(&mut token.response_token);

    encoded
}

/// Serializes the authenticate message.
pub fn encode_authenticate_message(mut message: ntlmssp::authenticate::Authenticate) -> Vec<u8> {
    let mut encoded: Vec<u8> = Vec::new();

    encoded.append(
        &mut message
            .lm_challenge_response_fields
            .lm_challenge_response_len,
    );
    encoded.append(
        &mut message
            .lm_challenge_response_fields
            .lm_challenge_response_max_len,
    );
    encoded.append(
        &mut message
            .lm_challenge_response_fields
            .lm_challenge_response_buffer_offset,
    );
    encoded.append(
        &mut message
            .nt_challenge_response_fields
            .nt_challenge_response_len,
    );
    encoded.append(
        &mut message
            .nt_challenge_response_fields
            .nt_challenge_response_max_len,
    );
    encoded.append(
        &mut message
            .nt_challenge_response_fields
            .nt_challenge_response_buffer_offset,
    );
    encoded.append(&mut message.domain_name_fields.domain_name_len);
    encoded.append(&mut message.domain_name_fields.domain_name_max_len);
    encoded.append(&mut message.domain_name_fields.domain_name_buffer_offset);
    encoded.append(&mut message.user_name_fields.user_name_len);
    encoded.append(&mut message.user_name_fields.user_name_max_len);
    encoded.append(&mut message.user_name_fields.user_name_buffer_offset);
    encoded.append(&mut message.workstation_fields.workstation_len);
    encoded.append(&mut message.workstation_fields.workstation_max_len);
    encoded.append(&mut message.workstation_fields.workstation_buffer_offset);
    encoded.append(
        &mut message
            .encrypted_random_session_key_fields
            .encrypted_random_session_key_len,
    );
    encoded.append(
        &mut message
            .encrypted_random_session_key_fields
            .encrypted_random_session_key_max_len,
    );
    encoded.append(
        &mut message
            .encrypted_random_session_key_fields
            .encrypted_random_session_key_buffer_offset,
    );
    encoded.append(&mut message.negotiate_flags);
    encoded.append(&mut message.version.product_major_version);
    encoded.append(&mut message.version.product_minor_version);
    encoded.append(&mut message.version.product_build);
    encoded.append(&mut message.version.ntlm_revision_current);
    encoded.append(&mut message.mic);
    encoded.append(&mut message.payload.lm_challenge_response);

    let mut ntlm_response = message.payload.nt_challenge_response;
    encoded.append(&mut ntlm_response.response);
    encoded.append(&mut serialize_ntlm_challenge(
        ntlm_response.ntlmv2_client_challenge,
    ));

    encoded.append(&mut message.payload.domain_name);
    encoded.append(&mut message.payload.user_name);
    encoded.append(&mut message.payload.workstation);
    encoded.append(&mut message.payload.encrypted_random_session_key);

    encoded
}

/// Serializes the ntlm client challenge.
pub fn serialize_ntlm_challenge(mut ntlm_challenge: NTLMv2ClientChallenge) -> Vec<u8> {
    let mut encoded: Vec<u8> = Vec::new();

    encoded.append(&mut ntlm_challenge.resp_type);
    encoded.append(&mut ntlm_challenge.hi_resp_type);
    encoded.append(&mut ntlm_challenge.reserved1);
    encoded.append(&mut ntlm_challenge.reserved2);
    encoded.append(&mut ntlm_challenge.time_stamp);
    encoded.append(&mut ntlm_challenge.challenge_from_client);
    encoded.append(&mut ntlm_challenge.reserved3);
    encoded.append(&mut encode_challenge_target_info(
        ntlm_challenge.av_pairs,
        false,
    ));

    encoded
}
