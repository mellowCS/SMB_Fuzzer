use crate::{
    format::convert_byte_array_to_int,
    ntlmssp::{self, challenge::Challenge, AvId, AvPair, MessageType},
};

/// Decodes the NTLMSSP security response body.
pub fn decode_security_response(security_response: Vec<u8>) -> ntlmssp::Header {
    let ntlmssp_response = remove_gss_wrapper(security_response);
    let mut header = ntlmssp::Header::default();

    header.signature = ntlmssp_response[..8].to_vec();
    header.message_type = ntlmssp_response[8..12].to_vec();

    let mut challenge = Challenge::default();

    challenge.target_name_fields.target_name_len = ntlmssp_response[12..14].to_vec();
    challenge.target_name_fields.target_name_max_len = ntlmssp_response[14..16].to_vec();
    challenge.target_name_fields.target_name_buffer_offset = ntlmssp_response[16..20].to_vec();

    challenge.negotiate_flags = ntlmssp_response[20..24].to_vec();
    challenge.server_challenge = ntlmssp_response[24..32].to_vec();

    challenge.target_info_fields.target_info_len = ntlmssp_response[40..42].to_vec();
    challenge.target_info_fields.target_info_max_len = ntlmssp_response[42..44].to_vec();
    challenge.target_info_fields.target_info_buffer_offset = ntlmssp_response[44..48].to_vec();

    challenge.version.product_major_version = ntlmssp_response[48..49].to_vec();
    challenge.version.product_minor_version = ntlmssp_response[49..50].to_vec();
    challenge.version.product_build = ntlmssp_response[50..52].to_vec();
    challenge.version.ntlm_revision_current = ntlmssp_response[55..56].to_vec();

    let target_info_offset = convert_byte_array_to_int(
        challenge
            .target_info_fields
            .target_info_buffer_offset
            .clone(),
        false,
    ) as usize;
    challenge.payload.target_name = ntlmssp_response[56..target_info_offset].to_vec();

    let end_of_message = target_info_offset
        + convert_byte_array_to_int(challenge.target_info_fields.target_info_len.clone(), false)
            as usize;

    challenge.payload.target_info =
        decode_target_info(ntlmssp_response, target_info_offset, end_of_message);

    header.message = Some(MessageType::Challenge(challenge));

    header
}

/// Decodes the AvPairs of the target info.
pub fn decode_target_info(
    ntlmssp_response: Vec<u8>,
    mut offset: usize,
    end_of_message: usize,
) -> Vec<AvPair> {
    let mut av_pairs: Vec<AvPair> = Vec::new();
    while offset < end_of_message - 4 {
        let mut target_info = AvPair::default();
        target_info.av_id = Some(AvId::map_byte_code_to_av_id(
            ntlmssp_response[offset..offset + 2].to_vec(),
        ));
        target_info.av_len = ntlmssp_response[offset + 2..offset + 4].to_vec();

        let value_size = convert_byte_array_to_int(target_info.av_len.clone(), false);
        target_info.value = ntlmssp_response[offset + 4..offset + 4 + value_size as usize].to_vec();

        av_pairs.push(target_info);

        offset = offset + 4 + value_size as usize;
    }

    av_pairs
}

/// Removes the ASN.1 encoded gss wrapper.
pub fn remove_gss_wrapper(security_response: Vec<u8>) -> Vec<u8> {
    security_response[31..].to_vec()
}

#[cfg(test)]
mod tests {

    use super::*;

    struct Setup {
        complete_byte_code: Vec<u8>,
        ntlm_byte_code: Vec<u8>,
        target_info: Vec<AvPair>,
    }

    impl Setup {
        pub fn new() -> Self {
            let byte_code = b"\xa1\x81\xce\x30\x81\xcb\xa0\x03\x0a\x01\x01\xa1\x0c\x06\x0a\x2b\
                                      \x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x81\xb5\x04\x81\xb2\x4e\
                                      \x54\x4c\x4d\x53\x53\x50\x00\x02\x00\x00\x00\x16\x00\x16\x00\x38\
                                      \x00\x00\x00\x15\x82\x8a\x62\x8d\x51\x0b\x30\x2d\x45\x71\xe0\x00\
                                      \x00\x00\x00\x00\x00\x00\x00\x64\x00\x64\x00\x4e\x00\x00\x00\x06\
                                      \x01\x00\x00\x00\x00\x00\x0f\x52\x00\x41\x00\x53\x00\x50\x00\x42\
                                      \x00\x45\x00\x52\x00\x52\x00\x59\x00\x50\x00\x49\x00\x02\x00\x16\
                                      \x00\x52\x00\x41\x00\x53\x00\x50\x00\x42\x00\x45\x00\x52\x00\x52\
                                      \x00\x59\x00\x50\x00\x49\x00\x01\x00\x16\x00\x52\x00\x41\x00\x53\
                                      \x00\x50\x00\x42\x00\x45\x00\x52\x00\x52\x00\x59\x00\x50\x00\x49\
                                      \x00\x04\x00\x02\x00\x00\x00\x03\x00\x16\x00\x72\x00\x61\x00\x73\
                                      \x00\x70\x00\x62\x00\x65\x00\x72\x00\x72\x00\x79\x00\x70\x00\x69\
                                      \x00\x07\x00\x08\x00\x60\x16\xad\x6d\x47\x21\xd7\x01\x00\x00\x00\
                                      \x00".to_vec();

            let mut first_target = AvPair::default();
            first_target.av_id = Some(AvId::MsvAvNbDomainName);
            first_target.av_len = b"\x16\x00".to_vec();
            first_target.value = b"\x52\x00\x41\x00\x53\x00\x50\x00\x42\x00\x45\
                                   \x00\x52\x00\x52\x00\x59\x00\x50\x00\x49\x00"
                .to_vec();
            let mut second_target = AvPair::default();
            second_target.av_id = Some(AvId::MsvAvNbComputerName);
            second_target.av_len = first_target.av_len.clone();
            second_target.value = first_target.value.clone();

            let mut third_target = AvPair::default();
            third_target.av_id = Some(AvId::MsvAvDnsDomainName);
            third_target.av_len = b"\x02\x00".to_vec();
            third_target.value = b"\x00\x00".to_vec();

            let mut fourth_target = AvPair::default();
            fourth_target.av_id = Some(AvId::MsvAvDnsComputerName);
            fourth_target.av_len = first_target.av_len.clone();
            fourth_target.value = b"\x72\x00\x61\x00\x73\x00\x70\x00\x62\x00\x65\
                                    \x00\x72\x00\x72\x00\x79\x00\x70\x00\x69\x00"
                .to_vec();

            let mut fifth_target = AvPair::default();
            fifth_target.av_id = Some(AvId::MsvAvTimeStamp);
            fifth_target.av_len = b"\x08\x00".to_vec();
            fifth_target.value = b"\x60\x16\xad\x6d\x47\x21\xd7\x01".to_vec();

            let mut sixth_target = AvPair::default();
            sixth_target.av_id = Some(AvId::MsvAvEOL);
            sixth_target.av_len = b"\x00\x00".to_vec();

            Setup {
                complete_byte_code: byte_code.clone(),
                ntlm_byte_code: byte_code[31..].to_vec(),
                target_info: vec![
                    first_target,
                    second_target,
                    third_target,
                    fourth_target,
                    fifth_target,
                    sixth_target,
                ],
            }
        }
    }

    #[test]
    fn test_decode_security_response() {
        let setup = Setup::new();

        let mut header = ntlmssp::Header::default();
        let mut challenge = Challenge::default();

        challenge.target_name_fields.target_name_len = b"\x16\x00".to_vec();
        challenge.target_name_fields.target_name_max_len = b"\x16\x00".to_vec();
        challenge.target_name_fields.target_name_buffer_offset = b"\x38\x00\x00\x00".to_vec();

        challenge.negotiate_flags = b"\x15\x82\x8a\x62".to_vec();
        challenge.server_challenge = b"\x8d\x51\x0b\x30\x2d\x45\x71\xe0".to_vec();

        challenge.target_info_fields.target_info_len = b"\x64\x00".to_vec();
        challenge.target_info_fields.target_info_max_len = b"\x64\x00".to_vec();
        challenge.target_info_fields.target_info_buffer_offset = b"\x4e\x00\x00\x00".to_vec();

        challenge.version.product_major_version = b"\x06".to_vec();
        challenge.version.product_minor_version = b"\x01".to_vec();
        challenge.version.product_build = b"\x00\x00".to_vec();
        challenge.version.ntlm_revision_current = b"\x0f".to_vec();

        challenge.payload.target_name = b"\x52\x00\x41\x00\x53\x00\x50\x00\x42\x00\x45\
                                          \x00\x52\x00\x52\x00\x59\x00\x50\x00\x49\x00"
            .to_vec();
        challenge.payload.target_info = setup.target_info;

        let message_type = MessageType::Challenge(challenge);
        header.message_type = message_type.unpack_byte_code();
        header.message = Some(message_type);

        assert_eq!(header, decode_security_response(setup.complete_byte_code));
    }

    #[test]
    fn test_decode_target_info() {
        let setup = Setup::new();

        assert_eq!(
            setup.target_info,
            decode_target_info(setup.ntlm_byte_code, 78, 178)
        );
    }
}
