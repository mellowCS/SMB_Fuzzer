use self::{
    close_encoder::serialize_close_request_body, create_encoder::serialize_create_request_body,
    echo_encoder::serialize_serialize_echo_request_body,
    negotiate_encoder::serialize_negotiate_request_body,
    query_info_encoder::serialize_query_info_request_body,
    session_setup_encoder::serialize_session_setup_request_body,
    tree_connect_encoder::serialize_tree_connect_request_body,
};

use crate::smb2::{
    header::{GenericHeader, SyncHeader},
    requests::RequestType,
};

pub mod close_encoder;
pub mod create_encoder;
pub mod echo_encoder;
pub mod negotiate_encoder;
pub mod query_info_encoder;
pub mod security_blob_encoder;
pub mod session_setup_encoder;
pub mod tree_connect_encoder;

/// Serializes the netbios session prefix by calculating the packet size.
pub fn serialize_netbios_session_prefix(packet_size: usize) -> Vec<u8> {
    let mut byte_size = packet_size.to_le_bytes().to_vec();
    byte_size.truncate(3);
    byte_size.reverse();
    let mut prefix: Vec<u8> = vec![0];
    prefix.append(&mut byte_size);

    prefix
}

/// Serializes the complete negotiate request.
pub fn serialize_request(header: &SyncHeader, body: &RequestType) -> Vec<u8> {
    let mut packet = serialize_sync_header(header);

    packet.append(&mut match body {
        RequestType::Negotiate(negotiate) => serialize_negotiate_request_body(&negotiate),
        RequestType::SessionSetup(session_setup) => {
            serialize_session_setup_request_body(&session_setup)
        }
        RequestType::TreeConnect(tree_connect) => {
            serialize_tree_connect_request_body(&tree_connect)
        }
        RequestType::Create(create) => serialize_create_request_body(&create),
        RequestType::QueryInfo(query_info) => serialize_query_info_request_body(query_info),
        RequestType::Close(close) => serialize_close_request_body(&close),
        RequestType::Echo(echo) => serialize_serialize_echo_request_body(&echo),
    });

    let mut request = serialize_netbios_session_prefix(packet.len());
    request.append(&mut packet);

    request
}

/// Serializes the generic part of the SMB header.
pub fn serialize_generic_header(header: &GenericHeader) -> Vec<u8> {
    let mut serialized_header: Vec<u8> = Vec::new();

    serialized_header.append(&mut header.protocol_id.clone());
    serialized_header.append(&mut header.structure_size.clone());
    serialized_header.append(&mut header.credit_charge.clone());
    serialized_header.append(&mut header.channel_sequence.clone());
    serialized_header.append(&mut header.reserved.clone());
    serialized_header.append(&mut header.command.clone());
    serialized_header.append(&mut header.credit.clone());
    serialized_header.append(&mut header.flags.clone());
    serialized_header.append(&mut header.next_command.clone());
    serialized_header.append(&mut header.message_id.clone());

    serialized_header
}

/// Serializes the sync variant of the SMB header.
pub fn serialize_sync_header(header: &SyncHeader) -> Vec<u8> {
    let mut serialized_header: Vec<u8> = Vec::new();

    serialized_header.append(&mut serialize_generic_header(&header.generic));
    serialized_header.append(&mut header.reserved.clone());
    serialized_header.append(&mut header.tree_id.clone());
    serialized_header.append(&mut header.session_id.clone());
    serialized_header.append(&mut header.signature.clone());

    serialized_header
}

#[cfg(test)]
mod tests {

    use crate::smb2::header::Commands;

    use super::*;

    struct Setup {
        generic_header: GenericHeader,
    }

    impl Setup {
        pub fn new() -> Self {
            let mut generic_header = GenericHeader::default();
            generic_header.protocol_id = b"\xfe\x53\x4d\x42".to_vec();
            generic_header.structure_size = b"\x40\x00".to_vec();
            generic_header.credit_charge = b"\x01\x00".to_vec();
            generic_header.channel_sequence = vec![0; 2];
            generic_header.reserved = vec![0; 2];
            generic_header.command = Commands::Negotiate.unpack_byte_code();
            generic_header.credit = vec![0; 2];
            generic_header.flags = vec![0; 4];
            generic_header.next_command = vec![0; 4];
            generic_header.message_id = vec![0; 8];

            Setup { generic_header }
        }
    }

    #[test]
    fn test_serialize_netbios_session_prefix() {
        assert_eq!(vec![0, 0, 0, 234], serialize_netbios_session_prefix(234));
    }

    #[test]
    fn test_serialize_generic_header() {
        let setup = Setup::new();

        let mut expected_byte_array: Vec<u8> = b"\xfe\x53\x4d\x42\x40\x00\x01\x00".to_vec();
        expected_byte_array.append(&mut vec![0; 24]);
        let serialized_header = serialize_generic_header(&setup.generic_header);

        assert_eq!(expected_byte_array, serialized_header);
    }

    #[test]
    fn test_serialize_sync_header() {
        let setup = Setup::new();
        let mut sync_header = SyncHeader::default();
        sync_header.generic = setup.generic_header;
        sync_header.tree_id = vec![0; 4];
        sync_header.session_id = vec![0; 8];
        sync_header.signature = vec![0; 16];

        let mut expected_byte_array: Vec<u8> = b"\xfe\x53\x4d\x42\x40\x00\x01\x00".to_vec();
        expected_byte_array.append(&mut vec![0; 56]);

        assert_eq!(expected_byte_array, serialize_sync_header(&sync_header));
    }
}
