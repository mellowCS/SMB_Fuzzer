use crate::smb2::requests::tree_connect::TreeConnect;

/// Serializes a tree connect request from the corresponding struct.
pub fn serialize_tree_connect_request_body(request: &TreeConnect) -> Vec<u8> {
    let mut serialized_request: Vec<u8> = Vec::new();

    serialized_request.append(&mut request.structure_size.clone());
    serialized_request.append(&mut request.flags.clone());
    serialized_request.append(&mut request.path_offset.clone());
    serialized_request.append(&mut request.path_length.clone());
    serialized_request.append(&mut request.buffer.clone());

    serialized_request
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_tree_connect_request_body() {
        let mut tree_connect = TreeConnect::default();
        tree_connect.flags = vec![0; 2];
        tree_connect.path_offset = b"\x48\x00".to_vec();
        tree_connect.path_length = b"\x2a\x00".to_vec();
        tree_connect.buffer = b"\x5c\x00\x5c\x00\x31\x00\x39\x00\x32\x00\x2e\x00\x31\x00\x36\x00\
                            \x38\x00\x2e\x00\x30\x00\x2e\x00\x31\x00\x37\x00\x31\x00\x5c\x00\
                            \x73\x00\x68\x00\x61\x00\x72\x00\x65\x00"
            .to_vec();

        let expected_byte_array = b"\x09\x00\x00\x00\x48\x00\x2a\x00\x5c\x00\x5c\x00\x31\x00\x39\x00\
                                            \x32\x00\x2e\x00\x31\x00\x36\x00\x38\x00\x2e\x00\x30\x00\x2e\x00\
                                            \x31\x00\x37\x00\x31\x00\x5c\x00\x73\x00\x68\x00\x61\x00\x72\x00\
                                            \x65\x00".to_vec();

        assert_eq!(
            expected_byte_array,
            serialize_tree_connect_request_body(&tree_connect)
        );
    }
}
