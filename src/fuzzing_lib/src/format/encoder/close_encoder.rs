use crate::smb2::requests::close::Close;

/// Serializes the create request body.
pub fn serialize_close_request_body(request: &Close) -> Vec<u8> {
    let mut serialized_request: Vec<u8> = Vec::new();

    serialized_request.append(&mut request.structure_size.clone());
    serialized_request.append(&mut request.flags.clone());
    serialized_request.append(&mut request.reserved.clone());
    serialized_request.append(&mut request.file_id.clone());

    serialized_request
}
