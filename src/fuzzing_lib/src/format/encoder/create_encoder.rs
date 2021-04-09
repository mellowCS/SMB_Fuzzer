use crate::smb2::requests::create::Create;

/// Serializes the create request body.
pub fn serialize_create_request_body(request: &Create) -> Vec<u8> {
    let mut serialized_request: Vec<u8> = Vec::new();

    serialized_request.append(&mut request.structure_size.clone());
    serialized_request.append(&mut request.security_flag.clone());
    serialized_request.append(&mut request.requested_oplock_level.clone());
    serialized_request.append(&mut request.impersonation_level.clone());
    serialized_request.append(&mut request.smb_create_flags.clone());
    serialized_request.append(&mut request.reserved.clone());
    serialized_request.append(&mut request.desired_access.clone());
    serialized_request.append(&mut request.file_attributes.clone());
    serialized_request.append(&mut request.share_access.clone());
    serialized_request.append(&mut request.create_disposition.clone());
    serialized_request.append(&mut request.create_options.clone());
    serialized_request.append(&mut request.name_offset.clone());
    serialized_request.append(&mut request.name_length.clone());
    serialized_request.append(&mut request.create_contexts_offset.clone());
    serialized_request.append(&mut request.create_contexts_length.clone());
    serialized_request.append(&mut request.buffer.clone());

    serialized_request
}
