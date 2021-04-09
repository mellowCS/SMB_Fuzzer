use crate::smb2::requests::echo::Echo;

/// Serializes the echo request body.
pub fn serialize_serialize_echo_request_body(request: &Echo) -> Vec<u8> {
    let mut serialized_request: Vec<u8> = Vec::new();

    serialized_request.append(&mut request.structure_size.clone());
    serialized_request.append(&mut request.reserved.clone());

    serialized_request
}
