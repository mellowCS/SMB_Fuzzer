use crate::smb2::requests::query_info::QueryInfo;

/// Serializes a query info request from the corresponding struct.
pub fn serialize_query_info_request_body(request: &QueryInfo) -> Vec<u8> {
    let mut serialized_request: Vec<u8> = Vec::new();

    serialized_request.append(&mut request.structure_size.clone());
    serialized_request.append(&mut request.info_type.clone());
    serialized_request.append(&mut request.file_info_class.clone());
    serialized_request.append(&mut request.output_buffer_length.clone());
    serialized_request.append(&mut request.input_buffer_offset.clone());
    serialized_request.append(&mut request.reserved.clone());
    serialized_request.append(&mut request.input_buffer_length.clone());

    serialized_request.append(&mut request.additional_information.clone());
    serialized_request.append(&mut request.file_full_ea_name_information.clone());
    serialized_request.append(&mut request.flags.clone());
    serialized_request.append(&mut request.file_id.clone());
    serialized_request.append(&mut request.buffer.clone());

    serialized_request
}
