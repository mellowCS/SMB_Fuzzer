use std::net::TcpStream;

use crate::{
    format::{
        self,
        decoder::{create_decoder::decode_create_response_body, decode_response_header},
    },
    smb2::responses::session_setup::SessionSetup,
};

use super::connect;

/// Sends a negotiate message to the server, entering the protocol
/// state after the negotiate response.
pub fn go_to_negotiate_state(stream: &mut TcpStream) {
    connect::send_negotiate(stream, None);
}

/// Sends the first session setup message to the server, entering the protocol
/// state after the first session setup response.
/// Returns the session id.
pub fn go_to_session_setup_1_state(stream: &mut TcpStream) -> (SessionSetup, Vec<u8>) {
    go_to_negotiate_state(stream);
    let response = connect::send_session_setup_1_request_and_get_response(stream, None);
    let (response_header, session_setup_response_body) =
        format::decoder::decode_session_setup_response(response.to_vec());

    (session_setup_response_body, response_header.session_id)
}

/// Sends the second session setup message to the server, entering the protocol
/// state after the second session setup response.
/// Returns the newly created session id.
pub fn go_to_session_setup_2_state(stream: &mut TcpStream) -> Vec<u8> {
    let (session_setup_response_body, session_id) = go_to_session_setup_1_state(stream);
    connect::send_session_setup_2_request(
        stream,
        session_setup_response_body,
        session_id.clone(),
        None,
    );

    session_id
}

/// Sends the tree connect message to the server, entering the protocol
/// state after the tree connect response
/// Returns session and newly created tree id.
pub fn go_to_tree_connect_state(stream: &mut TcpStream) -> (Vec<u8>, Vec<u8>) {
    let session_id = go_to_session_setup_2_state(stream);
    let tree_connect_response =
        connect::send_tree_connect_request_and_get_response(stream, session_id.clone(), None);
    (
        session_id,
        decode_response_header(tree_connect_response[4..68].to_vec()).tree_id,
    )
}

/// Sends the create message to the server, entering the protocol
/// state after the create response and after the file has been opened/created.
/// Returns the session, tree and newly created file id.
pub fn go_to_create_state(stream: &mut TcpStream) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (session_id, tree_id) = go_to_tree_connect_state(stream);
    let create_response = connect::send_create_request_and_get_response(
        stream,
        session_id.clone(),
        tree_id.clone(),
        None,
    );

    (
        session_id,
        tree_id,
        decode_create_response_body(create_response[68..].to_vec()).file_id,
    )
}
