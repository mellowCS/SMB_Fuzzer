//! This module establishes a direct TCP connection between client and host over port 445.
//! It also performs the SMB handshake.

use std::net::TcpStream;
use std::{
    io::{Read, Write},
    time::Duration,
};

use builder::{
    build_close_request, build_default_echo_request, create_request::build_default_create_request,
    query_info_request::build_default_query_info_request,
    session_setup_1_request::build_default_session_setup_1_request,
    session_setup_2_request::build_default_session_setup_2_request,
    tree_connect_request::build_default_tree_connect_request,
};
use format::{
    decoder::{
        create_decoder::decode_create_response_body, decode_response_header,
        security_blob_decoder::decode_security_response,
    },
    encoder::serialize_request,
};

use crate::builder;
use crate::ntlmssp::MessageType;
use crate::smb2::requests::RequestType;
use crate::{format, smb2::responses};

pub fn connect_to_port_445_via_tcp() {
    match TcpStream::connect("192.168.0.171:445") {
        Ok(mut stream) => {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("Failed to set read time out.");
            println!("Successfully connected to server in port 445.");

            send_negotiate(&mut stream);
            let mut buffer = send_session_setup_1_request_and_get_response(&mut stream);

            let (response_header, session_setup_response_body) =
                format::decoder::decode_session_setup_response(buffer.to_vec());

            let chosen_session_id = response_header.session_id;

            send_session_setup_2_request(
                &mut stream,
                session_setup_response_body,
                chosen_session_id.clone(),
            );

            buffer =
                send_tree_connect_request_and_get_response(&mut stream, chosen_session_id.clone());

            let tree_connect_response_header = decode_response_header(buffer[4..68].to_vec());
            let chosen_tree_id = tree_connect_response_header.tree_id;

            buffer = send_create_request_and_get_response(
                &mut stream,
                chosen_session_id.clone(),
                chosen_tree_id.clone(),
            );

            let create_response_body = decode_create_response_body(buffer[68..].to_vec());
            let chosen_file_id = create_response_body.file_id;

            send_query_info_request(
                &mut stream,
                chosen_session_id.clone(),
                chosen_tree_id.clone(),
                chosen_file_id.clone(),
            );

            send_echo_request(&mut stream);

            send_close_request(
                &mut stream,
                chosen_session_id,
                chosen_tree_id,
                chosen_file_id,
            );
        }
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Terminated.");
}

/// Sends a negotiate request to the server.
pub fn send_negotiate(stream: &mut TcpStream) {
    let mut buffer: [u8; 300] = [0; 300];
    let (negotiate_header, neg_request) =
        builder::negotiate_request::build_default_negotiate_request();
    let negotiate_request =
        format::encoder::serialize_request(&negotiate_header, &RequestType::Negotiate(neg_request));

    stream.write_all(&negotiate_request[..]).unwrap();
    println!("Sent Negotiate Request, awaiting reply...");
    match stream.read(&mut buffer) {
        Ok(_) => println!("Successfully received negotiate response from server."),
        Err(e) => {
            println!("Failed to receive negotiate response: {}", e);
        }
    }
}

/// Sends a session setup 1 request and returns the server response.
pub fn send_session_setup_1_request_and_get_response(stream: &mut TcpStream) -> [u8; 300] {
    let mut buffer: [u8; 300] = [0; 300];
    let (session_setup_header_1, sesh_request_1) = build_default_session_setup_1_request();
    let session_setup_request_1 = format::encoder::serialize_request(
        &session_setup_header_1,
        &RequestType::SessionSetup(sesh_request_1),
    );

    stream.write_all(&session_setup_request_1[..]).unwrap();
    println!("Sent Session Setup Request 1, awaiting reply...");
    match stream.read(&mut buffer) {
        Ok(_) => println!("Successfully received session setup response 1 from server."),
        Err(e) => {
            println!("Failed to receive session setup response: {}", e);
        }
    }

    buffer
}

/// Sends a session setup 2 request.
pub fn send_session_setup_2_request(
    stream: &mut TcpStream,
    session_setup_response_body: responses::session_setup::SessionSetup,
    chosen_session_id: Vec<u8>,
) {
    let mut buffer: [u8; 300] = [0; 300];
    let challenge_struct = match decode_security_response(session_setup_response_body.buffer)
        .message
        .unwrap()
    {
        MessageType::Challenge(challenge) => challenge,
        _ => panic!("Invalid message type in server response."),
    };

    let (session_setup_2_request_header, session_setup_2_request_body) =
        build_default_session_setup_2_request(chosen_session_id, challenge_struct);

    let session_setup_request_2 = serialize_request(
        &session_setup_2_request_header,
        &RequestType::SessionSetup(session_setup_2_request_body),
    );

    stream.write_all(&session_setup_request_2[..]).unwrap();
    println!("Sent Session Setup Request 2, awaiting reply...");
    match stream.read(&mut buffer) {
        Ok(_) => println!("Successfully received session setup response 2 from server."),
        Err(e) => {
            println!("Failed to receive session setup 2 response: {}", e);
        }
    }
}

/// Sends a tree connect request and returns the server response.
pub fn send_tree_connect_request_and_get_response(
    stream: &mut TcpStream,
    chosen_session_id: Vec<u8>,
) -> [u8; 300] {
    let mut buffer: [u8; 300] = [0; 300];
    let (tree_connect_header, tree_connect_request_body) =
        build_default_tree_connect_request(chosen_session_id);

    let tree_connect_request = serialize_request(
        &tree_connect_header,
        &RequestType::TreeConnect(tree_connect_request_body),
    );

    stream.write_all(&tree_connect_request[..]).unwrap();
    println!("Sent Tree Connect request, awaiting reply...");
    match stream.read(&mut buffer) {
        Ok(_) => println!("Successfully received Tree Connect response from server."),
        Err(e) => {
            println!("Failed to receive Tree Connect response: {}", e);
        }
    }

    buffer
}

/// Sends a create request and returns the server response.
pub fn send_create_request_and_get_response(
    stream: &mut TcpStream,
    chosen_session_id: Vec<u8>,
    chosen_tree_id: Vec<u8>,
) -> [u8; 300] {
    let mut buffer: [u8; 300] = [0; 300];
    let (create_request_header, create_request_body) =
        build_default_create_request(chosen_tree_id, chosen_session_id);
    let create_request = serialize_request(
        &create_request_header,
        &RequestType::Create(create_request_body),
    );

    stream.write_all(&create_request[..]).unwrap();
    println!("Sent Create request, awaiting reply...");
    match stream.read(&mut buffer) {
        Ok(_) => println!("Successfully received Create response from server."),
        Err(e) => {
            println!("Failed to receive Create response: {}", e);
        }
    }

    buffer
}

/// Sends a query info request.
pub fn send_query_info_request(
    stream: &mut TcpStream,
    chosen_session_id: Vec<u8>,
    chosen_tree_id: Vec<u8>,
    chosen_file_id: Vec<u8>,
) {
    let mut buffer: [u8; 300] = [0; 300];
    let (query_info_request_header, query_info_request_body) =
        build_default_query_info_request(chosen_tree_id, chosen_session_id, chosen_file_id);
    let query_info_request = serialize_request(
        &query_info_request_header,
        &RequestType::QueryInfo(query_info_request_body),
    );

    stream.write_all(&query_info_request[..]).unwrap();
    println!("Sent Query Info request, awaiting reply...");
    match stream.read(&mut buffer) {
        Ok(_) => println!("Successfully received Query Info response from server."),
        Err(e) => {
            println!("Failed to receive Query Info response: {}", e);
        }
    }
}

/// Sends an echo request.
pub fn send_echo_request(stream: &mut TcpStream) {
    let mut buffer: [u8; 300] = [0; 300];
    let (echo_request_header, echo_request_body) = build_default_echo_request();
    let echo_request =
        serialize_request(&echo_request_header, &RequestType::Echo(echo_request_body));

    stream.write_all(&echo_request[..]).unwrap();
    println!("Sent Echo request, awaiting reply...");
    match stream.read(&mut buffer) {
        Ok(_) => println!("Successfully received Echo response from server."),
        Err(e) => {
            println!("Failed to receive Echo response: {}", e);
        }
    }
}

/// Sends a close request.
pub fn send_close_request(
    stream: &mut TcpStream,
    chosen_session_id: Vec<u8>,
    chosen_tree_id: Vec<u8>,
    chosen_file_id: Vec<u8>,
) {
    let mut buffer: [u8; 300] = [0; 300];
    let (close_request_header, close_request_body) =
        build_close_request(chosen_tree_id, chosen_session_id, chosen_file_id);

    let close_request = serialize_request(
        &close_request_header,
        &RequestType::Close(close_request_body),
    );

    stream.write_all(&close_request[..]).unwrap();
    println!("Sent Close request, awaiting reply...");
    match stream.read(&mut buffer) {
        Ok(_) => println!("Successfully received Close response from server."),
        Err(e) => {
            println!("Failed to receive Close response: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection() {
        connect_to_port_445_via_tcp();
    }
}
