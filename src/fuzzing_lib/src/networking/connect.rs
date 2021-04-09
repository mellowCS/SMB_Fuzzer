//! This module establishes a direct TCP connection between client and host over port 445.
//! It also performs the SMB handshake.

use std::net::TcpStream;
use std::{
    io::{Read, Write},
    time::Duration,
};

use super::state_transition_engine::State;

use crate::fuzzer::FuzzingStrategy;

use super::packets;
use crate::smb2::responses;

pub fn go_to_session_setup_negotiate_state_and_fuzz_session_setup_2() {
    match TcpStream::connect("192.168.0.171:445") {
        Ok(mut stream) => {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("Failed to set read time out.");
            println!("Successfully connected to server in port 445.");

            let (response_body, session_id) =
                State::go_to_session_setup_negotiate_state(&mut stream);
            send_session_setup_authenticate_request(
                &mut stream,
                response_body,
                session_id,
                Some(FuzzingStrategy::Predefined),
            );
        }
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Terminated.");
}

pub fn go_to_session_setup_authenticate_state_and_fuzz_tree_connect() {
    match TcpStream::connect("192.168.0.171:445") {
        Ok(mut stream) => {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("Failed to set read time out.");
            println!("Successfully connected to server in port 445.");

            let session_id = State::go_to_session_setup_authenticate_state(&mut stream);

            send_tree_connect_request_and_get_response(
                &mut stream,
                session_id,
                Some(FuzzingStrategy::Predefined),
            );
        }
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Terminated.");
}

pub fn go_to_tree_connect_state_and_fuzz_create() {
    match TcpStream::connect("192.168.0.171:445") {
        Ok(mut stream) => {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("Failed to set read time out.");
            println!("Successfully connected to server in port 445.");

            let (session_id, tree_id) = State::go_to_tree_connect_state(&mut stream);

            send_create_request_and_get_response(
                &mut stream,
                session_id,
                tree_id,
                Some(FuzzingStrategy::Predefined),
            );
        }
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Terminated.");
}

pub fn go_to_create_state_and_fuzz_query_info() {
    match TcpStream::connect("192.168.0.171:445") {
        Ok(mut stream) => {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("Failed to set read time out.");
            println!("Successfully connected to server in port 445.");

            let (session_id, tree_id, file_id) = State::go_to_create_state(&mut stream);

            send_query_info_request(
                &mut stream,
                session_id,
                tree_id,
                file_id,
                Some(FuzzingStrategy::Predefined),
            );
        }
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Terminated.");
}

/// Sends a negotiate request to the server.
pub fn send_negotiate(stream: &mut TcpStream, fuzzing_strategy: Option<FuzzingStrategy>) {
    let negotiate_request: Vec<u8> = packets::prepare_negotiate_packet(fuzzing_strategy);

    if stream.write_all(&negotiate_request[..]).is_err() {
        println!("Negotiate State Reset");
    } else {
        let mut buffer: [u8; 300] = [0; 300];
        match stream.read(&mut buffer) {
            Ok(_) => (),
            Err(e) => {
                println!("Failed to receive Negotiate response: {}", e);
            }
        }
    };
}

/// Sends a session setup 1 request and returns the server response.
pub fn send_session_setup_negotiate_request_and_get_response(
    stream: &mut TcpStream,
    fuzzing_strategy: Option<FuzzingStrategy>,
) -> [u8; 300] {
    let mut buffer: [u8; 300] = [0; 300];
    let session_setup_request_1 = packets::prepare_session_setup_negotiate_packet(fuzzing_strategy);

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
pub fn send_session_setup_authenticate_request(
    stream: &mut TcpStream,
    session_setup_response_body: responses::session_setup::SessionSetup,
    session_id: Vec<u8>,
    fuzzing_strategy: Option<FuzzingStrategy>,
) {
    let mut buffer: [u8; 300] = [0; 300];

    let session_setup_request_2 = packets::prepare_session_setup_authenticate_packet(
        fuzzing_strategy,
        session_id,
        session_setup_response_body,
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
    session_id: Vec<u8>,
    fuzzing_strategy: Option<FuzzingStrategy>,
) -> [u8; 300] {
    let mut buffer: [u8; 300] = [0; 300];

    let tree_connect_request = packets::prepare_tree_connect_packet(fuzzing_strategy, session_id);

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
    session_id: Vec<u8>,
    tree_id: Vec<u8>,
    fuzzing_strategy: Option<FuzzingStrategy>,
) -> [u8; 300] {
    let mut buffer: [u8; 300] = [0; 300];
    let create_request = packets::prepare_create_packet(fuzzing_strategy, session_id, tree_id);

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
    session_id: Vec<u8>,
    tree_id: Vec<u8>,
    file_id: Vec<u8>,
    fuzzing_strategy: Option<FuzzingStrategy>,
) {
    let mut buffer: [u8; 300] = [0; 300];
    let query_info_request =
        packets::prepare_query_info_packet(fuzzing_strategy, session_id, tree_id, file_id);

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
pub fn send_echo_request(stream: &mut TcpStream, fuzzing_strategy: Option<FuzzingStrategy>) {
    let mut buffer: [u8; 300] = [0; 300];
    let echo_request = packets::prepare_echo_packet(fuzzing_strategy);

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
    session_id: Vec<u8>,
    tree_id: Vec<u8>,
    file_id: Vec<u8>,
    fuzzing_strategy: Option<FuzzingStrategy>,
) {
    let mut buffer: [u8; 300] = [0; 300];

    let close_request =
        packets::prepare_close_packet(fuzzing_strategy, session_id, tree_id, file_id);

    stream.write_all(&close_request[..]).unwrap();
    println!("Sent Close request, awaiting reply...");
    match stream.read(&mut buffer) {
        Ok(_) => println!("Successfully received Close response from server."),
        Err(e) => {
            println!("Failed to receive Close response: {}", e);
        }
    }
}
