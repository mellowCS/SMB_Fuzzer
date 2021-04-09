use std::net::TcpStream;

use crate::{
    format::{
        self,
        decoder::{create_decoder::decode_create_response_body, decode_response_header},
    },
    smb2::responses::session_setup::SessionSetup,
};

use super::connect;

/// The State Enum represents the implemented states the SMB fuzzer can reach.
/// The Negotiate, SessionSetupNeg, SessionSetupAuth and TreeConnect state are part of the SMB handshake.
/// The remaining states are reached after a successful handshake.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum State {
    Initial,
    Negotiate,
    SessionSetupNeg,
    SessionSetupAuth,
    TreeConnect,
    Create,
    Close,
}

pub enum ResponseType {
    Initial,
    Negotiate,
    SessionSetupNeg((SessionSetup, Vec<u8>)),
    SessionSetupAuth(Vec<u8>),
    TreeConnect((Vec<u8>, Vec<u8>)),
    Create((Vec<u8>, Vec<u8>, Vec<u8>)),
    Close((Vec<u8>, Vec<u8>)),
}

impl State {
    /// Maps a user input string to a state.
    pub fn map_string_to_state(state: &str) -> Self {
        match state {
            "-init_state" => State::Initial,
            "-neg_state" => State::Negotiate,
            "-session_setup_neg_state" => State::SessionSetupNeg,
            "-session_setup_auth_state" => State::SessionSetupAuth,
            "-tree_state" => State::TreeConnect,
            "-create_state" => State::Create,
            "-close_state" => State::Close,
            _ => panic!("Invalid state."),
        }
    }

    /// Goes to the state specified by the state enum and returns a payload if needed.
    pub fn go_to_state(&self, stream: &mut TcpStream) -> ResponseType {
        match self {
            State::Initial => ResponseType::Initial,
            State::Negotiate => {
                Self::go_to_negotiate_state(stream);
                ResponseType::Negotiate
            }
            State::SessionSetupNeg => {
                ResponseType::SessionSetupNeg(Self::go_to_session_setup_negotiate_state(stream))
            }
            State::SessionSetupAuth => {
                ResponseType::SessionSetupAuth(Self::go_to_session_setup_authenticate_state(stream))
            }
            State::TreeConnect => ResponseType::TreeConnect(Self::go_to_tree_connect_state(stream)),
            State::Create => ResponseType::Create(Self::go_to_create_state(stream)),
            State::Close => ResponseType::Close(Self::go_to_close_state(stream)),
        }
    }

    /// Sends a negotiate message to the server, entering the protocol
    /// state after the negotiate response.
    pub fn go_to_negotiate_state(stream: &mut TcpStream) {
        connect::send_negotiate(stream, None);
    }

    /// Sends the first session setup message to the server, entering the protocol
    /// state after the first session setup response.
    /// Returns the session id.
    pub fn go_to_session_setup_negotiate_state(stream: &mut TcpStream) -> (SessionSetup, Vec<u8>) {
        Self::go_to_negotiate_state(stream);
        let response = connect::send_session_setup_negotiate_request_and_get_response(stream, None);
        let (response_header, session_setup_response_body) =
            format::decoder::decode_session_setup_response(response.to_vec());

        (session_setup_response_body, response_header.session_id)
    }

    /// Sends the second session setup message to the server, entering the protocol
    /// state after the second session setup response.
    /// Returns the newly created session id.
    pub fn go_to_session_setup_authenticate_state(stream: &mut TcpStream) -> Vec<u8> {
        let (session_setup_response_body, session_id) =
            Self::go_to_session_setup_negotiate_state(stream);
        connect::send_session_setup_authenticate_request(
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
        let session_id = Self::go_to_session_setup_authenticate_state(stream);
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
        let (session_id, tree_id) = Self::go_to_tree_connect_state(stream);
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

    /// Sends the close message to the server, entering the protocol
    /// state after the close response and after the file has been closed.
    /// Returns the session and tree id
    pub fn go_to_close_state(stream: &mut TcpStream) -> (Vec<u8>, Vec<u8>) {
        let (session_id, tree_id, file_id) = Self::go_to_create_state(stream);
        connect::send_close_request(stream, session_id.clone(), tree_id.clone(), file_id, None);
        (session_id, tree_id)
    }
}
