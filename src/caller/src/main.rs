//! This module will call the fuzzer with a desired fuzzing strategy.
//! The fuzzing lib provides the needed functionality to create and initiate a fuzzing directive.
//! A fuzzing directive includes the  message to be fuzzed (e.g. negotiate, session setup, create etc.),
//! the state in which the message is to be sent, the number of iterations of the fuzzing process,
//! and finally, the fuzzing strategy to be used.

use std::env;
use std::net::TcpStream;
use std::{
    io::{Error, Write},
    thread::sleep,
};

use fuzzing_lib::{
    fuzzer::{FuzzingDirective, FuzzingStrategy},
    networking::{
        packets,
        state_transition_engine::{ResponseType, State},
    },
    smb2::requests::RequestType,
};

pub fn main() {
    let args: Vec<String> = env::args().collect();
    check_args(&args);
    let fuzzing_directive = map_input_to_fuzzing_directive(args);

    if !correct_message_for_state(&fuzzing_directive) {
        panic!("Invalid message for desired state.");
    }

    execute_fuzzing_process(fuzzing_directive, "192.168.0.171", "445");
}

/// Checks whether the passed user input is valid.
pub fn check_args(args: &[String]) {
    if args.len() == 2 {
        match args[1].as_str() {
            "-h" | "--help" => print_help(),
            _ => panic!(
                "Invalid or missing parameters. Check Help by calling cargo run -- -h/--help. "
            ),
        }
    } else if args.len() < 4 {
        panic!("Missing parameters. Check Help by calling cargo run -- -h/--help.");
    }
}

/// Maps the string input to a fuzzing directive.
pub fn map_input_to_fuzzing_directive(args: Vec<String>) -> FuzzingDirective {
    let mut fuzzing_directive = FuzzingDirective::default();

    fuzzing_directive.message = Some(RequestType::map_string_to_request_type(&args[1]));
    fuzzing_directive.fuzzing_strategy =
        Some(FuzzingStrategy::map_string_to_fuzzing_strategy(&args[2]));
    fuzzing_directive.state = Some(State::map_string_to_state(&args[3]));

    fuzzing_directive
}

/// Checks whether the message to be fuzzed is the correct one for the state.
/// In later versions this won't be needed as the tool will enable to fuzz each
/// message in each state.
pub fn correct_message_for_state(directive: &FuzzingDirective) -> bool {
    if let Some(message) = directive.message.as_ref() {
        if let Some(state) = directive.state.as_ref() {
            match state {
                State::Initial => {
                    if let RequestType::Negotiate(_) | RequestType::Echo(_) = message {
                        return true;
                    }
                }
                State::Negotiate => {
                    if let RequestType::SessionSetupNeg(_) | RequestType::Echo(_) = message {
                        return true;
                    }
                }
                State::SessionSetupNeg => {
                    if let RequestType::SessionSetupAuth(_) | RequestType::Echo(_) = message {
                        return true;
                    }
                }
                State::SessionSetupAuth => {
                    if let RequestType::TreeConnect(_) | RequestType::Echo(_) = message {
                        return true;
                    }
                }
                State::TreeConnect => {
                    if let RequestType::Create(_) | RequestType::Echo(_) = message {
                        return true;
                    }
                }
                State::Create => {
                    if let RequestType::QueryInfo(_)
                    | RequestType::Close(_)
                    | RequestType::Echo(_) = message
                    {
                        return true;
                    }
                }
                State::Close => {
                    if let RequestType::Create(_) | RequestType::Echo(_) = message {
                        return true;
                    }
                }
            }
        } else {
            panic!("Directive is missing the state.")
        }
    } else {
        panic!("Direcive is missing the message.")
    }

    false
}

/// Sets up a TCP connection, goes to the desired state and fuzzes the desired message with
/// the corresponding strategy.
pub fn execute_fuzzing_process(directive: FuzzingDirective, ip_address: &str, port: &str) {
    let mut tcp_error: Option<Error> = None;
    while tcp_error.is_none() {
        match TcpStream::connect(ip_address.to_owned() + ":" + port) {
            Ok(mut stream) => {
                if let Some(state) = directive.state.as_ref() {
                    let state_response = state.go_to_state(&mut stream);
                    fuzz_message_with_strategy(&mut stream, directive.clone(), &state_response);
                } else {
                    panic!("Fuzzing directive is missing the state parameter.")
                }
            }
            Err(e) => {
                tcp_error = Some(e);
            }
        }
        sleep(std::time::Duration::from_millis(1000));
    }

    if let Some(err) = tcp_error {
        println!("Failed to connect: {}", err);
    }
}

/// Matches the message type and executes the appropriate the fuzzing strategy and sending order.
pub fn fuzz_message_with_strategy(
    stream: &mut TcpStream,
    directive: FuzzingDirective,
    state_response: &ResponseType,
) {
    if let Some(message) = directive.message {
        match message {
            RequestType::Negotiate(_) => {
                send_fuzzed_negotiate(stream, directive.fuzzing_strategy.unwrap())
            }
            RequestType::SessionSetupNeg(_) => {
                send_fuzzed_session_setup_negotiate(stream, directive.fuzzing_strategy.unwrap())
            }
            RequestType::SessionSetupAuth(_) => send_fuzzed_session_setup_authenticate(
                stream,
                state_response,
                directive.fuzzing_strategy.unwrap(),
            ),
            RequestType::TreeConnect(_) => send_fuzzed_tree_connect_request(
                stream,
                state_response,
                directive.fuzzing_strategy.unwrap(),
            ),
            RequestType::Create(_) => send_fuzzed_create_request(
                stream,
                state_response,
                directive.fuzzing_strategy.unwrap(),
            ),
            RequestType::QueryInfo(_) => send_fuzzed_query_info_request(
                stream,
                state_response,
                directive.fuzzing_strategy.unwrap(),
            ),
            RequestType::Close(_) => send_fuzzed_close_request(
                stream,
                state_response,
                directive.fuzzing_strategy.unwrap(),
            ),
            RequestType::Echo(_) => {
                send_fuzzed_echo_request(stream, directive.fuzzing_strategy.unwrap())
            }
        }
    } else {
        panic!("Empty message field in Fuzzing Directive.");
    }
}

/// Prepares the fuzzed negotiate message and sends it wrapped in a TCP packet.
pub fn send_fuzzed_negotiate(stream: &mut TcpStream, strategy: FuzzingStrategy) {
    let negotiate_request: Vec<u8> = packets::prepare_negotiate_packet(Some(strategy));
    if stream.write_all(&negotiate_request[..]).is_err() {
        println!("Reset Connection.");
    }
}

/// Prepares the fuzzed session setup negotiate message and sends it wrapped in a TCP packet.
pub fn send_fuzzed_session_setup_negotiate(stream: &mut TcpStream, strategy: FuzzingStrategy) {
    let session_setup_negotiate_request: Vec<u8> =
        packets::prepare_session_setup_negotiate_packet(Some(strategy));
    if stream
        .write_all(&session_setup_negotiate_request[..])
        .is_err()
    {
        println!("Reset Connection.");
    }
}

/// Prepares the fuzzed session setup authenticate message and sends it wrapped in a TCP packet.
pub fn send_fuzzed_session_setup_authenticate(
    stream: &mut TcpStream,
    state_response: &ResponseType,
    strategy: FuzzingStrategy,
) {
    let (body, session_id) = match state_response {
        ResponseType::SessionSetupNeg((body, session_id)) => (body, session_id),
        _ => panic!("Invalid ResponseType."),
    };

    let session_setup_authenticate_request: Vec<u8> =
        packets::prepare_session_setup_authenticate_packet(
            Some(strategy),
            session_id.clone(),
            body.clone(),
        );

    if stream
        .write_all(&session_setup_authenticate_request[..])
        .is_err()
    {
        println!("Reset Connection.");
    }
}

/// Prepares the fuzzed tree connect message and sends it wrapped in a TCP packet.
pub fn send_fuzzed_tree_connect_request(
    stream: &mut TcpStream,
    state_response: &ResponseType,
    strategy: FuzzingStrategy,
) {
    let session_id = match state_response {
        ResponseType::SessionSetupAuth(session_id) => session_id,
        _ => panic!("Invalid ResponseType."),
    };

    let tree_connect_request: Vec<u8> =
        packets::prepare_tree_connect_packet(Some(strategy), session_id.clone());

    if stream.write_all(&tree_connect_request[..]).is_err() {
        println!("Reset Connection.");
    }
}

/// Prepares the fuzzed create message and sends it wrapped in a TCP packet.
pub fn send_fuzzed_create_request(
    stream: &mut TcpStream,
    state_response: &ResponseType,
    strategy: FuzzingStrategy,
) {
    let (session_id, tree_id) = match state_response {
        ResponseType::TreeConnect(ids) => ids,
        _ => panic!("Invalid ResponseType."),
    };

    let create_request: Vec<u8> =
        packets::prepare_create_packet(Some(strategy), session_id.clone(), tree_id.clone());

    if stream.write_all(&create_request[..]).is_err() {
        println!("Reset Connection.");
    }
}

/// Prepares the fuzzed query info message and sends it wrapped in a TCP packet.
pub fn send_fuzzed_query_info_request(
    stream: &mut TcpStream,
    state_response: &ResponseType,
    strategy: FuzzingStrategy,
) {
    let (session_id, tree_id, file_id) = match state_response {
        ResponseType::Create(ids) => ids,
        _ => panic!("Invalid ResponseType."),
    };

    let query_info_request: Vec<u8> = packets::prepare_query_info_packet(
        Some(strategy),
        session_id.clone(),
        tree_id.clone(),
        file_id.clone(),
    );

    if stream.write_all(&query_info_request[..]).is_err() {
        println!("Reset Connection.");
    }
}

/// Prepares the fuzzed close message and sends it wrapped in a TCP packet.
pub fn send_fuzzed_close_request(
    stream: &mut TcpStream,
    state_response: &ResponseType,
    strategy: FuzzingStrategy,
) {
    let (session_id, tree_id, file_id) = match state_response {
        ResponseType::Create(ids) => ids,
        _ => panic!("Invalid ResponseType."),
    };

    let close_request: Vec<u8> = packets::prepare_close_packet(
        Some(strategy),
        session_id.clone(),
        tree_id.clone(),
        file_id.clone(),
    );

    if stream.write_all(&close_request[..]).is_err() {
        println!("Reset Connection.");
    }
}

/// Prepares the fuzzed echo message and sends it wrapped in a TCP packet.
pub fn send_fuzzed_echo_request(stream: &mut TcpStream, fuzzing_strategy: FuzzingStrategy) {
    let echo_request = packets::prepare_echo_packet(Some(fuzzing_strategy));

    if stream.write_all(&echo_request[..]).is_err() {
        println!("Reset Connection.");
    }
}

/// Prints the help message.
pub fn print_help() {
    println!(
        r#"
The Fuzzamba fuzzer can be called by the following command:
    cargo run -- -h/--help
    OR
    carg run -- [flags]

    NOTE: Each of the three flag types has to be provided!
          For now, a message has to be sent in the correct state.
          The state is indicated after each flag below as [STATE].

    flags: 
        request types:
            -n | --negotiate | --Negotiate [initial]
            -sn | --session_setup_neg | --Session_setup_neg [negotiate]
            -sa | --session_setup_auth | --Session_setup_auth [session setup neg]
            -t | --tree_connect | --Tree_connect [session setup auth]
            -cr | --create | --Create [tree connect]
            -q | --query_info | --Query_info [create]
            -cl | --close | --Close [create]
            -e | --echo | --Echo [any]

        fuzzing strategy:
            -pre | --predefined | --Predefined
            -rf | --random_fields | --Random_fields
            -cr | --completely_random | --Completely_random

        states:
            -init_state
            -neg_state
            -session_setup_neg_state
            -session_setup_auth_state
            -tree_state
            -create_state
            -close_state
"#
    );
}
