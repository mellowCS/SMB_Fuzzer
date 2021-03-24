//! This module establishes a direct TCP connection between client and host over port 445.
//! It also performs the SMB handshake.

use std::io::{Read, Write};
use std::net::TcpStream;

use handshake_helper::negotiate_context::Ciphers;
use handshake_helper::negotiate_context::CompressionAlgorithms;
use handshake_helper::negotiate_context::CompressionCapabilities;
use handshake_helper::negotiate_context::EncryptionCapabilities;
use handshake_helper::negotiate_context::NetnameNegotiateContextId;
use handshake_helper::negotiate_context::PreauthIntegrityCapabilities;
use requests::negotiate::Dialects;

use super::super::smb2::handshake_helper;
use super::super::smb2::header;
use super::super::smb2::requests;

use crate::format;

pub fn connect_to_port_445_via_tcp() {
    let (header, neg_request) = build_negotiate_request();
    let request = format::encoder::serialize_negotiate_request(&header, &neg_request);
    let mut buffer = [0 as u8; 300];
    match TcpStream::connect("192.168.0.171:445") {
        Ok(mut stream) => {
            println!("Successfully connected to server in port 445.");
            stream.write(&request[..]).unwrap();
            println!("Sent Negotiate Request, awaiting reply...");
            match stream.read(&mut buffer) {
                Ok(_) => {
                    for (index, hex_value) in buffer.iter().enumerate() {
                        print!("{:#04x} ", hex_value);
                        if (index + 1) % 16 == 0 {
                            println!();
                        } else if (index + 1) % 8 == 0 {
                            print!("\t");
                        }
                    }
                    println!();
                    println!("Packet Size: {}", buffer.len());
                }
                Err(e) => {
                    println!("Failed to receive data: {}", e);
                }
            }
        }
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Terminated.");
}

pub fn build_negotiate_request() -> (header::SyncHeader, requests::negotiate::Negotiate) {
    let mut sync_neg_header = header::SyncHeader::default();

    sync_neg_header.generic.credit_charge = vec![0; 2];
    sync_neg_header.generic.channel_sequence = vec![0; 2];
    sync_neg_header.generic.reserved = vec![0; 2];
    sync_neg_header.generic.command = header::Commands::Negotiate.unpack_byte_code();
    sync_neg_header.generic.credit = vec![0; 2];
    sync_neg_header.generic.flags = header::Flags::NoFlags.unpack_byte_code();
    sync_neg_header.generic.next_command = vec![0; 4];
    sync_neg_header.generic.message_id = vec![0; 8];
    sync_neg_header.tree_id = vec![0; 4];
    sync_neg_header.session_id = vec![0; 8];
    sync_neg_header.signature = vec![0; 16];

    let mut neg_req = requests::negotiate::Negotiate::default();

    neg_req.dialect_count = b"\x05\x00".to_vec();
    neg_req.security_mode =
        handshake_helper::fields::SecurityMode::NegotiateSigningEnabled.unpack_byte_code(2);
    neg_req.capabilities = handshake_helper::fields::Capabilities::return_all_capabilities();
    neg_req.client_guid = vec![0; 16];
    neg_req.negotiate_context_offset = b"\x70\x00\x00\x00".to_vec();
    neg_req.negotiate_context_count = b"\x04\x00".to_vec();
    neg_req.dialects = vec![
        Dialects::SMB202.unpack_byte_code(),
        Dialects::SMB21.unpack_byte_code(),
        Dialects::SMB30.unpack_byte_code(),
        Dialects::SMB302.unpack_byte_code(),
        Dialects::SMB311.unpack_byte_code(),
    ];
    neg_req.padding = vec![0; 2];

    let context = handshake_helper::negotiate_context::NegotiateContext::default();

    // Pre authentication setup
    let mut preauth = context.clone();
    let mut preauth_caps = PreauthIntegrityCapabilities::default();
    preauth_caps.hash_algorithm_count = b"\x01\x00".to_vec();
    preauth_caps.salt_length = b"\x20\x00".to_vec();
    preauth_caps.hash_algorithms = vec![b"\x01\x00".to_vec()];
    preauth_caps.salt = b"\x79\x13\x02\xd4\xd7\x0c\x2a\x12\x50\x84\xba\xa6\x03\xae\xda\xe4\x12\xe8\x0b\x6e\x96\xf7\xdb\xa9\x46\xdf\x3e\xdc\x16\xe8\x4a\x5a".to_vec();

    let preauth_context =
        handshake_helper::negotiate_context::ContextType::PreauthIntegrityCapabilities(
            preauth_caps,
        );
    preauth.context_type = preauth_context.unpack_byte_code();
    preauth.data_length = b"\x26\x00".to_vec();
    preauth.data = Some(preauth_context);

    // Encryption setup
    let mut encrypt = context.clone();
    let mut encrypt_caps = EncryptionCapabilities::default();
    encrypt_caps.cipher_count = b"\x02\x00".to_vec();
    encrypt_caps.ciphers = vec![
        Ciphers::AES128GCM.unpack_byte_code(),
        Ciphers::AES128CCM.unpack_byte_code(),
    ];

    let encrypt_context =
        handshake_helper::negotiate_context::ContextType::EncryptionCapabilities(encrypt_caps);

    encrypt.context_type = encrypt_context.unpack_byte_code();
    encrypt.data_length = b"\x06\x00".to_vec();
    encrypt.data = Some(encrypt_context);

    let mut compress = context.clone();
    let mut compress_caps = CompressionCapabilities::default();
    compress_caps.compression_algorithm_count = b"\x03\x00".to_vec();
    compress_caps.flags = vec![0; 4];
    compress_caps.compression_algorithms = vec![
        CompressionAlgorithms::LZ77.unpack_byte_code(),
        CompressionAlgorithms::LZ77Huffman.unpack_byte_code(),
        CompressionAlgorithms::LZNT1.unpack_byte_code(),
    ];

    let compress_context =
        handshake_helper::negotiate_context::ContextType::CompressionCapabilities(compress_caps);

    compress.context_type = compress_context.unpack_byte_code();
    compress.data_length = b"\x0e\x00".to_vec();
    compress.data = Some(compress_context);

    let mut netname = context.clone();
    let mut netname_id = NetnameNegotiateContextId::default();

    netname_id.net_name = b"\x31\x00\x39\x00\x32\x00\x2e\x00\x31\x00\x36\x00\x38\x00\x2e\x00\x30\x00\x2e\x00\x31\x00\x37\x00\x31\x00".to_vec();

    let netname_context =
        handshake_helper::negotiate_context::ContextType::NetnameNegotiateContextId(netname_id);

    netname.context_type = netname_context.unpack_byte_code();
    netname.data_length = b"\x1a\x00".to_vec();
    netname.data = Some(netname_context);

    neg_req.negotiate_context_list = vec![preauth, encrypt, compress, netname];

    (sync_neg_header, neg_req)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection() {
        connect_to_port_445_via_tcp();
    }
}
