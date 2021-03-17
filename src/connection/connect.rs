//! This module establishes a direct TCP connection between client and host over port 445.
//! It also performs the SMB handshake.

use std::net::TcpStream;
