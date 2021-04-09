use self::{
    close::Close, create::Create, echo::Echo, negotiate::Negotiate, query_info::QueryInfo,
    session_setup::SessionSetup, tree_connect::TreeConnect,
};

pub mod close;
pub mod create;
pub mod echo;
pub mod negotiate;
pub mod query_info;
pub mod session_setup;
pub mod tree_connect;

/// The request type determines which message request is sent to the server.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RequestType {
    Negotiate(Negotiate),
    SessionSetupNeg(SessionSetup),
    SessionSetupAuth(SessionSetup),
    TreeConnect(TreeConnect),
    Create(Create),
    QueryInfo(QueryInfo),
    Close(Close),
    Echo(Echo),
}

impl RequestType {
    /// Maps a user input flag to the corresponding request type.
    pub fn map_string_to_request_type(request_type: &str) -> Self {
        match request_type {
            "-n" | "--negotiate" | "--Negotiate" => RequestType::Negotiate(Negotiate::default()),
            "-sn" | "--session_setup_neg" | "--Session_setup_neg" => {
                RequestType::SessionSetupNeg(SessionSetup::default())
            }
            "-sa" | "--session_setup_auth" | "--Session_setup_auth" => {
                RequestType::SessionSetupAuth(SessionSetup::default())
            }
            "-t" | "--tree_connect" | "--Tree_connect" => {
                RequestType::TreeConnect(TreeConnect::default())
            }
            "-cr" | "--create" | "--Create" => RequestType::Create(Create::default()),
            "-q" | "--query_info" | "--Query_info" => RequestType::QueryInfo(QueryInfo::default()),
            "-cl" | "--close" | "--Close" => RequestType::Close(Close::default()),
            "-e" | "--echo" | "--Echo" => RequestType::Echo(Echo::default()),
            _ => panic!("Invalid Request Type."),
        }
    }
}
