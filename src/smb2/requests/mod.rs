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

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RequestType {
    Negotiate(Negotiate),
    SessionSetup(SessionSetup),
    TreeConnect(TreeConnect),
    Create(Create),
    QueryInfo(QueryInfo),
    Close(Close),
    Echo(Echo),
}
