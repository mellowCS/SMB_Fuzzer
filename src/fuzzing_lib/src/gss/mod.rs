#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NegTokenResp {
    /// NegState (1 byte): Contains the state of the negotiation. (required in first reply)
    pub state: Vec<u8>,
    /// SupportedMech (10 byte): The negotiation mechanism offered by the initiator. OPTIONAL
    /// (only in first reply)
    pub supported_mech: Vec<u8>,
    /// ResponseToke (variable): Contains tokens specific to the mechanism selected. OPTIONAL
    pub response_token: Vec<u8>,
    /// MechListMic (?): MIC token for per message integrity.
    pub mech_list_mic: Vec<u8>,
}

impl NegTokenResp {
    /// Creates a new instance of the neg token response.
    pub fn default() -> Self {
        NegTokenResp {
            state: Vec::new(),
            supported_mech: Vec::new(),
            response_token: Vec::new(),
            mech_list_mic: Vec::new(),
        }
    }
}
