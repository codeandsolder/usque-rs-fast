use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct AccountData {
    pub id: String,
    #[serde(default)]
    pub token: String,
    pub account: Account,
    pub config: WarpConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Account {
    pub license: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WarpConfig {
    pub peers: Vec<Peer>,
    pub interface: Interface,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Peer {
    pub public_key: String,
    pub endpoint: Endpoint,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Endpoint {
    pub v4: String,
    pub v6: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Interface {
    pub addresses: Addresses,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Addresses {
    pub v4: String,
    pub v6: String,
}
