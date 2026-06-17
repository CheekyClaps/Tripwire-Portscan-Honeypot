use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize, Clone)]
pub struct NotificationsConfig {
    pub desktop: bool,
    pub syslog: bool,
    pub webhook_url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub interface: String,
    pub tcp_ports: Vec<u16>,
    pub udp_ports: Vec<u16>,
    #[serde(default = "default_icmp")]
    pub icmp: bool,
    pub notifications: NotificationsConfig,
}

fn default_icmp() -> bool {
    false
}

impl Config {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }
}
