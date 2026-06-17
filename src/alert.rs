use crate::config::NotificationsConfig;
use log::{info, warn};
use notify_rust::Notification;
use reqwest::Client;
use std::collections::HashMap;
use std::net::IpAddr;

pub struct Alerter {
    config: NotificationsConfig,
    client: Client,
}

impl Alerter {
    pub fn new(config: NotificationsConfig) -> Self {
        Self {
            config,
            client: Client::new(),
        }
    }

    pub async fn alert(&self, protocol: &str, src_ip: &str, src_mac: &str, src_port: u16, dst_port: u16, details: &str) {
        let src_ip_owned = src_ip.to_string();
        let src_mac_owned = src_mac.to_string();
        let protocol_owned = protocol.to_string();
        let details_owned = details.to_string();
        let config = self.config.clone();
        let client = self.client.clone();

        tokio::spawn(async move {
            // Attempt reverse DNS lookup
            let hostname = if let Ok(ip) = src_ip_owned.parse::<IpAddr>() {
                tokio::task::spawn_blocking(move || {
                    dns_lookup::lookup_addr(&ip).unwrap_or_else(|_| "Unknown Host".to_string())
                })
                .await
                .unwrap_or_else(|_| "Unknown Host".to_string())
            } else {
                "Unknown Host".to_string()
            };

            let message = format!(
                "[{}] Scan from {} ({}) [MAC: {}] :{} -> Port {} ({})",
                protocol_owned, src_ip_owned, hostname, src_mac_owned, src_port, dst_port, details_owned
            );

            // System Log
            if config.syslog {
                warn!("TRIPWIRE-ALERT: {}", message);
            } else {
                info!("TRIPWIRE-ALERT: {}", message);
            }

            // Desktop Notifications
            if config.desktop {
                if let Err(e) = Notification::new()
                    .summary("Tripwire Alert")
                    .body(&message)
                    .icon("dialog-warning")
                    .show()
                {
                    warn!("Failed to send desktop notification: {}", e);
                }
            }

            // Webhook
            if !config.webhook_url.is_empty() {
                let mut payload = HashMap::new();
                payload.insert("content", message.clone());
                
                if let Err(e) = client.post(&config.webhook_url).json(&payload).send().await {
                    warn!("Failed to send webhook: {}", e);
                }
            }
        });
    }
}
