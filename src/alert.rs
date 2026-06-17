use crate::config::NotificationsConfig;
use log::{info, warn};
use notify_rust::Notification;
use reqwest::Client;
use std::collections::HashMap;

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

    pub async fn alert(&self, protocol: &str, src_ip: &str, src_port: u16, dst_port: u16, details: &str) {
        let message = format!(
            "[{}] Scan detected! {}:{} -> Port {} ({})",
            protocol, src_ip, src_port, dst_port, details
        );

        // System Log (via env_logger / log crate, or syslog)
        if self.config.syslog {
            // syslog output is handled if syslog is configured as the logger backend
            // For now, we use standard log macros which can be routed to syslog by main.rs
            warn!("TRIPWIRE-ALERT: {}", message);
        } else {
            info!("TRIPWIRE-ALERT: {}", message);
        }

        // Desktop Notifications
        if self.config.desktop {
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
        if !self.config.webhook_url.is_empty() {
            let mut payload = HashMap::new();
            payload.insert("content", message.clone());

            let url = self.config.webhook_url.clone();
            let client = self.client.clone();
            
            // Spawn a task so we don't block the packet processing loop
            tokio::spawn(async move {
                if let Err(e) = client.post(&url).json(&payload).send().await {
                    warn!("Failed to send webhook: {}", e);
                }
            });
        }
    }
}
