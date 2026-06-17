mod alert;
mod capture;
mod config;

use alert::Alerter;
use capture::CaptureEngine;
use config::Config;
use log::{error, info};
use std::sync::Arc;
use syslog::{Facility, Formatter3164, BasicLogger};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Attempt to load configuration
    let config_path = if std::path::Path::new("/etc/tripwire/tripwire.yaml").exists() {
        "/etc/tripwire/tripwire.yaml"
    } else {
        "tripwire.yaml"
    };
    let config = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load configuration from {}: {}", config_path, e);
            std::process::exit(1);
        }
    };

    // Setup logging based on configuration
    if config.notifications.syslog {
        let formatter = Formatter3164 {
            facility: Facility::LOG_USER,
            hostname: None,
            process: "tripwire".into(),
            pid: 0,
        };
        match syslog::unix(formatter) {
            Ok(logger) => {
                log::set_boxed_logger(Box::new(BasicLogger::new(logger)))
                    .map(|()| log::set_max_level(log::LevelFilter::Info))
                    .expect("Failed to initialize syslog");
            }
            Err(e) => {
                eprintln!("Failed to connect to syslog: {}. Falling back to env_logger.", e);
                env_logger::init();
            }
        }
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }

    info!("Starting Tripwire Portscan Honeypot");

    let alerter = Arc::new(Alerter::new(config.notifications.clone()));
    let capture_engine = CaptureEngine::new(config, alerter);

    if let Err(e) = capture_engine.run().await {
        error!("Capture engine failed: {}", e);
        std::process::exit(1);
    }

    Ok(())
}
