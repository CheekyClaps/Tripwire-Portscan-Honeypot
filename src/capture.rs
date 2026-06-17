use crate::alert::Alerter;
use crate::config::Config;
use etherparse::{SlicedPacket, TransportSlice, InternetSlice};
use log::{error, info};
use pcap::{Active, Capture, Device};
use std::sync::Arc;

pub struct CaptureEngine {
    config: Config,
    alerter: Arc<Alerter>,
}

impl CaptureEngine {
    pub fn new(config: Config, alerter: Arc<Alerter>) -> Self {
        Self { config, alerter }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let device = Device::list()?
            .into_iter()
            .find(|d| d.name == self.config.interface)
            .ok_or_else(|| format!("Interface {} not found", self.config.interface))?;

        info!("Starting capture on interface: {}", device.name);

        let mut cap = Capture::from_device(device)?
            .promisc(true)
            .snaplen(65535)
            .timeout(100) // 100ms timeout
            .open()?;

        // Build BPF filter based on configured ports
        let bpf_filter = self.build_bpf_filter();
        if !bpf_filter.is_empty() {
            info!("Applying BPF filter: {}", bpf_filter);
            cap.filter(&bpf_filter, true)?;
        }

        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    self.process_packet(packet.data).await;
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Timeout is normal, just continue loop to allow for cancellation/yielding
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(e) => {
                    error!("Error reading packet: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    fn build_bpf_filter(&self) -> String {
        let mut filter_parts = Vec::new();

        if !self.config.tcp_ports.is_empty() {
            let tcp_ports = self
                .config
                .tcp_ports
                .iter()
                .map(|p| format!("tcp dst port {}", p))
                .collect::<Vec<_>>()
                .join(" or ");
            filter_parts.push(format!("({})", tcp_ports));
        }

        if !self.config.udp_ports.is_empty() {
            let udp_ports = self
                .config
                .udp_ports
                .iter()
                .map(|p| format!("udp dst port {}", p))
                .collect::<Vec<_>>()
                .join(" or ");
            filter_parts.push(format!("({})", udp_ports));
        }

        filter_parts.join(" or ")
    }

    async fn process_packet(&self, packet_data: &[u8]) {
        match SlicedPacket::from_ethernet(packet_data) {
            Ok(sliced) => {
                let (src_ip, _dst_ip) = match &sliced.ip {
                    Some(InternetSlice::Ipv4(ip, _)) => (ip.source_addr().to_string(), ip.destination_addr().to_string()),
                    Some(InternetSlice::Ipv6(ip, _)) => (ip.source_addr().to_string(), ip.destination_addr().to_string()),
                    None => return,
                };

                match &sliced.transport {
                    Some(TransportSlice::Tcp(tcp)) => {
                        let dst_port = tcp.destination_port();
                        if self.config.tcp_ports.contains(&dst_port) {
                            let flags = self.format_tcp_flags(tcp);
                            self.alerter
                                .alert("TCP", &src_ip, tcp.source_port(), dst_port, &flags)
                                .await;
                        }
                    }
                    Some(TransportSlice::Udp(udp)) => {
                        let dst_port = udp.destination_port();
                        if self.config.udp_ports.contains(&dst_port) {
                            self.alerter
                                .alert("UDP", &src_ip, udp.source_port(), dst_port, "")
                                .await;
                        }
                    }
                    _ => {}
                }
            }
            Err(_err) => {
                // Ignore parsing errors for malformed packets
            }
        }
    }

    fn format_tcp_flags(&self, tcp: &etherparse::TcpHeaderSlice) -> String {
        let mut flags = Vec::new();
        if tcp.syn() { flags.push("SYN"); }
        if tcp.ack() { flags.push("ACK"); }
        if tcp.fin() { flags.push("FIN"); }
        if tcp.rst() { flags.push("RST"); }
        if tcp.psh() { flags.push("PSH"); }
        if tcp.urg() { flags.push("URG"); }
        
        if flags.is_empty() {
            "NULL".to_string()
        } else {
            flags.join(",")
        }
    }
}
