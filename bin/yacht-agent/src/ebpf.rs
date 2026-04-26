// SPDX-License-Identifier: PMPL-1.0
// SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>

//! # eBPF XDP Shield Loader
//!
//! Userspace component that loads and manages the eBPF XDP firewall.
//! This module:
//! 1. Loads the compiled eBPF object file
//! 2. Attaches it to the XDP hook on the network interface
//! 3. Populates the maps (allowed ports, blocklist)
//! 4. Provides runtime updates to the blocklist

use anyhow::{Context, Result};
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use aya::Bpf;
use std::net::Ipv4Addr;
use std::path::Path;
use tracing::{info, warn};

/// Default allowed TCP ports for Yacht
const DEFAULT_TCP_PORTS: &[u16] = &[
    80,    // HTTP
    443,   // HTTPS
    9001,  // Agent API
];

/// Default allowed UDP ports for Yacht
const DEFAULT_UDP_PORTS: &[u16] = &[
    4242,  // Nebula mesh VPN
];

/// eBPF Shield Manager
pub struct Shield {
    /// The loaded BPF program
    bpf: Bpf,
    /// Interface the XDP program is attached to
    interface: String,
}

#[allow(dead_code)]
impl Shield {
    /// Load and attach the eBPF XDP firewall
    ///
    /// # Arguments
    /// * `ebpf_path` - Path to the compiled eBPF object file (wharf-shield.o)
    /// * `interface` - Network interface to attach to (e.g., "eth0")
    ///
    /// # Returns
    /// A Shield instance managing the loaded program
    pub fn load(ebpf_path: &Path, interface: &str) -> Result<Self> {
        info!("Loading eBPF XDP firewall from {:?}", ebpf_path);

        // Load the eBPF object file
        let mut bpf = Bpf::load_file(ebpf_path)
            .context("Failed to load eBPF object file")?;

        // Get the XDP program
        let program: &mut Xdp = bpf
            .program_mut("wharf_shield")
            .context("XDP program 'wharf_shield' not found")?
            .try_into()
            .context("Failed to convert to XDP program")?;

        // Load into kernel
        program.load().context("Failed to load XDP program into kernel")?;

        // Attach to interface
        // Try hardware offload first, fall back to driver mode, then generic
        let attach_result = program
            .attach(interface, XdpFlags::HW_MODE)
            .or_else(|_| {
                warn!("Hardware XDP not supported, trying driver mode");
                program.attach(interface, XdpFlags::DRV_MODE)
            })
            .or_else(|_| {
                warn!("Driver XDP not supported, using generic mode (slower)");
                program.attach(interface, XdpFlags::SKB_MODE)
            })
            .context("Failed to attach XDP program to interface")?;

        info!("eBPF XDP firewall attached to {} (link_id: {:?})", interface, attach_result);

        let mut shield = Self {
            bpf,
            interface: interface.to_string(),
        };

        // Configure default allowed ports
        shield.configure_default_ports()?;

        Ok(shield)
    }

    /// Configure the default allowed ports
    fn configure_default_ports(&mut self) -> Result<()> {
        // Configure TCP ports
        let mut tcp_ports: HashMap<_, u16, u32> = HashMap::try_from(
            self.bpf.map_mut("ALLOWED_TCP_PORTS")
                .context("TCP ports map not found")?
        )?;

        for &port in DEFAULT_TCP_PORTS {
            tcp_ports.insert(port, 1, 0)?;
            info!("Allowed TCP port: {}", port);
        }

        // Configure UDP ports
        let mut udp_ports: HashMap<_, u16, u32> = HashMap::try_from(
            self.bpf.map_mut("ALLOWED_UDP_PORTS")
                .context("UDP ports map not found")?
        )?;

        for &port in DEFAULT_UDP_PORTS {
            udp_ports.insert(port, 1, 0)?;
            info!("Allowed UDP port: {}", port);
        }

        Ok(())
    }

    /// Add an IP to the blocklist
    pub fn block_ip(&mut self, ip: Ipv4Addr) -> Result<()> {
        let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(
            self.bpf.map_mut("BLOCKLIST")
                .context("Blocklist map not found")?
        )?;

        let ip_bytes = u32::from(ip);
        blocklist.insert(ip_bytes, 1, 0)?;
        info!("Blocked IP: {}", ip);

        Ok(())
    }

    /// Remove an IP from the blocklist
    pub fn unblock_ip(&mut self, ip: Ipv4Addr) -> Result<()> {
        let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(
            self.bpf.map_mut("BLOCKLIST")
                .context("Blocklist map not found")?
        )?;

        let ip_bytes = u32::from(ip);
        blocklist.remove(&ip_bytes)?;
        info!("Unblocked IP: {}", ip);

        Ok(())
    }

    /// Allow an additional TCP port
    pub fn allow_tcp_port(&mut self, port: u16) -> Result<()> {
        let mut tcp_ports: HashMap<_, u16, u32> = HashMap::try_from(
            self.bpf.map_mut("ALLOWED_TCP_PORTS")
                .context("TCP ports map not found")?
        )?;

        tcp_ports.insert(port, 1, 0)?;
        info!("Allowed TCP port: {}", port);

        Ok(())
    }

    /// Allow an additional UDP port
    pub fn allow_udp_port(&mut self, port: u16) -> Result<()> {
        let mut udp_ports: HashMap<_, u16, u32> = HashMap::try_from(
            self.bpf.map_mut("ALLOWED_UDP_PORTS")
                .context("UDP ports map not found")?
        )?;

        udp_ports.insert(port, 1, 0)?;
        info!("Allowed UDP port: {}", port);

        Ok(())
    }

    /// Load blocklist from a file (one IP per line)
    pub fn load_blocklist(&mut self, path: &Path) -> Result<usize> {
        let content = std::fs::read_to_string(path)
            .context("Failed to read blocklist file")?;

        let mut count = 0;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Ok(ip) = line.parse::<Ipv4Addr>() {
                self.block_ip(ip)?;
                count += 1;
            } else {
                warn!("Invalid IP in blocklist: {}", line);
            }
        }

        info!("Loaded {} IPs into blocklist from {:?}", count, path);
        Ok(count)
    }

    /// Get the interface this shield is attached to
    pub fn interface(&self) -> &str {
        &self.interface
    }
}

/// Try to load the eBPF shield, returning None if it fails
/// This allows graceful fallback to nftables
pub fn try_load_shield(ebpf_path: &Path, interface: &str) -> Option<Shield> {
    match Shield::load(ebpf_path, interface) {
        Ok(shield) => {
            info!("eBPF XDP shield loaded successfully");
            Some(shield)
        }
        Err(e) => {
            warn!("Failed to load eBPF shield: {}", e);
            warn!("Ensure you have CAP_BPF capability and kernel 5.2+");
            None
        }
    }
}
