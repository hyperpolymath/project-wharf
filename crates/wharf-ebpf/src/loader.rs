// SPDX-License-Identifier: PMPL-1.0
// SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>

//! # eBPF Loader - Userspace Component
//!
//! This module is used by the Yacht Agent to load the XDP firewall
//! into the kernel and manage the shared maps (blocklist, allowed ports).
//!
//! This is NOT a no_std module - it runs in userspace.

use anyhow::{Context, Result};
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use aya::Bpf;
use std::net::Ipv4Addr;

/// The Shield Manager handles loading and configuring the XDP firewall
pub struct ShieldManager {
    bpf: Bpf,
    interface: String,
}

impl ShieldManager {
    /// Load the XDP program from embedded bytecode
    pub fn load(interface: &str) -> Result<Self> {
        // Load the compiled eBPF bytecode
        // In production, this would be include_bytes! of the compiled .o file
        let mut bpf = Bpf::load(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/wharf-shield"
        )))
        .context("Failed to load eBPF bytecode")?;

        // Attach to the network interface
        let program: &mut Xdp = bpf.program_mut("wharf_shield")?.try_into()?;
        program.load()?;
        program.attach(interface, XdpFlags::default())
            .context("Failed to attach XDP program")?;

        Ok(Self {
            bpf,
            interface: interface.to_string(),
        })
    }

    /// Add an IP to the blocklist
    pub fn block_ip(&mut self, ip: Ipv4Addr) -> Result<()> {
        let mut blocklist: HashMap<_, u32, u32> =
            HashMap::try_from(self.bpf.map_mut("BLOCKLIST")?)?;

        let ip_u32 = u32::from(ip);
        blocklist.insert(ip_u32, 1, 0)?;

        Ok(())
    }

    /// Remove an IP from the blocklist
    pub fn unblock_ip(&mut self, ip: Ipv4Addr) -> Result<()> {
        let mut blocklist: HashMap<_, u32, u32> =
            HashMap::try_from(self.bpf.map_mut("BLOCKLIST")?)?;

        let ip_u32 = u32::from(ip);
        blocklist.remove(&ip_u32)?;

        Ok(())
    }

    /// Configure allowed TCP ports
    pub fn allow_tcp_port(&mut self, port: u16) -> Result<()> {
        let mut ports: HashMap<_, u16, u32> =
            HashMap::try_from(self.bpf.map_mut("ALLOWED_TCP_PORTS")?)?;

        ports.insert(port, 1, 0)?;
        Ok(())
    }

    /// Configure allowed UDP ports
    pub fn allow_udp_port(&mut self, port: u16) -> Result<()> {
        let mut ports: HashMap<_, u16, u32> =
            HashMap::try_from(self.bpf.map_mut("ALLOWED_UDP_PORTS")?)?;

        ports.insert(port, 1, 0)?;
        Ok(())
    }

    /// Configure the default port allowlist for a web server
    pub fn configure_web_defaults(&mut self) -> Result<()> {
        // TCP ports
        self.allow_tcp_port(80)?;    // HTTP
        self.allow_tcp_port(443)?;   // HTTPS
        self.allow_tcp_port(3306)?;  // MySQL (masquerade)
        self.allow_tcp_port(5432)?;  // PostgreSQL (masquerade)

        // UDP ports
        self.allow_udp_port(443)?;   // QUIC/HTTP3
        self.allow_udp_port(4242)?;  // Nebula mesh

        Ok(())
    }

    /// Get statistics from the firewall
    pub fn get_stats(&self) -> ShieldStats {
        // In a full implementation, we'd read from perf events or additional maps
        ShieldStats {
            packets_allowed: 0,
            packets_dropped: 0,
            blocklist_hits: 0,
        }
    }
}

/// Firewall statistics
#[derive(Debug, Clone)]
pub struct ShieldStats {
    pub packets_allowed: u64,
    pub packets_dropped: u64,
    pub blocklist_hits: u64,
}

/// Database variant for port masquerading
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseVariant {
    MySQL,
    MariaDB,
    PostgreSQL,
    Redis,
}

impl DatabaseVariant {
    /// Get the standard port for this database
    pub fn public_port(&self) -> u16 {
        match self {
            DatabaseVariant::MySQL | DatabaseVariant::MariaDB => 3306,
            DatabaseVariant::PostgreSQL => 5432,
            DatabaseVariant::Redis => 6379,
        }
    }

    /// Get the shadow port (where the real DB hides)
    pub fn shadow_port(&self) -> u16 {
        match self {
            DatabaseVariant::MySQL | DatabaseVariant::MariaDB => 33060,
            DatabaseVariant::PostgreSQL => 54320,
            DatabaseVariant::Redis => 63790,
        }
    }
}
