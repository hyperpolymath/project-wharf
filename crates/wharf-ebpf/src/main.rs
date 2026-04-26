// SPDX-License-Identifier: PMPL-1.0
// SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>

//! # Wharf Shield - eBPF XDP Firewall
//!
//! This is the kernel-space component of the Wharf security architecture.
//! It drops malicious packets at the network driver level, before the OS
//! even allocates memory for them.
//!
//! ## Security Model
//!
//! - **APL Replacement**: Blocklist of malicious IPs dropped instantly
//! - **Protocol Lock**: Only TCP (Web) and UDP (Nebula) allowed
//! - **Port Lock**: Only 80, 443, 3306 (masquerade), 4242 (Nebula)
//! - **Fail-Closed**: Unknown protocols are dropped, not passed
//!
//! ## Why Rust?
//!
//! Traditional eBPF is written in C (memory-unsafe). This module uses the
//! Aya framework to provide compile-time memory safety guarantees, ensuring
//! we don't crash the kernel.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

// =============================================================================
// MAPS - Shared Memory with Userspace (Yacht Agent)
// =============================================================================

/// The APL Blocklist
/// Key: u32 (IPv4 address in network byte order)
/// Value: u32 (1 = block, 0 = allow)
#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(100_000, 0);

/// Allowed TCP Ports
/// Key: u16 (port number)
/// Value: u32 (1 = allowed)
#[map]
static ALLOWED_TCP_PORTS: HashMap<u16, u32> = HashMap::with_max_entries(64, 0);

/// Allowed UDP Ports
/// Key: u16 (port number)
/// Value: u32 (1 = allowed)
#[map]
static ALLOWED_UDP_PORTS: HashMap<u16, u32> = HashMap::with_max_entries(64, 0);

/// Rate limiting map (per-IP token bucket)
/// Key: u32 (IP address)
/// Value: u64 (last packet timestamp in nanoseconds)
#[map]
static RATE_LIMIT: HashMap<u32, u64> = HashMap::with_max_entries(10_000, 0);

// =============================================================================
// THE XDP PROGRAM - The Force Field
// =============================================================================

#[xdp]
pub fn wharf_shield(ctx: XdpContext) -> u32 {
    match try_wharf_shield(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED, // Fail-closed on error
    }
}

/// The main packet inspection logic
fn try_wharf_shield(ctx: XdpContext) -> Result<u32, ()> {
    // A. Parse Ethernet Header
    let eth_hdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };

    match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv4 => {}
        // Allow IPv6 to pass for now (can be extended)
        EtherType::Ipv6 => return Ok(xdp_action::XDP_PASS),
        // ARP is needed for local networking
        EtherType::Arp => return Ok(xdp_action::XDP_PASS),
        // Unknown protocols: DROP (fail-closed)
        _ => return Ok(xdp_action::XDP_DROP),
    }

    // B. Parse IPv4 Header
    let ipv4_hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let src_ip = unsafe { (*ipv4_hdr).src_addr };

    // C. THE APL CHECK - Instant Annihilation
    if unsafe { BLOCKLIST.get(&src_ip) }.is_some() {
        // Packet is from a known bad IP - drop it before the kernel sees it
        return Ok(xdp_action::XDP_DROP);
    }

    // D. PROTOCOL LOCKDOWN
    let protocol = unsafe { (*ipv4_hdr).proto };

    match protocol {
        IpProto::Tcp => {
            // Parse TCP header
            let tcp_hdr: *const TcpHdr = unsafe {
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?
            };
            let dest_port = u16::from_be(unsafe { (*tcp_hdr).dest });

            // Check against allowed TCP ports
            if unsafe { ALLOWED_TCP_PORTS.get(&dest_port) }.is_some() {
                Ok(xdp_action::XDP_PASS)
            } else {
                // Port not in allowlist - DROP
                Ok(xdp_action::XDP_DROP)
            }
        }
        IpProto::Udp => {
            // Parse UDP header
            let udp_hdr: *const UdpHdr = unsafe {
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?
            };
            let dest_port = u16::from_be(unsafe { (*udp_hdr).dest });

            // Check against allowed UDP ports
            if unsafe { ALLOWED_UDP_PORTS.get(&dest_port) }.is_some() {
                Ok(xdp_action::XDP_PASS)
            } else {
                // Port not in allowlist - DROP
                Ok(xdp_action::XDP_DROP)
            }
        }
        // ICMP - Disabled for invisibility (no ping responses)
        IpProto::Icmp => Ok(xdp_action::XDP_DROP),
        // Everything else (SCTP, GRE, etc.) - DROP
        _ => Ok(xdp_action::XDP_DROP),
    }
}

// =============================================================================
// HELPERS
// =============================================================================

/// Safe pointer arithmetic for eBPF verifier compliance
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
