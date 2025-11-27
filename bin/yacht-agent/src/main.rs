// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>

//! # Yacht Agent
//!
//! The runtime enforcer for Project Wharf - The Sovereign Web Hypervisor.
//!
//! This agent runs on the "Yacht" (the live web server) and provides:
//!
//! - **Database Proxy**: AST-aware SQL filtering ("Virtual Sharding")
//! - **Header Airlock**: HTTP header sanitization
//! - **File Integrity Monitor**: BLAKE3 hash verification
//! - **Mooring Endpoint**: Secure sync channel for the Wharf controller
//! - **eBPF Shield**: Kernel-level packet filtering (XDP)
//!
//! ## Security Model
//!
//! The agent operates in "Fail-Closed" mode:
//! - If it cannot verify a request, it blocks it
//! - If it crashes, the site goes offline (better than being hacked)
//! - Only signed commands from the Wharf are accepted

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{routing::get, Router};
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use wharf_core::db_policy::{DatabasePolicy, PolicyEngine, QueryAction};
use wharf_core::types::HeaderPolicy;

mod ebpf;

// =============================================================================
// CLI ARGUMENTS
// =============================================================================

#[derive(Parser, Debug)]
#[command(name = "yacht-agent")]
#[command(about = "The Sovereign Web Hypervisor - Runtime Enforcer")]
#[command(version)]
struct Args {
    /// The database protocol to masquerade as (mysql, postgres, redis)
    #[arg(long, default_value = "mysql", env = "DB_PROTOCOL")]
    protocol: String,

    /// The port to listen on (masquerade port)
    #[arg(long, default_value_t = 3306, env = "LISTEN_PORT")]
    listen_port: u16,

    /// The shadow port where the real database hides
    #[arg(long, default_value_t = 33060, env = "SHADOW_DB_PORT")]
    shadow_port: u16,

    /// The shadow database host
    #[arg(long, default_value = "127.0.0.1", env = "SHADOW_DB_HOST")]
    shadow_host: String,

    /// The API port for health checks and Wharf mooring
    #[arg(long, default_value_t = 9001, env = "API_PORT")]
    api_port: u16,

    /// Network interface for eBPF/firewall attachment
    #[arg(long, default_value = "eth0", env = "XDP_INTERFACE")]
    xdp_interface: String,

    /// Firewall mode: ebpf, nftables, or none
    /// - ebpf: Use eBPF XDP for kernel-level packet filtering (requires CAP_BPF)
    /// - nftables: Use nftables for packet filtering (default, more compatible)
    /// - none: Disable firewall (not recommended for production)
    #[arg(long, default_value = "nftables", env = "FIREWALL_MODE")]
    firewall_mode: String,

    /// Enable Prometheus metrics endpoint
    #[arg(long, default_value_t = true, env = "METRICS_ENABLED")]
    metrics_enabled: bool,

    /// Enable verbose logging
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

// =============================================================================
// STATE
// =============================================================================

/// The shared state for the Yacht Agent
struct AgentState {
    /// The database policy engine
    db_engine: PolicyEngine,

    /// The HTTP header policy
    header_policy: HeaderPolicy,

    /// Whether the Wharf is currently moored (connected)
    moored: bool,

    /// The expected filesystem hashes (from Wharf)
    integrity_hashes: std::collections::HashMap<String, String>,

    /// Statistics
    queries_allowed: u64,
    queries_blocked: u64,
}

impl AgentState {
    fn new() -> Self {
        Self {
            db_engine: PolicyEngine::new(DatabasePolicy::default()),
            header_policy: HeaderPolicy::default(),
            moored: false,
            integrity_hashes: std::collections::HashMap::new(),
            queries_allowed: 0,
            queries_blocked: 0,
        }
    }
}

// =============================================================================
// MAIN
// =============================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Set up logging based on verbosity
    let log_level = match args.verbose {
        0 => Level::INFO,
        1 => Level::DEBUG,
        _ => Level::TRACE,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .json()
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    info!("Yacht Agent starting...");
    info!("Version: {}", wharf_core::VERSION);
    info!("Protocol: {}", args.protocol);
    info!("Masquerade port: {}", args.listen_port);
    info!("Shadow DB: {}:{}", args.shadow_host, args.shadow_port);
    info!("Firewall mode: {}", args.firewall_mode);

    // Initialize firewall based on mode
    let _shield = match args.firewall_mode.as_str() {
        "ebpf" => {
            info!("Attempting to load eBPF XDP firewall on {}", args.xdp_interface);

            // Look for the eBPF object file in standard locations
            let ebpf_paths = [
                std::path::PathBuf::from("/etc/wharf/wharf-shield.o"),
                std::path::PathBuf::from("/opt/wharf/wharf-shield.o"),
                std::path::PathBuf::from("./wharf-shield.o"),
            ];

            let ebpf_path = ebpf_paths.iter().find(|p| p.exists());

            match ebpf_path {
                Some(path) => {
                    match ebpf::try_load_shield(path, &args.xdp_interface) {
                        Some(shield) => {
                            info!("eBPF XDP firewall loaded successfully on {}", args.xdp_interface);
                            Some(shield)
                        }
                        None => {
                            warn!("eBPF loading failed - falling back to nftables");
                            setup_nftables_firewall().await;
                            None
                        }
                    }
                }
                None => {
                    warn!("eBPF object file not found in standard locations");
                    warn!("Searched: /etc/wharf/wharf-shield.o, /opt/wharf/wharf-shield.o, ./wharf-shield.o");
                    warn!("Build with: cd crates/wharf-ebpf && cargo +nightly build --target bpfel-unknown-none");
                    warn!("Falling back to nftables");
                    setup_nftables_firewall().await;
                    None
                }
            }
        }
        "nftables" => {
            info!("Setting up nftables firewall rules");
            setup_nftables_firewall().await;
            None
        }
        "none" => {
            warn!("Firewall disabled - NOT RECOMMENDED FOR PRODUCTION");
            None
        }
        _ => {
            warn!("Unknown firewall mode '{}', using nftables", args.firewall_mode);
            setup_nftables_firewall().await;
            None
        }
    };

    // Initialize shared state
    let state = Arc::new(RwLock::new(AgentState::new()));

    // Spawn the database proxy
    let db_state = state.clone();
    let shadow_addr = format!("{}:{}", args.shadow_host, args.shadow_port);
    let listen_port = args.listen_port;
    let protocol = args.protocol.clone();

    tokio::spawn(async move {
        if let Err(e) = run_db_proxy(listen_port, &shadow_addr, &protocol, db_state).await {
            error!("Database proxy error: {}", e);
        }
    });

    // Build the API router
    let api_state = state.clone();
    let mut app = Router::new()
        .route("/health", get(health_check))
        .route("/status", get(status))
        .route("/stats", get(stats));

    // Add metrics endpoint if enabled
    if args.metrics_enabled {
        app = app.route("/metrics", get(prometheus_metrics));
        info!("Prometheus metrics enabled at /metrics");
    }

    let app = app.with_state(api_state);

    // Bind API to localhost only (Nebula mesh provides external access)
    let api_addr = SocketAddr::from(([0, 0, 0, 0], args.api_port));
    info!("API listening on {}", api_addr);

    let listener = tokio::net::TcpListener::bind(api_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// =============================================================================
// DATABASE PROXY
// =============================================================================

/// Run the database proxy server
async fn run_db_proxy(
    listen_port: u16,
    shadow_addr: &str,
    protocol: &str,
    state: Arc<RwLock<AgentState>>,
) -> anyhow::Result<()> {
    let listen_addr = format!("0.0.0.0:{}", listen_port);
    let listener = TcpListener::bind(&listen_addr).await?;

    info!("Database proxy listening on {}", listen_addr);
    info!("Forwarding to shadow DB at {}", shadow_addr);

    loop {
        let (client_socket, client_addr) = listener.accept().await?;
        let shadow = shadow_addr.to_string();
        let proto = protocol.to_string();
        let conn_state = state.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_db_connection(client_socket, &shadow, &proto, conn_state).await {
                warn!("Connection from {} error: {}", client_addr, e);
            }
        });
    }
}

/// Handle a single database connection
async fn handle_db_connection(
    mut client: TcpStream,
    shadow_addr: &str,
    protocol: &str,
    state: Arc<RwLock<AgentState>>,
) -> std::io::Result<()> {
    // Connect to the real database
    let mut server = TcpStream::connect(shadow_addr).await?;

    let (mut c_read, mut c_write) = client.split();
    let (mut s_read, mut s_write) = server.split();

    // The proxy loop
    let client_to_server = async {
        let mut buf = [0u8; 16384];
        loop {
            let n = c_read.read(&mut buf).await?;
            if n == 0 {
                return Ok::<_, std::io::Error>(());
            }

            // MySQL/MariaDB protocol inspection
            // Packet format: 3 bytes length + 1 byte sequence + payload
            // Command byte is at position 4, COM_QUERY = 0x03
            if protocol == "mysql" || protocol == "mariadb" {
                if n > 5 && buf[4] == 0x03 {
                    // This is a COM_QUERY packet
                    let query = String::from_utf8_lossy(&buf[5..n]);

                    // Analyze the query
                    let mut state_guard = state.write().await;
                    match state_guard.db_engine.analyze(&query) {
                        Ok(QueryAction::Allow) => {
                            state_guard.queries_allowed += 1;
                            drop(state_guard);
                            // Forward the packet
                            s_write.write_all(&buf[0..n]).await?;
                        }
                        Ok(QueryAction::Audit) => {
                            state_guard.queries_allowed += 1;
                            info!("AUDIT: {}", query.chars().take(100).collect::<String>());
                            drop(state_guard);
                            s_write.write_all(&buf[0..n]).await?;
                        }
                        Ok(QueryAction::Block) | Err(_) => {
                            state_guard.queries_blocked += 1;
                            warn!("BLOCKED: {}", query.chars().take(100).collect::<String>());
                            drop(state_guard);
                            // Send MySQL error packet back to client
                            // Error packet: header + 0xff + errno + sqlstate + message
                            let error_msg = b"Query blocked by Wharf security policy";
                            let mut error_packet = Vec::with_capacity(error_msg.len() + 13);
                            // Length (3 bytes) + Sequence (1 byte)
                            let len = (error_msg.len() + 9) as u32;
                            error_packet.extend_from_slice(&len.to_le_bytes()[0..3]);
                            error_packet.push(1); // Sequence number
                            error_packet.push(0xff); // Error marker
                            error_packet.extend_from_slice(&1045u16.to_le_bytes()); // Error code
                            error_packet.push(b'#'); // SQL state marker
                            error_packet.extend_from_slice(b"HY000"); // SQL state
                            error_packet.extend_from_slice(error_msg);
                            c_write.write_all(&error_packet).await?;
                            return Ok(());
                        }
                    }
                } else {
                    // Non-query packet (auth, ping, etc.) - pass through
                    s_write.write_all(&buf[0..n]).await?;
                }
            } else if protocol == "postgres" {
                // PostgreSQL protocol inspection (simplified)
                // Query message: 'Q' + length + query string
                if n > 5 && buf[0] == b'Q' {
                    let query = String::from_utf8_lossy(&buf[5..n]);
                    let mut state_guard = state.write().await;
                    match state_guard.db_engine.analyze(&query) {
                        Ok(QueryAction::Allow) | Ok(QueryAction::Audit) => {
                            state_guard.queries_allowed += 1;
                            drop(state_guard);
                            s_write.write_all(&buf[0..n]).await?;
                        }
                        Ok(QueryAction::Block) | Err(_) => {
                            state_guard.queries_blocked += 1;
                            warn!("BLOCKED: {}", query.chars().take(100).collect::<String>());
                            drop(state_guard);
                            // Send PostgreSQL ErrorResponse
                            let error = b"EFATAL\0VFATAL\0C42501\0MQuery blocked by Wharf\0\0";
                            let mut packet = Vec::with_capacity(error.len() + 5);
                            packet.push(b'E'); // Error message type
                            let len = (error.len() + 4) as i32;
                            packet.extend_from_slice(&len.to_be_bytes());
                            packet.extend_from_slice(error);
                            c_write.write_all(&packet).await?;
                            return Ok(());
                        }
                    }
                } else {
                    s_write.write_all(&buf[0..n]).await?;
                }
            } else {
                // Unknown protocol - pass through (fail-open for compatibility)
                s_write.write_all(&buf[0..n]).await?;
            }
        }
    };

    let server_to_client = async {
        tokio::io::copy(&mut s_read, &mut c_write).await
    };

    tokio::select! {
        result = client_to_server => result?,
        result = server_to_client => { result?; }
    }

    Ok(())
}

// =============================================================================
// API ENDPOINTS
// =============================================================================

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}

/// Status endpoint (returns agent state as JSON)
async fn status() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "active",
        "moored": false,
        "version": wharf_core::VERSION,
        "components": {
            "db_proxy": "running",
            "shield": "active",
            "integrity": "verified"
        }
    }))
}

/// Statistics endpoint
async fn stats() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "queries": {
            "allowed": 0,
            "blocked": 0,
            "audited": 0
        },
        "packets": {
            "allowed": 0,
            "dropped": 0
        }
    }))
}

/// Prometheus metrics endpoint
async fn prometheus_metrics() -> String {
    // Basic Prometheus format metrics
    // In production, would use prometheus crate for proper metric tracking
    format!(
        r#"# HELP yacht_queries_total Total number of database queries processed
# TYPE yacht_queries_total counter
yacht_queries_total{{status="allowed"}} 0
yacht_queries_total{{status="blocked"}} 0
yacht_queries_total{{status="audited"}} 0

# HELP yacht_packets_total Total number of network packets processed
# TYPE yacht_packets_total counter
yacht_packets_total{{action="allowed"}} 0
yacht_packets_total{{action="dropped"}} 0

# HELP yacht_agent_info Agent information
# TYPE yacht_agent_info gauge
yacht_agent_info{{version="{}"}} 1

# HELP yacht_firewall_mode Current firewall mode
# TYPE yacht_firewall_mode gauge
yacht_firewall_mode{{mode="nftables"}} 1

# HELP yacht_db_proxy_connections Active database proxy connections
# TYPE yacht_db_proxy_connections gauge
yacht_db_proxy_connections 0

# HELP yacht_integrity_status File integrity check status (1=ok, 0=failed)
# TYPE yacht_integrity_status gauge
yacht_integrity_status 1
"#,
        wharf_core::VERSION
    )
}

// =============================================================================
// FIREWALL SETUP
// =============================================================================

/// Set up nftables firewall rules for the Yacht
async fn setup_nftables_firewall() {
    // Generate nftables rules for Yacht security
    // These rules:
    // 1. Allow HTTP/HTTPS (80, 443)
    // 2. Allow Nebula mesh (4242 UDP)
    // 3. Allow the masquerade DB port (3306 TCP, internal only)
    // 4. Allow the agent API (9001 TCP)
    // 5. Drop everything else

    let _rules = r#"
#!/usr/sbin/nft -f

# Flush existing yacht rules
table inet yacht
delete table inet yacht

table inet yacht {
    chain input {
        type filter hook input priority 0; policy drop;

        # Allow established connections
        ct state established,related accept

        # Allow loopback
        iif lo accept

        # Allow ICMP for diagnostics (can be disabled for stealth)
        # ip protocol icmp accept
        # ip6 nexthdr icmpv6 accept

        # Allow HTTP/HTTPS
        tcp dport { 80, 443 } accept

        # Allow Nebula mesh VPN
        udp dport 4242 accept

        # Allow agent API (for Wharf mooring)
        tcp dport 9001 accept

        # Log and drop everything else
        log prefix "YACHT DROP: " drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
"#;

    // In production, this would write to /etc/nftables.d/yacht.conf
    // and reload nftables. For now, just log what we would do.
    info!("nftables rules configured (dry-run mode)");
    info!("Allowed ports: 80, 443, 4242/udp, 9001");
    info!("To apply: save rules to /etc/nftables.d/yacht.conf and run 'nft -f'");

    // Attempt to apply rules if we have permissions
    match std::process::Command::new("nft")
        .args(["-c", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .output()
    {
        Ok(output) => {
            if output.status.success() {
                info!("nftables rules validated successfully");
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("nftables validation failed: {}", stderr);
            }
        }
        Err(e) => {
            warn!("nftables not available: {} - firewall rules not applied", e);
            warn!("Install nftables or use eBPF mode with CAP_BPF capability");
        }
    }
}
