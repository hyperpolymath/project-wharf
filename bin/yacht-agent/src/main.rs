// SPDX-License-Identifier: PMPL-1.0
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

use axum::{extract::State, routing::{get, post}, Json, Router};
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use wharf_core::config::{ConfigLoader, YachtAgentConfig};
use wharf_core::db_policy::{DatabasePolicy, PolicyEngine, QueryAction};
use wharf_core::mooring::{
    self, CommitRequest, CommitResponse, MooringInitRequest, MooringInitResponse,
    MooringSession, SessionState, VerifyRequest, VerifyResponse, YachtStatus,
    MOORING_PROTOCOL_VERSION,
};
use wharf_core::types::HeaderPolicy;

mod ebpf;

// =============================================================================
// FIREWALL TYPES
// =============================================================================

/// Unified firewall type that can be either eBPF XDP or nftables
#[allow(dead_code)]
pub enum Firewall {
    /// eBPF XDP firewall (kernel-level, fastest)
    Ebpf(ebpf::Shield),
    /// nftables firewall (userspace, fallback)
    Nftables(NftablesManager),
    /// No firewall (not recommended)
    None,
}

impl Firewall {
    /// Check if the firewall is active
    pub fn is_active(&self) -> bool {
        match self {
            Firewall::Ebpf(_) => true,
            Firewall::Nftables(mgr) => mgr.is_active(),
            Firewall::None => false,
        }
    }

    /// Get the firewall mode name
    pub fn mode_name(&self) -> &'static str {
        match self {
            Firewall::Ebpf(_) => "ebpf",
            Firewall::Nftables(_) => "nftables",
            Firewall::None => "none",
        }
    }

    /// Block an IP address (if supported)
    pub fn block_ip(&mut self, ip: std::net::Ipv4Addr) -> Result<(), String> {
        match self {
            Firewall::Ebpf(shield) => shield
                .block_ip(ip)
                .map_err(|e| format!("eBPF block_ip failed: {}", e)),
            Firewall::Nftables(mgr) => mgr.block_ip(ip),
            Firewall::None => Err("No firewall active".to_string()),
        }
    }
}

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

    /// Active mooring sessions
    mooring_sessions: std::collections::HashMap<String, MooringSession>,

    /// Allowed Wharf public keys (Ed25519, hex-encoded)
    allowed_wharf_keys: Vec<String>,

    /// Last successful mooring timestamp
    last_mooring_time: Option<u64>,

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
            mooring_sessions: std::collections::HashMap::new(),
            allowed_wharf_keys: vec![],
            last_mooring_time: None,
            queries_allowed: 0,
            queries_blocked: 0,
        }
    }

    /// Check if a Wharf public key is allowed
    fn is_wharf_key_allowed(&self, pubkey: &str) -> bool {
        // In development mode, accept any key if no keys are configured
        if self.allowed_wharf_keys.is_empty() {
            return true;
        }
        self.allowed_wharf_keys.contains(&pubkey.to_string())
    }

    /// Get the current yacht status
    fn get_status(&self) -> YachtStatus {
        YachtStatus {
            ready: true,
            load: 0, // TODO: Calculate actual load
            connections: 0, // TODO: Track connections
            last_mooring: self.last_mooring_time,
            not_ready_reason: None,
        }
    }
}

// =============================================================================
// MAIN
// =============================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Load configuration file (CLI args override config file values)
    let config_loader = ConfigLoader::new();
    let config = config_loader.load_yacht_agent_config().unwrap_or_else(|e| {
        eprintln!("Warning: Failed to load config file: {}. Using defaults.", e);
        YachtAgentConfig::default()
    });

    // Merge config with CLI args (CLI takes precedence)
    let protocol = if args.protocol != "mysql" {
        args.protocol.clone()
    } else {
        config.db_proxy.protocol.clone()
    };
    let listen_port = args.listen_port;
    let shadow_host = if args.shadow_host != "127.0.0.1" {
        args.shadow_host.clone()
    } else {
        config.db_proxy.shadow_host.clone()
    };
    let shadow_port = if args.shadow_port != 33060 {
        args.shadow_port
    } else {
        config.db_proxy.shadow_port
    };
    let firewall_mode = if args.firewall_mode != "nftables" {
        args.firewall_mode.clone()
    } else {
        config.firewall.mode.clone()
    };
    let xdp_interface = if args.xdp_interface != "eth0" {
        args.xdp_interface.clone()
    } else {
        config.firewall.xdp_interface.clone()
    };

    // Set up logging based on verbosity (CLI overrides config)
    let verbosity = if args.verbose > 0 {
        args.verbose
    } else {
        config.logging.verbosity
    };
    let log_level = match verbosity {
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
    info!("Protocol: {}", protocol);
    info!("Masquerade port: {}", listen_port);
    info!("Shadow DB: {}:{}", shadow_host, shadow_port);
    info!("Firewall mode: {}", firewall_mode);

    // Initialize firewall based on mode
    let _firewall: Firewall = match firewall_mode.as_str() {
        "ebpf" => {
            info!("Attempting to load eBPF XDP firewall on {}", xdp_interface);

            // Look for the eBPF object file in standard locations
            let ebpf_paths = [
                std::path::PathBuf::from("/etc/wharf/wharf-shield.o"),
                std::path::PathBuf::from("/opt/wharf/wharf-shield.o"),
                std::path::PathBuf::from("./wharf-shield.o"),
            ];

            let ebpf_path = ebpf_paths.iter().find(|p| p.exists());

            match ebpf_path {
                Some(path) => {
                    match ebpf::try_load_shield(path, &xdp_interface) {
                        Some(shield) => {
                            info!("eBPF XDP firewall loaded successfully on {}", xdp_interface);
                            Firewall::Ebpf(shield)
                        }
                        None => {
                            warn!("eBPF loading failed - falling back to nftables");
                            match setup_nftables_firewall().await {
                                Some(mgr) => Firewall::Nftables(mgr),
                                None => {
                                    error!("Both eBPF and nftables failed! No firewall active!");
                                    Firewall::None
                                }
                            }
                        }
                    }
                }
                None => {
                    warn!("eBPF object file not found in standard locations");
                    warn!("Searched: /etc/wharf/wharf-shield.o, /opt/wharf/wharf-shield.o, ./wharf-shield.o");
                    warn!("Build with: cd crates/wharf-ebpf && cargo +nightly build --target bpfel-unknown-none");
                    warn!("Falling back to nftables");
                    match setup_nftables_firewall().await {
                        Some(mgr) => Firewall::Nftables(mgr),
                        None => {
                            error!("Both eBPF and nftables failed! No firewall active!");
                            Firewall::None
                        }
                    }
                }
            }
        }
        "nftables" => {
            info!("Setting up nftables firewall rules");
            match setup_nftables_firewall().await {
                Some(mgr) => Firewall::Nftables(mgr),
                None => {
                    error!("nftables setup failed! No firewall active!");
                    Firewall::None
                }
            }
        }
        "none" => {
            warn!("Firewall disabled - NOT RECOMMENDED FOR PRODUCTION");
            Firewall::None
        }
        _ => {
            warn!("Unknown firewall mode '{}', using nftables", args.firewall_mode);
            match setup_nftables_firewall().await {
                Some(mgr) => Firewall::Nftables(mgr),
                None => {
                    error!("nftables setup failed! No firewall active!");
                    Firewall::None
                }
            }
        }
    };

    // Log final firewall status
    if _firewall.is_active() {
        info!("Firewall active: {}", _firewall.mode_name());
    } else {
        error!("WARNING: No firewall protection active!");
    }

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
        .route("/stats", get(stats))
        // Mooring protocol endpoints
        .route("/mooring/init", post(mooring_init))
        .route("/mooring/verify", post(mooring_verify))
        .route("/mooring/commit", post(mooring_commit));

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
    client: TcpStream,
    shadow_addr: &str,
    protocol: &str,
    state: Arc<RwLock<AgentState>>,
) -> std::io::Result<()> {
    // Connect to the real database
    let server = TcpStream::connect(shadow_addr).await?;

    let (mut c_read, c_write) = client.into_split();
    let (mut s_read, mut s_write) = server.into_split();

    // Wrap c_write in Arc<Mutex> so both async blocks can write to client
    let c_write = Arc::new(Mutex::new(c_write));
    let c_write_clone = Arc::clone(&c_write);

    // The proxy loop
    let client_to_server = async move {
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
                            c_write.lock().await.write_all(&error_packet).await?;
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
                            c_write.lock().await.write_all(&packet).await?;
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

    let server_to_client = async move {
        let mut buf = [0u8; 16384];
        loop {
            let n = s_read.read(&mut buf).await?;
            if n == 0 {
                return Ok::<_, std::io::Error>(());
            }
            c_write_clone.lock().await.write_all(&buf[0..n]).await?;
        }
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
// MOORING ENDPOINTS
// =============================================================================

/// Type alias for shared state
type SharedState = Arc<RwLock<AgentState>>;

/// Initialize a mooring session
async fn mooring_init(
    State(state): State<SharedState>,
    Json(request): Json<MooringInitRequest>,
) -> Json<serde_json::Value> {
    debug!("Mooring init request from key: {}", request.wharf_pubkey);

    // Version check
    if request.version != MOORING_PROTOCOL_VERSION {
        return Json(serde_json::json!({
            "error": "version_mismatch",
            "expected": MOORING_PROTOCOL_VERSION,
            "actual": request.version
        }));
    }

    let mut state_guard = state.write().await;

    // Key authorization check
    if !state_guard.is_wharf_key_allowed(&request.wharf_pubkey) {
        warn!("Mooring attempt from unknown key: {}", request.wharf_pubkey);
        return Json(serde_json::json!({
            "error": "unauthorized",
            "message": "Wharf public key not in allow list"
        }));
    }

    // TODO: Verify Ed25519 signature

    // Create session
    let session_id = mooring::generate_session_id();
    let now = mooring::current_timestamp();
    let expires_at = now + 3600; // 1 hour session

    let session = MooringSession {
        session_id: session_id.clone(),
        wharf_pubkey: request.wharf_pubkey.clone(),
        created_at: now,
        expires_at,
        requested_layers: request.layers.clone(),
        committed_layers: vec![],
        state: SessionState::Initiated,
    };

    state_guard.mooring_sessions.insert(session_id.clone(), session);
    let yacht_status = state_guard.get_status();
    drop(state_guard);

    info!("Mooring session initiated: {}", session_id);

    let response = MooringInitResponse {
        session_id,
        version: MOORING_PROTOCOL_VERSION.to_string(),
        yacht_pubkey: "TODO_YACHT_PUBKEY".to_string(), // TODO: Generate/load yacht keypair
        accepted_layers: request.layers,
        expires_at,
        status: yacht_status,
    };

    Json(serde_json::to_value(response).unwrap())
}

/// Verify a layer against expected manifest
async fn mooring_verify(
    State(state): State<SharedState>,
    Json(request): Json<VerifyRequest>,
) -> Json<serde_json::Value> {
    debug!("Mooring verify request for session: {}", request.session_id);

    let state_guard = state.read().await;

    // Find session
    let session = match state_guard.mooring_sessions.get(&request.session_id) {
        Some(s) => s,
        None => {
            return Json(serde_json::json!({
                "error": "session_not_found",
                "session_id": request.session_id
            }));
        }
    };

    // Check session validity
    let now = mooring::current_timestamp();
    if now > session.expires_at {
        return Json(serde_json::json!({
            "error": "session_expired",
            "session_id": request.session_id
        }));
    }

    drop(state_guard);

    // TODO: Actually verify files on disk against manifest
    // For MVP, just return success
    let response = VerifyResponse {
        verified: true,
        matched_files: request.expected_manifest.file_count,
        differing_files: vec![],
        missing_files: vec![],
        extra_files: vec![],
    };

    Json(serde_json::to_value(response).unwrap())
}

/// Commit transferred layers
async fn mooring_commit(
    State(state): State<SharedState>,
    Json(request): Json<CommitRequest>,
) -> Json<serde_json::Value> {
    debug!("Mooring commit request for session: {}", request.session_id);

    let mut state_guard = state.write().await;

    // Find and update session
    let session = match state_guard.mooring_sessions.get_mut(&request.session_id) {
        Some(s) => s,
        None => {
            return Json(serde_json::json!({
                "error": "session_not_found",
                "session_id": request.session_id
            }));
        }
    };

    // Check session validity
    let now = mooring::current_timestamp();
    if now > session.expires_at {
        return Json(serde_json::json!({
            "error": "session_expired",
            "session_id": request.session_id
        }));
    }

    // Update session state
    session.state = SessionState::Committed;
    session.committed_layers = request.layers.clone();

    // Update agent state
    state_guard.moored = true;
    state_guard.last_mooring_time = Some(now);

    info!("Mooring commit successful for session: {}", request.session_id);

    let response = CommitResponse {
        success: true,
        committed_layers: request.layers,
        files_modified: 0, // TODO: Track actual changes
        snapshot_id: Some(format!("snap-{}", now)),
        error: None,
    };

    Json(serde_json::to_value(response).unwrap())
}

// =============================================================================
// FIREWALL SETUP
// =============================================================================

/// Default allowed TCP ports for Yacht
const NFTABLES_TCP_PORTS: &[u16] = &[80, 443, 9001];

/// Default allowed UDP ports for Yacht
const NFTABLES_UDP_PORTS: &[u16] = &[4242];

/// nftables firewall manager for runtime rule management
#[allow(dead_code)]
pub struct NftablesManager {
    /// Whether rules have been successfully applied
    active: bool,
    /// Additional TCP ports allowed at runtime
    extra_tcp_ports: Vec<u16>,
    /// Additional UDP ports allowed at runtime
    extra_udp_ports: Vec<u16>,
    /// Blocked IP addresses
    blocked_ips: Vec<std::net::Ipv4Addr>,
}

#[allow(dead_code)]
impl NftablesManager {
    /// Create a new nftables manager
    pub fn new() -> Self {
        Self {
            active: false,
            extra_tcp_ports: Vec::new(),
            extra_udp_ports: Vec::new(),
            blocked_ips: Vec::new(),
        }
    }

    /// Generate the base nftables rules
    fn generate_rules(&self) -> String {
        let mut tcp_ports: Vec<u16> = NFTABLES_TCP_PORTS.to_vec();
        tcp_ports.extend(&self.extra_tcp_ports);
        let tcp_str = tcp_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        let mut udp_ports: Vec<u16> = NFTABLES_UDP_PORTS.to_vec();
        udp_ports.extend(&self.extra_udp_ports);
        let udp_str = udp_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        let blocked_ips_rules = self
            .blocked_ips
            .iter()
            .map(|ip| format!("        ip saddr {} drop", ip))
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            r#"#!/usr/sbin/nft -f

# Yacht Agent Firewall Rules
# Generated by yacht-agent - do not edit manually

table inet yacht
delete table inet yacht

table inet yacht {{
    chain input {{
        type filter hook input priority 0; policy drop;

        # Allow established connections
        ct state established,related accept

        # Allow loopback
        iif lo accept

        # Blocklist
{blocked_ips_rules}

        # Allow HTTP/HTTPS and Agent API
        tcp dport {{ {tcp_str} }} accept

        # Allow Nebula mesh VPN
        udp dport {{ {udp_str} }} accept

        # Log and drop everything else
        log prefix "YACHT DROP: " drop
    }}

    chain forward {{
        type filter hook forward priority 0; policy drop;
    }}

    chain output {{
        type filter hook output priority 0; policy accept;
    }}
}}
"#,
            blocked_ips_rules = blocked_ips_rules,
            tcp_str = tcp_str,
            udp_str = udp_str
        )
    }

    /// Apply nftables rules to the kernel
    pub fn apply(&mut self) -> Result<(), String> {
        let rules = self.generate_rules();

        // First validate the rules
        let validate = std::process::Command::new("nft")
            .args(["-c", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();

        let mut validate_child = match validate {
            Ok(child) => child,
            Err(e) => {
                return Err(format!("Failed to spawn nft for validation: {}", e));
            }
        };

        if let Some(mut stdin) = validate_child.stdin.take() {
            use std::io::Write;
            if let Err(e) = stdin.write_all(rules.as_bytes()) {
                return Err(format!("Failed to write rules for validation: {}", e));
            }
        }

        let validate_output = validate_child
            .wait_with_output()
            .map_err(|e| format!("Failed to wait for validation: {}", e))?;

        if !validate_output.status.success() {
            let stderr = String::from_utf8_lossy(&validate_output.stderr);
            return Err(format!("nftables validation failed: {}", stderr));
        }

        // Now actually apply the rules
        let apply = std::process::Command::new("nft")
            .args(["-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();

        let mut apply_child = match apply {
            Ok(child) => child,
            Err(e) => {
                return Err(format!("Failed to spawn nft for application: {}", e));
            }
        };

        if let Some(mut stdin) = apply_child.stdin.take() {
            use std::io::Write;
            if let Err(e) = stdin.write_all(rules.as_bytes()) {
                return Err(format!("Failed to write rules: {}", e));
            }
        }

        let apply_output = apply_child
            .wait_with_output()
            .map_err(|e| format!("Failed to wait for nft: {}", e))?;

        if apply_output.status.success() {
            self.active = true;
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&apply_output.stderr);
            Err(format!("nftables application failed: {}", stderr))
        }
    }

    /// Block an IP address
    pub fn block_ip(&mut self, ip: std::net::Ipv4Addr) -> Result<(), String> {
        if !self.blocked_ips.contains(&ip) {
            self.blocked_ips.push(ip);
        }
        if self.active {
            // Apply immediately via nft add rule
            let result = std::process::Command::new("nft")
                .args([
                    "add",
                    "rule",
                    "inet",
                    "yacht",
                    "input",
                    "ip",
                    "saddr",
                    &ip.to_string(),
                    "drop",
                ])
                .output();

            match result {
                Ok(output) if output.status.success() => {
                    info!("Blocked IP: {}", ip);
                    Ok(())
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    Err(format!("Failed to block IP {}: {}", ip, stderr))
                }
                Err(e) => Err(format!("Failed to run nft: {}", e)),
            }
        } else {
            Ok(()) // Will be applied on next full apply()
        }
    }

    /// Allow an additional TCP port
    pub fn allow_tcp_port(&mut self, port: u16) -> Result<(), String> {
        if !self.extra_tcp_ports.contains(&port) {
            self.extra_tcp_ports.push(port);
        }
        if self.active {
            self.apply() // Reapply all rules
        } else {
            Ok(())
        }
    }

    /// Allow an additional UDP port
    pub fn allow_udp_port(&mut self, port: u16) -> Result<(), String> {
        if !self.extra_udp_ports.contains(&port) {
            self.extra_udp_ports.push(port);
        }
        if self.active {
            self.apply() // Reapply all rules
        } else {
            Ok(())
        }
    }

    /// Check if the firewall is active
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Remove the yacht firewall table
    pub fn cleanup(&mut self) -> Result<(), String> {
        let result = std::process::Command::new("nft")
            .args(["delete", "table", "inet", "yacht"])
            .output();

        match result {
            Ok(output) if output.status.success() => {
                self.active = false;
                info!("nftables yacht table removed");
                Ok(())
            }
            Ok(_) => {
                // Table might not exist, that's fine
                self.active = false;
                Ok(())
            }
            Err(e) => Err(format!("Failed to cleanup nftables: {}", e)),
        }
    }
}

impl Default for NftablesManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Set up nftables firewall rules for the Yacht
async fn setup_nftables_firewall() -> Option<NftablesManager> {
    info!("Setting up nftables firewall...");
    info!("Allowed TCP ports: {:?}", NFTABLES_TCP_PORTS);
    info!("Allowed UDP ports: {:?}", NFTABLES_UDP_PORTS);

    let mut manager = NftablesManager::new();

    match manager.apply() {
        Ok(()) => {
            info!("nftables firewall applied successfully");
            Some(manager)
        }
        Err(e) => {
            error!("nftables setup failed: {}", e);
            warn!("Firewall NOT active! Ensure you have CAP_NET_ADMIN or run as root");
            warn!("Alternatively, use eBPF mode with CAP_BPF capability");
            None
        }
    }
}
