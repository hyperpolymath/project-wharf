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
use wharf_core::crypto::{
    self, HybridKeypair, HybridPublicKey, generate_hybrid_keypair, hybrid_public_key,
    verify_with_scheme, serialize_public_key, SignatureScheme,
    serialize_keypair_raw, deserialize_keypair_raw,
};
use wharf_core::db_policy::{DatabasePolicy, PolicyEngine, QueryAction};
use wharf_core::mooring::{
    self, CommitRequest, CommitResponse, MooringInitRequest, MooringInitResponse,
    MooringSession, SessionState, VerifyRequest, VerifyResponse, YachtStatus,
    MOORING_PROTOCOL_VERSION, canonical_init_bytes,
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

    /// Signature scheme: ml-dsa-87-only (default, production-safe) or hybrid (requires ed448 audit)
    #[arg(long, default_value = "ml-dsa-87-only", env = "SIGNATURE_SCHEME")]
    signature_scheme: String,

    /// Enable verbose logging
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

// =============================================================================
// STATE
// =============================================================================

/// The shared state for the Yacht Agent
#[allow(dead_code)]
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

    /// Allowed Wharf public keys (serialized JSON)
    allowed_wharf_keys: Vec<String>,

    /// Yacht's own Ed448 + ML-DSA-87 hybrid keypair
    yacht_keypair: Option<HybridKeypair>,

    /// Yacht's public key for responses
    yacht_pubkey: Option<HybridPublicKey>,

    /// Last successful mooring timestamp
    last_mooring_time: Option<u64>,

    /// Site root for integrity verification
    site_root: Option<String>,

    /// Signature scheme for mooring verification
    signature_scheme: SignatureScheme,

    /// Statistics
    queries_allowed: u64,
    queries_blocked: u64,
    queries_audited: u64,
    mooring_session_count: u64,
    integrity_checks: u64,
}

impl AgentState {
    fn new(key_store_dir: Option<&str>, signature_scheme: SignatureScheme) -> Self {
        // Load or generate yacht keypair with persistence
        let (keypair, pubkey) = Self::load_or_generate_keypair(key_store_dir);

        Self {
            db_engine: PolicyEngine::new(DatabasePolicy::default()),
            header_policy: HeaderPolicy::default(),
            moored: false,
            integrity_hashes: std::collections::HashMap::new(),
            mooring_sessions: std::collections::HashMap::new(),
            allowed_wharf_keys: vec![],
            yacht_keypair: keypair,
            yacht_pubkey: pubkey,
            last_mooring_time: None,
            site_root: None,
            signature_scheme,
            queries_allowed: 0,
            queries_blocked: 0,
            queries_audited: 0,
            mooring_session_count: 0,
            integrity_checks: 0,
        }
    }

    /// Load or generate the yacht agent keypair with disk persistence
    fn load_or_generate_keypair(key_store_dir: Option<&str>) -> (Option<HybridKeypair>, Option<HybridPublicKey>) {
        let key_dir = std::path::PathBuf::from(
            key_store_dir.unwrap_or("/etc/wharf/keys")
        );
        let key_path = key_dir.join("yacht.key");

        // Try loading existing keypair
        if key_path.exists() {
            match std::fs::read(&key_path) {
                Ok(data) => {
                    match deserialize_keypair_raw(&data) {
                        Ok(kp) => {
                            let pk = hybrid_public_key(&kp);
                            tracing::info!("Loaded yacht keypair from {}", key_path.display());
                            return (Some(kp), Some(pk));
                        }
                        Err(e) => {
                            tracing::error!("Failed to deserialize yacht keypair: {}. Generating new one.", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to read yacht keypair: {}. Generating new one.", e);
                }
            }
        }

        // Generate new keypair
        match generate_hybrid_keypair() {
            Ok(kp) => {
                let pk = hybrid_public_key(&kp);

                // Persist to disk
                if let Err(e) = std::fs::create_dir_all(&key_dir) {
                    tracing::warn!("Failed to create key directory {}: {}. Keypair will be ephemeral.", key_dir.display(), e);
                    return (Some(kp), Some(pk));
                }

                match serialize_keypair_raw(&kp) {
                    Ok(data) => {
                        if let Err(e) = std::fs::write(&key_path, &data) {
                            tracing::warn!("Failed to persist keypair to {}: {}. Keypair will be ephemeral.", key_path.display(), e);
                        } else {
                            // Set 0600 permissions
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                let _ = std::fs::set_permissions(
                                    &key_path,
                                    std::fs::Permissions::from_mode(0o600),
                                );
                            }
                            tracing::info!("Generated and saved yacht keypair to {}", key_path.display());
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to serialize keypair: {}. Keypair will be ephemeral.", e);
                    }
                }

                (Some(kp), Some(pk))
            }
            Err(e) => {
                tracing::error!("Failed to generate yacht keypair: {}. Mooring will be unavailable.", e);
                (None, None)
            }
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
            load: 0,
            connections: 0,
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

    // Parse signature scheme from CLI arg
    let signature_scheme = match args.signature_scheme.as_str() {
        "hybrid" => SignatureScheme::Hybrid,
        _ => SignatureScheme::MlDsa87Only,
    };
    info!("Signature scheme: {:?}", signature_scheme);

    // Initialize shared state with persistent keypair
    let mut agent_state = AgentState::new(config.key_store_dir.as_deref(), signature_scheme);
    agent_state.site_root = config.site_root.clone();
    let state = Arc::new(RwLock::new(agent_state));

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
    let app = build_api_router(state.clone(), args.metrics_enabled);
    if args.metrics_enabled {
        info!("Prometheus metrics enabled at /metrics");
    }

    // Bind API to localhost only (Nebula mesh provides external access)
    let api_addr = SocketAddr::from(([0, 0, 0, 0], args.api_port));
    info!("API listening on {}", api_addr);

    let listener = tokio::net::TcpListener::bind(api_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// =============================================================================
// ROUTER CONSTRUCTION
// =============================================================================

/// Build the API router for the yacht-agent.
///
/// Extracted for testability — the integration tests call this directly.
fn build_api_router(state: SharedState, metrics_enabled: bool) -> Router {
    let mut app = Router::new()
        .route("/health", get(health_check))
        .route("/status", get(status))
        .route("/stats", get(stats))
        .route("/mooring/init", post(mooring_init))
        .route("/mooring/verify", post(mooring_verify))
        .route("/mooring/commit", post(mooring_commit));

    if metrics_enabled {
        app = app.route("/metrics", get(prometheus_metrics));
    }

    app.with_state(state)
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
                            state_guard.queries_audited += 1;
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
async fn stats(
    State(state): State<SharedState>,
) -> axum::Json<serde_json::Value> {
    let s = state.read().await;
    axum::Json(serde_json::json!({
        "queries": {
            "allowed": s.queries_allowed,
            "blocked": s.queries_blocked,
            "audited": s.queries_audited
        },
        "mooring_sessions": s.mooring_session_count,
        "integrity_checks": s.integrity_checks
    }))
}

/// Prometheus metrics endpoint
async fn prometheus_metrics(
    State(state): State<SharedState>,
) -> String {
    let s = state.read().await;
    format!(
        r#"# HELP yacht_queries_total Total number of database queries processed
# TYPE yacht_queries_total counter
yacht_queries_total{{status="allowed"}} {}
yacht_queries_total{{status="blocked"}} {}
yacht_queries_total{{status="audited"}} {}

# HELP yacht_mooring_sessions_total Total mooring sessions initiated
# TYPE yacht_mooring_sessions_total counter
yacht_mooring_sessions_total {}

# HELP yacht_integrity_checks_total Total integrity checks performed
# TYPE yacht_integrity_checks_total counter
yacht_integrity_checks_total {}

# HELP yacht_agent_info Agent information
# TYPE yacht_agent_info gauge
yacht_agent_info{{version="{}"}} 1

# HELP yacht_moored Whether the agent is currently moored
# TYPE yacht_moored gauge
yacht_moored {}

# HELP yacht_integrity_status File integrity check status (1=ok, 0=failed)
# TYPE yacht_integrity_status gauge
yacht_integrity_status 1
"#,
        s.queries_allowed,
        s.queries_blocked,
        s.queries_audited,
        s.mooring_session_count,
        s.integrity_checks,
        wharf_core::VERSION,
        if s.moored { 1 } else { 0 },
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

    // Verify Ed448 + ML-DSA-87 hybrid signature
    if !request.signature.is_empty() {
        let canonical = canonical_init_bytes(&request);
        match crypto::deserialize_public_key(&request.wharf_pubkey) {
            Ok(wharf_pk) => {
                match crypto::deserialize_signature(&request.signature) {
                    Ok(sig) => {
                        if let Err(e) = verify_with_scheme(&wharf_pk, &canonical, &sig, state_guard.signature_scheme) {
                            warn!("Signature verification failed: {}", e);
                            return Json(serde_json::json!({
                                "error": "invalid_signature",
                                "message": format!("Signature verification failed: {}", e)
                            }));
                        }
                        debug!("Hybrid signature verified successfully");
                    }
                    Err(e) => {
                        warn!("Invalid signature format: {}", e);
                        return Json(serde_json::json!({
                            "error": "invalid_signature_format",
                            "message": format!("Could not parse signature: {}", e)
                        }));
                    }
                }
            }
            Err(e) => {
                // In dev mode without keys configured, allow unsigned requests
                if !state_guard.allowed_wharf_keys.is_empty() {
                    warn!("Invalid public key format: {}", e);
                    return Json(serde_json::json!({
                        "error": "invalid_key_format",
                        "message": format!("Could not parse wharf public key: {}", e)
                    }));
                }
                debug!("Dev mode: skipping signature verification (no allowed keys configured)");
            }
        }
    }

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
    state_guard.mooring_session_count += 1;
    let yacht_status = state_guard.get_status();
    let yacht_pubkey_str = state_guard
        .yacht_pubkey
        .as_ref()
        .map(serialize_public_key)
        .unwrap_or_else(|| "NO_KEYPAIR".to_string());
    drop(state_guard);

    info!("Mooring session initiated: {}", session_id);

    let response = MooringInitResponse {
        session_id,
        version: MOORING_PROTOCOL_VERSION.to_string(),
        yacht_pubkey: yacht_pubkey_str,
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

    let site_root = state_guard.site_root.clone();
    drop(state_guard);

    // Verify files on disk against the manifest if a site root is configured
    let response = if let Some(ref root) = site_root {
        let root_path = std::path::Path::new(root);
        if root_path.exists() {
            // Build a Manifest from the request's expected_manifest for verification
            let mut manifest_files = std::collections::HashMap::new();
            for (path, hash) in &request.expected_manifest.files {
                manifest_files.insert(
                    path.clone(),
                    wharf_core::integrity::FileEntry {
                        path: path.clone(),
                        hash: hash.clone(),
                        size: 0,
                        modified: 0,
                        mode: 0o644,
                    },
                );
            }
            let manifest = wharf_core::integrity::Manifest {
                files: manifest_files,
                ..Default::default()
            };

            match wharf_core::integrity::verify_manifest(root_path, &manifest, true) {
                Ok(result) => {
                    let mut s = state.write().await;
                    s.integrity_checks += 1;

                    VerifyResponse {
                        verified: result.is_ok(),
                        matched_files: result.passed.len(),
                        differing_files: result.mismatched.iter().map(|(p, _, _)| p.clone()).collect(),
                        missing_files: result.missing.clone(),
                        extra_files: result.unexpected.clone(),
                    }
                }
                Err(e) => {
                    warn!("Integrity verification failed: {}", e);
                    VerifyResponse {
                        verified: false,
                        matched_files: 0,
                        differing_files: vec![],
                        missing_files: vec![],
                        extra_files: vec![],
                    }
                }
            }
        } else {
            warn!("Site root {} does not exist, skipping verification", root);
            VerifyResponse {
                verified: true,
                matched_files: request.expected_manifest.file_count,
                differing_files: vec![],
                missing_files: vec![],
                extra_files: vec![],
            }
        }
    } else {
        // No site root configured — accept manifest as-is (dev mode)
        VerifyResponse {
            verified: true,
            matched_files: request.expected_manifest.file_count,
            differing_files: vec![],
            missing_files: vec![],
            extra_files: vec![],
        }
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

// =============================================================================
// INTEGRATION TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use wharf_core::mooring::{LayerManifest, MooringLayer};
    use wharf_core::mooring_client::MooringClient;

    /// End-to-end test of the full mooring protocol flow:
    /// init → verify → commit over real HTTP.
    #[tokio::test]
    async fn test_mooring_e2e_flow() {
        // Build the yacht-agent API on a random port
        let state = Arc::new(RwLock::new(AgentState::new(None, SignatureScheme::default())));
        let app = build_api_router(state.clone(), true);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind test listener");
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Give the server a moment to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Create a MooringClient with a fresh keypair
        let keypair = generate_hybrid_keypair().expect("keypair gen");
        let client = MooringClient::new(&format!("http://{}", addr), keypair);

        // Step 1: Init mooring session
        let layers = vec![MooringLayer::Config, MooringLayer::Files];
        let init_resp = client
            .init_session(layers, false, false)
            .await
            .expect("init_session failed");

        assert!(!init_resp.session_id.is_empty(), "session_id should not be empty");
        assert_eq!(init_resp.accepted_layers.len(), 2);
        assert!(init_resp.expires_at > 0);

        // Step 2: Verify a layer
        let manifest = LayerManifest {
            files: HashMap::from([
                ("index.html".to_string(), "abc123".to_string()),
                ("style.css".to_string(), "def456".to_string()),
            ]),
            total_size: 2048,
            file_count: 2,
            root_hash: "root000".to_string(),
        };

        let verify_resp = client
            .verify_layer(&init_resp.session_id, MooringLayer::Config, manifest)
            .await
            .expect("verify_layer failed");

        // Without site_root configured, verification passes (dev mode)
        assert!(verify_resp.verified);
        assert_eq!(verify_resp.matched_files, 2);

        // Step 3: Commit
        let commit_resp = client
            .commit(&init_resp.session_id, init_resp.accepted_layers)
            .await
            .expect("commit failed");

        assert!(commit_resp.success);
        assert!(commit_resp.snapshot_id.is_some());

        // Verify state was updated
        let s = state.read().await;
        assert!(s.moored);
        assert!(s.last_mooring_time.is_some());
        assert_eq!(s.mooring_session_count, 1);
    }

    /// Test that the health endpoint responds
    #[tokio::test]
    async fn test_health_endpoint() {
        let state = Arc::new(RwLock::new(AgentState::new(None, SignatureScheme::default())));
        let app = build_api_router(state, false);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let resp = reqwest::get(format!("http://{}/health", addr))
            .await
            .expect("health request failed");

        assert!(resp.status().is_success());
        assert_eq!(resp.text().await.unwrap(), "OK");
    }

    /// Test that metrics endpoint returns real counters
    #[tokio::test]
    async fn test_metrics_endpoint() {
        let state = Arc::new(RwLock::new(AgentState::new(None, SignatureScheme::default())));
        {
            let mut s = state.write().await;
            s.queries_allowed = 42;
            s.queries_blocked = 3;
        }
        let app = build_api_router(state, true);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let resp = reqwest::get(format!("http://{}/metrics", addr))
            .await
            .expect("metrics request failed");

        let body = resp.text().await.unwrap();
        assert!(body.contains("yacht_queries_total{status=\"allowed\"} 42"));
        assert!(body.contains("yacht_queries_total{status=\"blocked\"} 3"));
    }

    /// Test that stats endpoint returns real counters
    #[tokio::test]
    async fn test_stats_endpoint() {
        let state = Arc::new(RwLock::new(AgentState::new(None, SignatureScheme::default())));
        {
            let mut s = state.write().await;
            s.queries_allowed = 10;
            s.queries_blocked = 5;
            s.queries_audited = 2;
        }
        let app = build_api_router(state, false);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let resp = reqwest::get(format!("http://{}/stats", addr))
            .await
            .expect("stats request failed");

        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["queries"]["allowed"], 10);
        assert_eq!(body["queries"]["blocked"], 5);
        assert_eq!(body["queries"]["audited"], 2);
    }
}
