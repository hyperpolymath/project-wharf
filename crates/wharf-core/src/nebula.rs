// SPDX-License-Identifier: PMPL-1.0
// SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>

//! # Nebula Mesh VPN Coordination
//!
//! This module provides coordination for Nebula mesh VPN networking between
//! the Wharf control plane and Yacht agents. Nebula creates a zero-trust
//! overlay network with certificate-based authentication.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Wharf Control Plane                       │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
//! │  │  Nebula CA  │  │ Lighthouse  │  │  Certificate Store  │  │
//! │  │  (Offline)  │  │  (Primary)  │  │                     │  │
//! │  └─────────────┘  └─────────────┘  └─────────────────────┘  │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!                    Nebula Mesh (UDP 4242)
//!                              │
//!         ┌────────────────────┼────────────────────┐
//!         │                    │                    │
//! ┌───────┴───────┐    ┌───────┴───────┐    ┌───────┴───────┐
//! │   Yacht A     │    │   Yacht B     │    │   Yacht C     │
//! │  10.42.0.10   │    │  10.42.0.11   │    │  10.42.0.12   │
//! └───────────────┘    └───────────────┘    └───────────────┘
//! ```
//!
//! ## Security Model
//!
//! - CA private key MUST be kept offline (air-gapped)
//! - Yacht certificates are signed by the CA and distributed via mooring
//! - Lighthouse nodes coordinate peer discovery
//! - All traffic is encrypted with Noise protocol (Curve25519, ChaCha20, Poly1305)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

/// Nebula-specific errors
#[derive(Error, Debug)]
pub enum NebulaError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Nebula CA not initialized")]
    CaNotInitialized,

    #[error("Certificate not found: {0}")]
    CertNotFound(String),

    #[error("Invalid IP address: {0}")]
    InvalidIp(String),

    #[error("Nebula command failed: {0}")]
    CommandFailed(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Certificate signing failed: {0}")]
    SigningFailed(String),

    #[error("Parse error: {0}")]
    ParseError(String),
}

/// Result type for Nebula operations
pub type NebulaResult<T> = Result<T, NebulaError>;

// =============================================================================
// NEBULA MESH NETWORK CONFIGURATION
// =============================================================================

/// IP address allocation strategy for the mesh
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum IpAllocationStrategy {
    /// Sequential allocation from the subnet
    #[default]
    Sequential,
    /// Static IP assignment per yacht
    Static,
    /// Hash-based allocation from yacht ID
    HashBased,
}

/// Nebula mesh network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NebulaNetworkConfig {
    /// Mesh network CIDR (e.g., "10.42.0.0/16")
    pub cidr: String,

    /// IP allocation strategy
    pub allocation: IpAllocationStrategy,

    /// Lighthouse nodes (public IPs)
    pub lighthouses: Vec<LighthouseConfig>,

    /// Default UDP port for Nebula
    pub port: u16,

    /// DNS servers to use inside the mesh
    pub dns_servers: Vec<String>,

    /// Maximum Transmission Unit for the tunnel
    pub mtu: u16,
}

impl Default for NebulaNetworkConfig {
    fn default() -> Self {
        Self {
            cidr: "10.42.0.0/16".to_string(),
            allocation: IpAllocationStrategy::Sequential,
            lighthouses: vec![],
            port: 4242,
            dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            mtu: 1300,
        }
    }
}

impl NebulaNetworkConfig {
    /// Parse the CIDR and return the network address and prefix
    pub fn parse_cidr(&self) -> NebulaResult<(IpAddr, u8)> {
        let parts: Vec<&str> = self.cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(NebulaError::InvalidIp(format!(
                "Invalid CIDR format: {}",
                self.cidr
            )));
        }

        let ip: IpAddr = parts[0]
            .parse()
            .map_err(|_| NebulaError::InvalidIp(parts[0].to_string()))?;

        let prefix: u8 = parts[1]
            .parse()
            .map_err(|_| NebulaError::InvalidIp(format!("Invalid prefix: {}", parts[1])))?;

        Ok((ip, prefix))
    }

    /// Allocate the next available IP in the network
    pub fn allocate_ip(&self, index: u32) -> NebulaResult<String> {
        let (base_ip, prefix) = self.parse_cidr()?;

        match base_ip {
            IpAddr::V4(ipv4) => {
                let base: u32 = u32::from(ipv4);
                // Reserve .0 (network) and .1 (gateway/lighthouse)
                let new_ip = base + index + 10; // Start from .10
                let octets = new_ip.to_be_bytes();
                Ok(format!(
                    "{}.{}.{}.{}/{}",
                    octets[0], octets[1], octets[2], octets[3], prefix
                ))
            }
            IpAddr::V6(_) => Err(NebulaError::InvalidIp(
                "IPv6 allocation not yet supported".to_string(),
            )),
        }
    }
}

/// Lighthouse (relay/discovery) node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LighthouseConfig {
    /// Nebula mesh IP for this lighthouse
    pub nebula_ip: String,

    /// Public IP or hostname
    pub public_host: String,

    /// Public port (usually same as mesh port)
    pub public_port: u16,

    /// Whether this lighthouse is the primary
    pub is_primary: bool,
}

// =============================================================================
// CERTIFICATE AUTHORITY
// =============================================================================

/// Nebula Certificate Authority management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NebulaCa {
    /// Path to the CA directory
    pub ca_dir: PathBuf,

    /// CA name (organization)
    pub name: String,

    /// CA duration in hours (default: 87600 = 10 years)
    pub duration_hours: u64,

    /// Groups that can be assigned to certificates
    pub groups: Vec<String>,
}

impl Default for NebulaCa {
    fn default() -> Self {
        Self {
            ca_dir: PathBuf::from("/etc/wharf/nebula/ca"),
            name: "Wharf CA".to_string(),
            duration_hours: 87600, // 10 years
            groups: vec![
                "wharf".to_string(),
                "yacht".to_string(),
                "lighthouse".to_string(),
                "admin".to_string(),
            ],
        }
    }
}

impl NebulaCa {
    /// Create a new CA configuration
    pub fn new(ca_dir: impl AsRef<Path>, name: &str) -> Self {
        Self {
            ca_dir: ca_dir.as_ref().to_path_buf(),
            name: name.to_string(),
            ..Default::default()
        }
    }

    /// Path to the CA certificate
    pub fn ca_crt_path(&self) -> PathBuf {
        self.ca_dir.join("ca.crt")
    }

    /// Path to the CA private key
    pub fn ca_key_path(&self) -> PathBuf {
        self.ca_dir.join("ca.key")
    }

    /// Check if the CA has been initialized
    pub fn is_initialized(&self) -> bool {
        self.ca_crt_path().exists() && self.ca_key_path().exists()
    }

    /// Initialize a new Certificate Authority
    ///
    /// This generates a new CA key pair. The private key should be
    /// stored securely and ideally kept offline.
    pub fn initialize(&self) -> NebulaResult<()> {
        if self.is_initialized() {
            return Err(NebulaError::ConfigError(
                "CA already initialized".to_string(),
            ));
        }

        // Ensure CA directory exists
        std::fs::create_dir_all(&self.ca_dir)?;

        // Run nebula-cert ca command
        let output = Command::new("nebula-cert")
            .arg("ca")
            .arg("-name")
            .arg(&self.name)
            .arg("-duration")
            .arg(format!("{}h", self.duration_hours))
            .arg("-out-crt")
            .arg(self.ca_crt_path())
            .arg("-out-key")
            .arg(self.ca_key_path())
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NebulaError::CommandFailed(format!(
                "nebula-cert ca failed: {}",
                stderr
            )));
        }

        // Set restrictive permissions on the key
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(self.ca_key_path())?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(self.ca_key_path(), perms)?;
        }

        Ok(())
    }

    /// Sign a certificate for a node
    pub fn sign_certificate(&self, request: &CertSignRequest) -> NebulaResult<NebulaCert> {
        if !self.is_initialized() {
            return Err(NebulaError::CaNotInitialized);
        }

        let cert_dir = self.ca_dir.join("certs").join(&request.name);
        std::fs::create_dir_all(&cert_dir)?;

        let crt_path = cert_dir.join(format!("{}.crt", request.name));
        let key_path = cert_dir.join(format!("{}.key", request.name));

        // Build nebula-cert sign command
        let mut cmd = Command::new("nebula-cert");
        cmd.arg("sign")
            .arg("-ca-crt")
            .arg(self.ca_crt_path())
            .arg("-ca-key")
            .arg(self.ca_key_path())
            .arg("-name")
            .arg(&request.name)
            .arg("-ip")
            .arg(&request.ip)
            .arg("-out-crt")
            .arg(&crt_path)
            .arg("-out-key")
            .arg(&key_path);

        if !request.groups.is_empty() {
            cmd.arg("-groups").arg(request.groups.join(","));
        }

        if let Some(duration) = request.duration_hours {
            cmd.arg("-duration").arg(format!("{}h", duration));
        }

        // Add subnets if specified
        for subnet in &request.subnets {
            cmd.arg("-subnets").arg(subnet);
        }

        let output = cmd.output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NebulaError::SigningFailed(stderr.to_string()));
        }

        // Set restrictive permissions on the key
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&key_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&key_path, perms)?;
        }

        Ok(NebulaCert {
            name: request.name.clone(),
            ip: request.ip.clone(),
            groups: request.groups.clone(),
            crt_path,
            key_path,
            ca_crt_path: self.ca_crt_path(),
        })
    }

    /// Get the CA certificate contents (safe to distribute)
    pub fn get_ca_cert(&self) -> NebulaResult<String> {
        if !self.is_initialized() {
            return Err(NebulaError::CaNotInitialized);
        }
        Ok(std::fs::read_to_string(self.ca_crt_path())?)
    }
}

/// Certificate signing request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertSignRequest {
    /// Node name (usually yacht ID)
    pub name: String,

    /// Nebula IP with CIDR (e.g., "10.42.0.10/16")
    pub ip: String,

    /// Groups to assign
    pub groups: Vec<String>,

    /// Certificate duration in hours (None = use CA default)
    pub duration_hours: Option<u64>,

    /// Subnets this node can route to
    pub subnets: Vec<String>,
}

impl CertSignRequest {
    /// Create a new certificate request for a yacht
    pub fn for_yacht(name: &str, ip: &str) -> Self {
        Self {
            name: name.to_string(),
            ip: ip.to_string(),
            groups: vec!["yacht".to_string()],
            duration_hours: Some(8760), // 1 year
            subnets: vec![],
        }
    }

    /// Create a new certificate request for a lighthouse
    pub fn for_lighthouse(name: &str, ip: &str) -> Self {
        Self {
            name: name.to_string(),
            ip: ip.to_string(),
            groups: vec!["lighthouse".to_string(), "wharf".to_string()],
            duration_hours: Some(26280), // 3 years
            subnets: vec![],
        }
    }
}

/// A signed Nebula certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NebulaCert {
    /// Node name
    pub name: String,

    /// Assigned IP address
    pub ip: String,

    /// Assigned groups
    pub groups: Vec<String>,

    /// Path to certificate file
    pub crt_path: PathBuf,

    /// Path to private key file
    pub key_path: PathBuf,

    /// Path to CA certificate
    pub ca_crt_path: PathBuf,
}

impl NebulaCert {
    /// Read the certificate contents
    pub fn read_cert(&self) -> NebulaResult<String> {
        Ok(std::fs::read_to_string(&self.crt_path)?)
    }

    /// Read the private key contents
    pub fn read_key(&self) -> NebulaResult<String> {
        Ok(std::fs::read_to_string(&self.key_path)?)
    }

    /// Read the CA certificate contents
    pub fn read_ca_cert(&self) -> NebulaResult<String> {
        Ok(std::fs::read_to_string(&self.ca_crt_path)?)
    }
}

// =============================================================================
// NODE CONFIGURATION GENERATION
// =============================================================================

/// Nebula firewall rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NebulaFirewallRule {
    /// Port or port range (e.g., "443" or "8000-9000")
    pub port: String,

    /// Protocol: tcp, udp, icmp, any
    pub proto: String,

    /// Source: "any", a group name, or CIDR
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    /// Source group
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    /// Source CIDR
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
}

impl NebulaFirewallRule {
    /// Allow any host
    pub fn allow_any(port: &str, proto: &str) -> Self {
        Self {
            port: port.to_string(),
            proto: proto.to_string(),
            host: Some("any".to_string()),
            group: None,
            cidr: None,
        }
    }

    /// Allow a specific group
    pub fn allow_group(port: &str, proto: &str, group: &str) -> Self {
        Self {
            port: port.to_string(),
            proto: proto.to_string(),
            host: None,
            group: Some(group.to_string()),
            cidr: None,
        }
    }
}

/// Nebula node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NebulaNodeConfig {
    /// PKI configuration
    pub pki: PkiConfig,

    /// Static host map (for lighthouses)
    pub static_host_map: HashMap<String, Vec<String>>,

    /// Lighthouse configuration
    pub lighthouse: LighthouseNodeConfig,

    /// Listen configuration
    pub listen: ListenConfig,

    /// Punchy configuration (NAT traversal)
    pub punchy: PunchyConfig,

    /// Firewall configuration
    pub firewall: FirewallNodeConfig,

    /// Tunnel configuration
    pub tun: TunConfig,

    /// Logging configuration
    pub logging: NebulaLoggingConfig,
}

/// PKI paths configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkiConfig {
    /// Path to CA certificate
    pub ca: String,

    /// Path to node certificate
    pub cert: String,

    /// Path to node private key
    pub key: String,
}

/// Lighthouse-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LighthouseNodeConfig {
    /// Whether this node is a lighthouse
    pub am_lighthouse: bool,

    /// Interval for querying lighthouses (seconds)
    pub interval: u32,

    /// Lighthouse hosts (Nebula IPs)
    pub hosts: Vec<String>,
}

/// Listen configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenConfig {
    /// Listen host (0.0.0.0 for all interfaces)
    pub host: String,

    /// Listen port
    pub port: u16,
}

/// NAT traversal configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PunchyConfig {
    /// Enable punchy (NAT hole punching)
    pub punch: bool,

    /// Respond to punch requests
    pub respond: bool,

    /// Delay before punching (ms)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delay: Option<String>,
}

/// Firewall configuration for the node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallNodeConfig {
    /// Outbound rules
    pub outbound: Vec<NebulaFirewallRule>,

    /// Inbound rules
    pub inbound: Vec<NebulaFirewallRule>,
}

/// Tunnel device configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunConfig {
    /// Enable unsafe routes
    pub unsafe_routes: Vec<UnsafeRoute>,

    /// Tunnel device name
    pub dev: String,

    /// Drop local broadcast packets
    pub drop_local_broadcast: bool,

    /// Drop multicast packets
    pub drop_multicast: bool,

    /// TX queue length
    pub tx_queue: u32,

    /// MTU
    pub mtu: u16,
}

/// Unsafe route for routing external traffic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsafeRoute {
    /// Route destination CIDR
    pub route: String,

    /// Via Nebula IP
    pub via: String,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NebulaLoggingConfig {
    /// Log level: debug, info, warn, error
    pub level: String,

    /// Log format: text, json
    pub format: String,
}

// =============================================================================
// CONFIGURATION GENERATOR
// =============================================================================

/// Generate Nebula configuration for different node types
pub struct NebulaConfigGenerator {
    /// Network configuration
    pub network: NebulaNetworkConfig,

    /// CA configuration
    pub ca: NebulaCa,
}

impl NebulaConfigGenerator {
    /// Create a new config generator
    pub fn new(network: NebulaNetworkConfig, ca: NebulaCa) -> Self {
        Self { network, ca }
    }

    /// Generate configuration for a yacht node
    pub fn generate_yacht_config(
        &self,
        cert: &NebulaCert,
        config_dir: &Path,
    ) -> NebulaResult<NebulaNodeConfig> {
        let mut static_host_map = HashMap::new();

        // Add lighthouse entries
        for lighthouse in &self.network.lighthouses {
            static_host_map.insert(
                lighthouse.nebula_ip.clone(),
                vec![format!("{}:{}", lighthouse.public_host, lighthouse.public_port)],
            );
        }

        let lighthouse_hosts: Vec<String> = self
            .network
            .lighthouses
            .iter()
            .map(|l| l.nebula_ip.clone())
            .collect();

        Ok(NebulaNodeConfig {
            pki: PkiConfig {
                ca: config_dir.join("ca.crt").to_string_lossy().to_string(),
                cert: config_dir.join("host.crt").to_string_lossy().to_string(),
                key: config_dir.join("host.key").to_string_lossy().to_string(),
            },
            static_host_map,
            lighthouse: LighthouseNodeConfig {
                am_lighthouse: false,
                interval: 60,
                hosts: lighthouse_hosts,
            },
            listen: ListenConfig {
                host: "0.0.0.0".to_string(),
                port: self.network.port,
            },
            punchy: PunchyConfig {
                punch: true,
                respond: true,
                delay: Some("1s".to_string()),
            },
            firewall: self.generate_yacht_firewall(&cert.groups),
            tun: TunConfig {
                unsafe_routes: vec![],
                dev: "nebula1".to_string(),
                drop_local_broadcast: false,
                drop_multicast: false,
                tx_queue: 500,
                mtu: self.network.mtu,
            },
            logging: NebulaLoggingConfig {
                level: "info".to_string(),
                format: "text".to_string(),
            },
        })
    }

    /// Generate configuration for a lighthouse node
    pub fn generate_lighthouse_config(
        &self,
        cert: &NebulaCert,
        config_dir: &Path,
    ) -> NebulaResult<NebulaNodeConfig> {
        let mut static_host_map = HashMap::new();

        // Add other lighthouse entries (for multi-lighthouse setups)
        for lighthouse in &self.network.lighthouses {
            if lighthouse.nebula_ip != cert.ip {
                static_host_map.insert(
                    lighthouse.nebula_ip.clone(),
                    vec![format!("{}:{}", lighthouse.public_host, lighthouse.public_port)],
                );
            }
        }

        Ok(NebulaNodeConfig {
            pki: PkiConfig {
                ca: config_dir.join("ca.crt").to_string_lossy().to_string(),
                cert: config_dir.join("host.crt").to_string_lossy().to_string(),
                key: config_dir.join("host.key").to_string_lossy().to_string(),
            },
            static_host_map,
            lighthouse: LighthouseNodeConfig {
                am_lighthouse: true,
                interval: 60,
                hosts: vec![],
            },
            listen: ListenConfig {
                host: "0.0.0.0".to_string(),
                port: self.network.port,
            },
            punchy: PunchyConfig {
                punch: true,
                respond: true,
                delay: None,
            },
            firewall: self.generate_lighthouse_firewall(),
            tun: TunConfig {
                unsafe_routes: vec![],
                dev: "nebula1".to_string(),
                drop_local_broadcast: false,
                drop_multicast: false,
                tx_queue: 500,
                mtu: self.network.mtu,
            },
            logging: NebulaLoggingConfig {
                level: "info".to_string(),
                format: "text".to_string(),
            },
        })
    }

    /// Generate firewall rules for a yacht
    fn generate_yacht_firewall(&self, _groups: &[String]) -> FirewallNodeConfig {
        FirewallNodeConfig {
            outbound: vec![
                // Allow all outbound traffic
                NebulaFirewallRule::allow_any("any", "any"),
            ],
            inbound: vec![
                // Allow ICMP from any mesh host
                NebulaFirewallRule::allow_any("any", "icmp"),
                // Allow SSH from wharf group
                NebulaFirewallRule::allow_group("22", "tcp", "wharf"),
                // Allow yacht-agent API from wharf group
                NebulaFirewallRule::allow_group("9001", "tcp", "wharf"),
                // Allow mooring protocol from wharf group
                NebulaFirewallRule::allow_group("9002", "tcp", "wharf"),
            ],
        }
    }

    /// Generate firewall rules for a lighthouse
    fn generate_lighthouse_firewall(&self) -> FirewallNodeConfig {
        FirewallNodeConfig {
            outbound: vec![NebulaFirewallRule::allow_any("any", "any")],
            inbound: vec![
                // Allow ICMP from any mesh host
                NebulaFirewallRule::allow_any("any", "icmp"),
                // Allow SSH from admin group
                NebulaFirewallRule::allow_group("22", "tcp", "admin"),
            ],
        }
    }

    /// Export configuration as YAML
    pub fn export_yaml(&self, config: &NebulaNodeConfig) -> NebulaResult<String> {
        serde_yaml::to_string(config)
            .map_err(|e| NebulaError::ConfigError(format!("YAML serialization failed: {}", e)))
    }
}

// =============================================================================
// FLEET INTEGRATION
// =============================================================================

/// Nebula certificate store for the fleet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NebulaCertStore {
    /// Certificates indexed by yacht ID
    pub certs: HashMap<String, NebulaCertRecord>,

    /// Next IP index for sequential allocation
    pub next_ip_index: u32,
}

impl Default for NebulaCertStore {
    fn default() -> Self {
        Self {
            certs: HashMap::new(),
            next_ip_index: 0,
        }
    }
}

/// A certificate record in the store
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NebulaCertRecord {
    /// Yacht ID
    pub yacht_id: String,

    /// Assigned Nebula IP
    pub nebula_ip: String,

    /// Certificate fingerprint
    pub fingerprint: String,

    /// Issue timestamp
    pub issued_at: u64,

    /// Expiry timestamp
    pub expires_at: u64,

    /// Certificate status
    pub status: CertStatus,
}

/// Certificate status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CertStatus {
    /// Certificate is valid and active
    Active,
    /// Certificate is about to expire
    Expiring,
    /// Certificate has been revoked
    Revoked,
    /// Certificate has expired
    Expired,
}

impl NebulaCertStore {
    /// Load the certificate store from a file
    pub fn load(path: &Path) -> NebulaResult<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)?;
        serde_json::from_str(&content)
            .map_err(|e| NebulaError::ParseError(format!("Failed to parse cert store: {}", e)))
    }

    /// Save the certificate store to a file
    pub fn save(&self, path: &Path) -> NebulaResult<()> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| NebulaError::ParseError(format!("Failed to serialize cert store: {}", e)))?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Get or allocate an IP for a yacht
    ///
    /// If the yacht already has a record, returns the existing IP.
    /// Otherwise, allocates a new IP and creates a placeholder record.
    pub fn get_or_allocate_ip(
        &mut self,
        yacht_id: &str,
        network: &NebulaNetworkConfig,
    ) -> NebulaResult<String> {
        // Check if yacht already has an IP
        if let Some(record) = self.certs.get(yacht_id) {
            return Ok(record.nebula_ip.clone());
        }

        // Allocate new IP
        let ip = network.allocate_ip(self.next_ip_index)?;
        self.next_ip_index += 1;

        // Create a placeholder record to track the allocation
        let record = NebulaCertRecord {
            yacht_id: yacht_id.to_string(),
            nebula_ip: ip.clone(),
            fingerprint: String::new(), // Will be set when cert is signed
            issued_at: 0,
            expires_at: 0,
            status: CertStatus::Active,
        };
        self.certs.insert(yacht_id.to_string(), record);

        Ok(ip)
    }

    /// Add a certificate record
    pub fn add_record(&mut self, record: NebulaCertRecord) {
        self.certs.insert(record.yacht_id.clone(), record);
    }

    /// Get a certificate record
    pub fn get_record(&self, yacht_id: &str) -> Option<&NebulaCertRecord> {
        self.certs.get(yacht_id)
    }

    /// Revoke a certificate
    pub fn revoke(&mut self, yacht_id: &str) -> Option<()> {
        self.certs.get_mut(yacht_id).map(|record| {
            record.status = CertStatus::Revoked;
        })
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidr() {
        let config = NebulaNetworkConfig::default();
        let (ip, prefix) = config.parse_cidr().unwrap();
        assert_eq!(prefix, 16);
        assert_eq!(ip.to_string(), "10.42.0.0");
    }

    #[test]
    fn test_allocate_ip() {
        let config = NebulaNetworkConfig::default();
        let ip0 = config.allocate_ip(0).unwrap();
        let ip1 = config.allocate_ip(1).unwrap();
        let ip2 = config.allocate_ip(2).unwrap();

        assert_eq!(ip0, "10.42.0.10/16");
        assert_eq!(ip1, "10.42.0.11/16");
        assert_eq!(ip2, "10.42.0.12/16");
    }

    #[test]
    fn test_cert_sign_request_for_yacht() {
        let req = CertSignRequest::for_yacht("yacht-prod-1", "10.42.0.10/16");
        assert_eq!(req.name, "yacht-prod-1");
        assert_eq!(req.groups, vec!["yacht"]);
        assert_eq!(req.duration_hours, Some(8760));
    }

    #[test]
    fn test_cert_sign_request_for_lighthouse() {
        let req = CertSignRequest::for_lighthouse("lighthouse-1", "10.42.0.1/16");
        assert_eq!(req.name, "lighthouse-1");
        assert!(req.groups.contains(&"lighthouse".to_string()));
        assert!(req.groups.contains(&"wharf".to_string()));
    }

    #[test]
    fn test_firewall_rules() {
        let rule = NebulaFirewallRule::allow_group("22", "tcp", "wharf");
        assert_eq!(rule.port, "22");
        assert_eq!(rule.proto, "tcp");
        assert_eq!(rule.group, Some("wharf".to_string()));
    }

    #[test]
    fn test_cert_store_allocation() {
        let network = NebulaNetworkConfig::default();
        let mut store = NebulaCertStore::default();

        let ip1 = store.get_or_allocate_ip("yacht-1", &network).unwrap();
        let ip2 = store.get_or_allocate_ip("yacht-2", &network).unwrap();
        let ip1_again = store.get_or_allocate_ip("yacht-1", &network).unwrap();

        // First yacht gets first IP
        assert!(ip1.starts_with("10.42.0.10"));
        // Second yacht gets next IP
        assert!(ip2.starts_with("10.42.0.11"));
        // Same yacht gets same IP
        assert_eq!(ip1, ip1_again);
    }

    #[test]
    fn test_default_ca() {
        let ca = NebulaCa::default();
        assert_eq!(ca.name, "Wharf CA");
        assert_eq!(ca.duration_hours, 87600);
        assert!(ca.groups.contains(&"yacht".to_string()));
    }

    #[test]
    fn test_lighthouse_config() {
        let lighthouse = LighthouseConfig {
            nebula_ip: "10.42.0.1".to_string(),
            public_host: "lighthouse.example.com".to_string(),
            public_port: 4242,
            is_primary: true,
        };
        assert!(lighthouse.is_primary);
    }
}
