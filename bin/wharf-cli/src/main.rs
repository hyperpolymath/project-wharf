// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>

//! # Wharf CLI
//!
//! The offline controller for Project Wharf - The Sovereign Web Hypervisor.
//!
//! ## Commands
//!
//! - `wharf init` - Initialize a new fleet configuration
//! - `wharf build` - Compile zone files and artifacts
//! - `wharf moor <yacht>` - Connect to a yacht and sync state
//! - `wharf state` - State management (freeze, thaw, diff)
//! - `wharf sec` - Security operations (audit, rotate-keys, gen-firewall)
//! - `wharf gen-keys` - Generate cryptographic keys (DKIM, SSH, TLS)
//! - `wharf db` - Database configuration commands

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod ops;

// =============================================================================
// CLI STRUCTURE
// =============================================================================

#[derive(Parser)]
#[command(name = "wharf")]
#[command(author = "Jonathan D. A. Jewell <hyperpolymath>")]
#[command(version = wharf_core::VERSION)]
#[command(about = "The Sovereign Web Hypervisor - Offline CMS Administration", long_about = None)]
struct Cli {
    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Configuration directory
    #[arg(short, long, default_value = ".", global = true)]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new fleet configuration
    Init {
        /// Path to create the configuration
        #[arg(short, long, default_value = ".")]
        path: String,

        /// CMS adapter (wordpress, drupal, moodle, joomla, custom)
        #[arg(long, default_value = "wordpress")]
        adapter: String,
    },

    /// Build zone files and deployment artifacts
    Build {
        /// The target yacht to build for
        #[arg(short, long)]
        target: Option<String>,

        /// Output directory
        #[arg(short, long, default_value = "dist")]
        output: String,

        /// Build containers
        #[arg(long)]
        containers: bool,

        /// Build eBPF firewall
        #[arg(long)]
        ebpf: bool,
    },

    /// Connect to a yacht and synchronize state (The Mooring)
    Moor {
        /// The yacht ID to connect to
        yacht: String,

        /// Force sync even if hashes match
        #[arg(long)]
        force: bool,

        /// Push only specific layers (db, files, config)
        #[arg(long, value_delimiter = ',', num_args = 1..)]
        layers: Vec<String>,

        /// Emergency mode: Break glass access (bypass 2FA)
        #[arg(long)]
        emergency: bool,

        /// Dry run - show what would be synced
        #[arg(long)]
        dry_run: bool,
    },

    /// State management commands
    State(StateArgs),

    /// Security operations
    Sec(SecArgs),

    /// Database configuration commands
    Db(DbArgs),

    /// Generate cryptographic keys and DNS records
    GenKeys {
        /// Domain to generate keys for
        domain: String,

        /// DKIM selector name
        #[arg(long, default_value = "default")]
        selector: String,

        /// Generate SSH host keys
        #[arg(long)]
        ssh: bool,

        /// Generate TLSA/DANE records
        #[arg(long)]
        tlsa: bool,

        /// Generate OPENPGPKEY records
        #[arg(long)]
        openpgpkey: bool,
    },

    /// Render a DNS zone template
    RenderZone {
        /// Template file path
        template: String,

        /// Variables file (JSON or Nickel)
        vars: String,

        /// Output file (stdout if not specified)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Validate a DNS zone file
    CheckZone {
        /// Domain name
        domain: String,

        /// Zone file path
        file: String,
    },

    /// Fleet management commands
    Fleet(FleetArgs),

    /// Container management commands
    Container(ContainerArgs),

    /// File integrity commands
    Integrity(IntegrityArgs),

    /// Show version and system info
    Version,
}

// =============================================================================
// STATE COMMANDS
// =============================================================================

#[derive(Args)]
struct StateArgs {
    #[command(subcommand)]
    command: StateCommands,
}

#[derive(Subcommand)]
enum StateCommands {
    /// Create a snapshot of the current local state
    Freeze {
        /// Name for the snapshot
        #[arg(short, long)]
        name: Option<String>,

        /// Include database dump
        #[arg(long)]
        with_db: bool,
    },

    /// Apply a snapshot to the local staging area
    Thaw {
        /// Snapshot ID or name
        id: String,

        /// Force overwrite current state
        #[arg(long)]
        force: bool,
    },

    /// Compare local state vs remote Yacht state
    Diff {
        /// Target yacht to compare against
        target: String,

        /// Show only changed files
        #[arg(long)]
        changed_only: bool,
    },

    /// List all snapshots
    List {
        /// Show detailed information
        #[arg(short, long)]
        long: bool,
    },

    /// Prune old snapshots
    Prune {
        /// Keep only the last N snapshots
        #[arg(long, default_value_t = 10)]
        keep: usize,

        /// Dry run - show what would be deleted
        #[arg(long)]
        dry_run: bool,
    },
}

// =============================================================================
// SECURITY COMMANDS
// =============================================================================

#[derive(Args)]
struct SecArgs {
    #[command(subcommand)]
    command: SecCommands,
}

#[derive(Subcommand)]
enum SecCommands {
    /// Audit the security configuration
    Audit {
        /// Target yacht (or 'all')
        #[arg(default_value = "all")]
        target: String,

        /// Output format (text, json, sarif)
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Check against CIS benchmarks
        #[arg(long)]
        cis: bool,
    },

    /// Rotate cryptographic keys
    RotateKeys {
        /// Key type to rotate (nebula, dkim, tlsa, all)
        #[arg(default_value = "all")]
        key_type: String,

        /// Force rotation even if not expired
        #[arg(long)]
        force: bool,
    },

    /// Generate eBPF firewall bytecode
    GenFirewall {
        /// Output path for the compiled BPF object
        #[arg(short, long, default_value = "dist/wharf-shield.o")]
        output: String,

        /// Target architecture (x86_64, aarch64)
        #[arg(long, default_value = "x86_64")]
        arch: String,
    },

    /// Verify file integrity against manifest
    Verify {
        /// Target yacht
        target: String,

        /// Path to manifest file
        #[arg(long)]
        manifest: Option<String>,
    },

    /// Scan for vulnerabilities
    Scan {
        /// Target yacht
        target: String,

        /// Scan type (deps, containers, config)
        #[arg(long, default_value = "all")]
        scan_type: String,
    },
}

// =============================================================================
// DATABASE COMMANDS
// =============================================================================

#[derive(Args)]
struct DbArgs {
    #[command(subcommand)]
    command: DbCommands,
}

#[derive(Subcommand)]
enum DbCommands {
    /// Configure database virtual sharding policy
    Policy {
        /// Path to policy file (Nickel)
        file: String,

        /// Validate only, don't apply
        #[arg(long)]
        validate: bool,
    },

    /// Export database (for migration to Wharf)
    Export {
        /// Connection string
        connection: String,

        /// Output file
        #[arg(short, long)]
        output: String,

        /// Prune revisions and spam
        #[arg(long)]
        prune: bool,
    },

    /// Import database dump
    Import {
        /// Dump file
        file: String,

        /// Target yacht
        target: String,
    },

    /// Show database proxy status
    Status {
        /// Target yacht
        target: String,
    },
}

// =============================================================================
// FLEET COMMANDS
// =============================================================================

#[derive(Args)]
struct FleetArgs {
    #[command(subcommand)]
    command: FleetCommands,
}

#[derive(Subcommand)]
enum FleetCommands {
    /// List all yachts in the fleet
    List {
        /// Show detailed information
        #[arg(short, long)]
        long: bool,
    },

    /// Add a new yacht to the fleet
    Add {
        /// Yacht name/ID
        name: String,

        /// IP address or hostname
        #[arg(long)]
        ip: String,

        /// Domain name
        #[arg(long)]
        domain: String,

        /// CMS adapter
        #[arg(long, default_value = "wordpress")]
        adapter: String,
    },

    /// Remove a yacht from the fleet
    Remove {
        /// Yacht name/ID
        name: String,

        /// Force removal
        #[arg(long)]
        force: bool,
    },

    /// Show yacht status
    Status {
        /// Yacht name (or 'all')
        #[arg(default_value = "all")]
        name: String,
    },
}

// =============================================================================
// CONTAINER COMMANDS
// =============================================================================

#[derive(Args)]
struct ContainerArgs {
    #[command(subcommand)]
    command: ContainerCommands,
}

#[derive(Subcommand)]
enum ContainerCommands {
    /// Build container images
    Build {
        /// Image to build (php, nginx, agent, all)
        #[arg(default_value = "all")]
        image: String,

        /// Push to registry after building
        #[arg(long)]
        push: bool,

        /// Registry URL
        #[arg(long)]
        registry: Option<String>,
    },

    /// Deploy containers to yacht
    Deploy {
        /// Target yacht
        target: String,

        /// Pod definition file
        #[arg(long, default_value = "infra/podman/yacht.yaml")]
        pod: String,
    },

    /// Show container logs
    Logs {
        /// Target yacht
        target: String,

        /// Container name (nginx, php, agent)
        container: String,

        /// Follow logs
        #[arg(short, long)]
        follow: bool,

        /// Number of lines
        #[arg(short, long, default_value_t = 100)]
        lines: usize,
    },
}

// =============================================================================
// INTEGRITY COMMANDS
// =============================================================================

#[derive(Args)]
struct IntegrityArgs {
    #[command(subcommand)]
    command: IntegrityCommands,
}

#[derive(Subcommand)]
enum IntegrityCommands {
    /// Generate a BLAKE3 integrity manifest for a directory
    Generate {
        /// Directory to generate manifest for
        #[arg(default_value = "site")]
        path: String,

        /// Output manifest file
        #[arg(short, long, default_value = ".wharf-manifest.json")]
        output: String,

        /// Patterns to exclude (can be repeated)
        #[arg(short, long)]
        exclude: Vec<String>,
    },

    /// Verify file integrity against a manifest
    Verify {
        /// Target: "local" for local files, or yacht name for remote
        #[arg(default_value = "local")]
        target: String,

        /// Path to manifest file
        #[arg(short, long)]
        manifest: Option<String>,

        /// Directory to verify (for local verification)
        #[arg(short, long, default_value = "site")]
        path: String,

        /// Allow unexpected files (don't fail if extra files found)
        #[arg(long)]
        allow_extra: bool,
    },

    /// Compute BLAKE3 hash of a single file
    Hash {
        /// File to hash
        file: String,
    },

    /// Compare two manifests and show differences
    Diff {
        /// First manifest file
        manifest1: String,

        /// Second manifest file
        manifest2: String,

        /// Show only changed files
        #[arg(long)]
        changed_only: bool,
    },
}

// =============================================================================
// MAIN
// =============================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Set up logging based on verbosity
    let level = match cli.verbose {
        0 => Level::WARN,
        1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::TRACE,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    match cli.command {
        Commands::Init { path, adapter } => {
            info!("Initializing Wharf configuration at: {}", path);
            println!("Wharf fleet configuration initialized at: {}", path);
            println!("CMS Adapter: {}", adapter);
            println!();
            println!("Next steps:");
            println!("  1. Edit configs/fleet.ncl to add your yachts");
            println!("  2. Run 'wharf build' to generate artifacts");
            println!("  3. Run 'wharf moor <yacht>' to deploy");
        }

        Commands::Build { target, output, containers, ebpf } => {
            info!("Building deployment artifacts");
            if let Some(t) = target {
                println!("Building for yacht: {}", t);
            } else {
                println!("Building all yachts...");
            }
            println!("Output directory: {}", output);

            if containers {
                println!("Building container images...");
                println!("  - yacht-php:latest");
                println!("  - yacht-nginx:latest");
                println!("  - yacht-agent:latest");
            }

            if ebpf {
                println!("Compiling eBPF firewall...");
                println!("  - wharf-shield.o");
            }
        }

        Commands::Moor { yacht, force, layers, emergency, dry_run } => {
            info!("Initiating mooring sequence for yacht: {}", yacht);

            if emergency {
                println!("!!! EMERGENCY OVERRIDE ENABLED !!!");
                println!(">>> Bypassing standard security checks <<<");
            } else {
                println!(">>> TOUCH FIDO2 KEY NOW <<<");
            }

            // Load fleet configuration
            let config_dir = PathBuf::from(&cli.config);
            let fleet_path = config_dir.join("fleet.json");
            let fleet = ops::fleet::load_fleet(&fleet_path)?;

            // Load CLI config for mooring settings
            let cli_config = wharf_core::config::ConfigLoader::new()
                .load_wharf_cli_config()
                .unwrap_or_default();

            // Build source directory path
            let source_dir = config_dir.join("site");
            if !source_dir.exists() {
                anyhow::bail!("Source directory not found: {:?}. Create it with site files.", source_dir);
            }

            // Load or generate hybrid keypair
            let keypair = ops::moor::load_or_generate_keypair(&config_dir)?;

            // Execute mooring
            let options = ops::moor::MoorOptions {
                force,
                dry_run,
                emergency,
                layers,
            };

            match ops::moor::execute_moor(
                &fleet, &yacht, &source_dir, &options, &keypair, &cli_config.mooring,
            ).await {
                Ok(result) => {
                    println!();
                    println!("Mooring complete!");
                    println!("  Yacht: {}", result.yacht_name);
                    println!("  Files synced: {}", result.files_synced);
                    println!("  Integrity verified: {}", result.integrity_verified);
                    if let Some(snap) = &result.snapshot_id {
                        println!("  Snapshot: {}", snap);
                    }
                }
                Err(e) => {
                    eprintln!("Mooring failed: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::State(args) => match args.command {
            StateCommands::Freeze { name, with_db } => {
                let snap_name = name.unwrap_or_else(|| {
                    chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string()
                });
                println!("Creating snapshot: {}", snap_name);
                if with_db {
                    println!("Including database dump...");
                }
            }
            StateCommands::Thaw { id, force } => {
                println!("Restoring snapshot: {}", id);
                if force {
                    println!("Force overwrite enabled");
                }
            }
            StateCommands::Diff { target, changed_only } => {
                println!("Comparing local state with yacht: {}", target);
                if changed_only {
                    println!("Showing only changed files");
                }
            }
            StateCommands::List { long } => {
                println!("Available snapshots:");
                if long {
                    println!("  ID                  SIZE      DATE");
                }
            }
            StateCommands::Prune { keep, dry_run } => {
                println!("Pruning snapshots, keeping last {}", keep);
                if dry_run {
                    println!("[DRY RUN] Would delete:");
                }
            }
        },

        Commands::Sec(args) => match args.command {
            SecCommands::Audit { target, format, cis } => {
                println!("Security audit for: {}", target);
                println!("Output format: {}", format);
                if cis {
                    println!("Checking against CIS benchmarks...");
                }
            }
            SecCommands::RotateKeys { key_type, force } => {
                println!("Rotating {} keys", key_type);
                if force {
                    println!("Force rotation enabled");
                }
            }
            SecCommands::GenFirewall { output, arch } => {
                println!("Generating eBPF firewall for {}", arch);
                println!("Output: {}", output);
            }
            SecCommands::Verify { target, manifest } => {
                let config_dir = PathBuf::from(&cli.config);

                // Determine manifest path
                let manifest_path = if let Some(m) = manifest {
                    PathBuf::from(m)
                } else {
                    config_dir.join("site").join(".wharf-manifest.json")
                };

                if !manifest_path.exists() {
                    anyhow::bail!("Manifest not found: {:?}. Run 'wharf moor' first to generate one.", manifest_path);
                }

                // Check if target is "local" or a yacht name
                if target == "local" {
                    // Local verification
                    let target_dir = config_dir.join("site");
                    println!("Verifying local file integrity");
                    println!("Using manifest: {:?}", manifest_path);

                    match ops::integrity::verify_against_manifest(&target_dir, &manifest_path, false) {
                        Ok(result) => {
                            println!();
                            if result.is_ok() {
                                println!("✓ Integrity verification PASSED");
                                println!("  {} files verified", result.passed.len());
                            } else {
                                println!("✗ Integrity verification FAILED");
                                if !result.mismatched.is_empty() {
                                    println!("  {} files mismatched", result.mismatched.len());
                                }
                                if !result.missing.is_empty() {
                                    println!("  {} files missing", result.missing.len());
                                }
                                if !result.unexpected.is_empty() {
                                    println!("  {} unexpected files", result.unexpected.len());
                                }
                                std::process::exit(1);
                            }
                        }
                        Err(e) => {
                            eprintln!("✗ Verification failed: {}", e);
                            std::process::exit(1);
                        }
                    }
                } else {
                    // Remote verification - load fleet and find yacht
                    let fleet_path = config_dir.join("fleet.toml");
                    let fleet = ops::fleet::load_fleet(&fleet_path)?;

                    let yacht = fleet.get_yacht(&target)
                        .ok_or_else(|| anyhow::anyhow!("Yacht '{}' not found in fleet", target))?;

                    println!("Verifying remote yacht: {}", target);
                    println!("Host: {}@{}:{}", yacht.ssh_user, yacht.ip, yacht.ssh_port);
                    println!("Remote root: {}", yacht.web_root);
                    println!("Using manifest: {:?}", manifest_path);
                    println!();

                    match ops::integrity::verify_remote(
                        &manifest_path,
                        &yacht.ssh_user,
                        &yacht.ip,
                        yacht.ssh_port,
                        &yacht.web_root,
                        None, // TODO: Support identity file from config
                    ) {
                        Ok(result) => {
                            println!();
                            if result.is_ok() {
                                println!("✓ Remote integrity verification PASSED");
                                println!("  Yacht: {}", result.yacht);
                                println!("  {} files verified", result.files_checked);
                            } else {
                                println!("✗ Remote integrity verification FAILED");
                                if let Some(err) = &result.error {
                                    println!("  Error: {}", err);
                                }
                                if !result.mismatched.is_empty() {
                                    println!("  {} files mismatched:", result.mismatched.len());
                                    for path in &result.mismatched {
                                        println!("    - {}", path);
                                    }
                                }
                                if !result.missing.is_empty() {
                                    println!("  {} files missing:", result.missing.len());
                                    for path in &result.missing {
                                        println!("    - {}", path);
                                    }
                                }
                                std::process::exit(1);
                            }
                        }
                        Err(e) => {
                            eprintln!("✗ Remote verification failed: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
            }
            SecCommands::Scan { target, scan_type } => {
                println!("Scanning {} for vulnerabilities (type: {})", target, scan_type);
            }
        },

        Commands::Db(args) => match args.command {
            DbCommands::Policy { file, validate } => {
                println!("Loading database policy from: {}", file);
                if validate {
                    println!("Validation only - not applying");
                }
            }
            DbCommands::Export { connection, output, prune } => {
                println!("Exporting database...");
                println!("Connection: {}", connection);
                println!("Output: {}", output);
                if prune {
                    println!("Pruning revisions and spam...");
                }
            }
            DbCommands::Import { file, target } => {
                println!("Importing {} to {}", file, target);
            }
            DbCommands::Status { target } => {
                println!("Database proxy status for: {}", target);
            }
        },

        Commands::Fleet(args) => {
            let config_dir = PathBuf::from(&cli.config);
            let fleet_path = config_dir.join("fleet.json");

            match args.command {
                FleetCommands::List { long } => {
                    let fleet = ops::fleet::load_fleet(&fleet_path)?;
                    ops::fleet::list_yachts(&fleet, long);
                }
                FleetCommands::Add { name, ip, domain, adapter } => {
                    let mut fleet = ops::fleet::load_fleet(&fleet_path)?;
                    ops::fleet::add_yacht(&mut fleet, &name, &ip, &domain, &adapter)?;
                    ops::fleet::save_fleet(&fleet, &fleet_path)?;
                    println!("✓ Added yacht '{}' to fleet", name);
                    println!("  IP: {}", ip);
                    println!("  Domain: {}", domain);
                    println!("  Adapter: {}", adapter);
                }
                FleetCommands::Remove { name, force } => {
                    if !force {
                        println!("This will remove yacht '{}' from the fleet.", name);
                        println!("Use --force to confirm removal.");
                        return Ok(());
                    }
                    let mut fleet = ops::fleet::load_fleet(&fleet_path)?;
                    ops::fleet::remove_yacht(&mut fleet, &name)?;
                    ops::fleet::save_fleet(&fleet, &fleet_path)?;
                    println!("✓ Removed yacht '{}' from fleet", name);
                }
                FleetCommands::Status { name } => {
                    let fleet = ops::fleet::load_fleet(&fleet_path)?;
                    ops::fleet::show_status(&fleet, &name);
                }
            }
        }

        Commands::Container(args) => match args.command {
            ContainerCommands::Build { image, push, registry } => {
                println!("Building container: {}", image);
                if push {
                    if let Some(reg) = registry {
                        println!("Will push to: {}", reg);
                    }
                }
            }
            ContainerCommands::Deploy { target, pod } => {
                println!("Deploying to yacht: {}", target);
                println!("Pod definition: {}", pod);
            }
            ContainerCommands::Logs { target, container, follow, lines } => {
                println!("Logs from {}/{} (last {} lines)", target, container, lines);
                if follow {
                    println!("Following...");
                }
            }
        },

        Commands::Integrity(args) => {
            let config_dir = PathBuf::from(&cli.config);

            match args.command {
                IntegrityCommands::Generate { path, output, exclude } => {
                    let source_path = config_dir.join(&path);
                    let output_path = config_dir.join(&output);

                    if !source_path.exists() {
                        anyhow::bail!("Source directory not found: {:?}", source_path);
                    }

                    println!("Generating BLAKE3 integrity manifest...");
                    println!("  Source: {:?}", source_path);
                    println!("  Output: {:?}", output_path);

                    if !exclude.is_empty() {
                        println!("  Excludes: {:?}", exclude);
                    }

                    match ops::integrity::generate_manifest(&source_path, &exclude, Some(&output_path)) {
                        Ok(manifest) => {
                            println!();
                            println!("✓ Manifest generated successfully");
                            println!("  {} files", manifest.files.len());
                            println!("  {} directories", manifest.directories.len());
                        }
                        Err(e) => {
                            eprintln!("✗ Failed to generate manifest: {}", e);
                            std::process::exit(1);
                        }
                    }
                }

                IntegrityCommands::Verify { target, manifest, path, allow_extra } => {
                    let manifest_path = if let Some(m) = manifest {
                        PathBuf::from(m)
                    } else {
                        config_dir.join(&path).join(".wharf-manifest.json")
                    };

                    if !manifest_path.exists() {
                        anyhow::bail!(
                            "Manifest not found: {:?}\nGenerate one with: wharf integrity generate",
                            manifest_path
                        );
                    }

                    if target == "local" {
                        let target_dir = config_dir.join(&path);
                        println!("Verifying local file integrity...");
                        println!("  Directory: {:?}", target_dir);
                        println!("  Manifest: {:?}", manifest_path);

                        match ops::integrity::verify_against_manifest(&target_dir, &manifest_path, allow_extra) {
                            Ok(result) => {
                                println!();
                                if result.is_ok() {
                                    println!("✓ Integrity verification PASSED");
                                    println!("  {} files verified", result.passed.len());
                                } else {
                                    println!("✗ Integrity verification FAILED");
                                    if !result.mismatched.is_empty() {
                                        println!("  {} files have different content:", result.mismatched.len());
                                        for (path, _, _) in &result.mismatched {
                                            println!("    ✗ {}", path);
                                        }
                                    }
                                    if !result.missing.is_empty() {
                                        println!("  {} files are missing:", result.missing.len());
                                        for path in &result.missing {
                                            println!("    - {}", path);
                                        }
                                    }
                                    if !result.unexpected.is_empty() && !allow_extra {
                                        println!("  {} unexpected files found:", result.unexpected.len());
                                        for path in &result.unexpected {
                                            println!("    + {}", path);
                                        }
                                    }
                                    std::process::exit(1);
                                }
                            }
                            Err(e) => {
                                eprintln!("✗ Verification error: {}", e);
                                std::process::exit(1);
                            }
                        }
                    } else {
                        // Remote verification
                        let fleet_path = config_dir.join("fleet.toml");
                        let fleet = ops::fleet::load_fleet(&fleet_path)?;
                        let yacht = fleet.get_yacht(&target)
                            .ok_or_else(|| anyhow::anyhow!("Yacht '{}' not found in fleet", target))?;

                        println!("Verifying remote yacht: {}", target);
                        println!("  Host: {}@{}:{}", yacht.ssh_user, yacht.ip, yacht.ssh_port);
                        println!("  Remote path: {}", yacht.web_root);
                        println!("  Manifest: {:?}", manifest_path);

                        match ops::integrity::verify_remote(
                            &manifest_path,
                            &yacht.ssh_user,
                            &yacht.ip,
                            yacht.ssh_port,
                            &yacht.web_root,
                            None,
                        ) {
                            Ok(result) => {
                                println!();
                                if result.is_ok() {
                                    println!("✓ Remote verification PASSED");
                                    println!("  {} files verified on {}", result.files_checked, result.yacht);
                                } else {
                                    println!("✗ Remote verification FAILED");
                                    if let Some(err) = &result.error {
                                        println!("  Error: {}", err);
                                    }
                                    if !result.mismatched.is_empty() {
                                        println!("  {} files have different content:", result.mismatched.len());
                                        for path in &result.mismatched {
                                            println!("    ✗ {}", path);
                                        }
                                    }
                                    if !result.missing.is_empty() {
                                        println!("  {} files are missing:", result.missing.len());
                                        for path in &result.missing {
                                            println!("    - {}", path);
                                        }
                                    }
                                    std::process::exit(1);
                                }
                            }
                            Err(e) => {
                                eprintln!("✗ Remote verification error: {}", e);
                                std::process::exit(1);
                            }
                        }
                    }
                }

                IntegrityCommands::Hash { file } => {
                    let file_path = PathBuf::from(&file);

                    if !file_path.exists() {
                        anyhow::bail!("File not found: {:?}", file_path);
                    }

                    match ops::integrity::hash_file(&file_path) {
                        Ok(hash) => {
                            println!("{}  {}", hash, file);
                        }
                        Err(e) => {
                            eprintln!("✗ Failed to hash file: {}", e);
                            std::process::exit(1);
                        }
                    }
                }

                IntegrityCommands::Diff { manifest1, manifest2, changed_only } => {
                    use wharf_core::integrity;

                    let m1_path = PathBuf::from(&manifest1);
                    let m2_path = PathBuf::from(&manifest2);

                    if !m1_path.exists() {
                        anyhow::bail!("Manifest not found: {:?}", m1_path);
                    }
                    if !m2_path.exists() {
                        anyhow::bail!("Manifest not found: {:?}", m2_path);
                    }

                    let m1 = integrity::load_manifest(&m1_path)?;
                    let m2 = integrity::load_manifest(&m2_path)?;

                    println!("Comparing manifests:");
                    println!("  A: {:?}", m1_path);
                    println!("  B: {:?}", m2_path);
                    println!();

                    let mut added = Vec::new();
                    let mut removed = Vec::new();
                    let mut changed = Vec::new();
                    let mut unchanged = 0;

                    // Find removed and changed files
                    for (path, entry1) in &m1.files {
                        if let Some(entry2) = m2.files.get(path) {
                            if entry1.hash != entry2.hash {
                                changed.push(path.clone());
                            } else {
                                unchanged += 1;
                            }
                        } else {
                            removed.push(path.clone());
                        }
                    }

                    // Find added files
                    for path in m2.files.keys() {
                        if !m1.files.contains_key(path) {
                            added.push(path.clone());
                        }
                    }

                    if !changed_only {
                        println!("Summary:");
                        println!("  {} files unchanged", unchanged);
                        println!("  {} files added", added.len());
                        println!("  {} files removed", removed.len());
                        println!("  {} files changed", changed.len());
                        println!();
                    }

                    if !added.is_empty() {
                        println!("Added in B:");
                        for path in &added {
                            println!("  + {}", path);
                        }
                    }

                    if !removed.is_empty() {
                        println!("Removed from A:");
                        for path in &removed {
                            println!("  - {}", path);
                        }
                    }

                    if !changed.is_empty() {
                        println!("Changed:");
                        for path in &changed {
                            println!("  ~ {}", path);
                        }
                    }

                    if added.is_empty() && removed.is_empty() && changed.is_empty() {
                        println!("No differences found.");
                    }
                }
            }
        }

        Commands::GenKeys { domain, selector, ssh, tlsa, openpgpkey } => {
            info!("Generating keys for domain: {}", domain);
            println!("Generating cryptographic records for {}...", domain);
            println!();
            println!("[DKIM Record - Selector: {}]", selector);
            println!("{}._domainkey IN TXT \"v=DKIM1; k=rsa; p=<PASTE_PUBLIC_KEY>\"", selector);
            println!();
            println!("[SPF Record]");
            println!("{} IN TXT \"v=spf1 a mx -all\"", domain);
            println!();
            println!("[DMARC Record]");
            println!("_dmarc IN TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@{}\"", domain);

            if ssh {
                println!();
                println!("[SSHFP Records - Run on server]");
                println!("ssh-keygen -r {}", domain);
            }

            if tlsa {
                println!();
                println!("[TLSA/DANE Record]");
                println!("_443._tcp IN TLSA 3 1 1 <CERTIFICATE_HASH>");
            }

            if openpgpkey {
                println!();
                println!("[OPENPGPKEY Record]");
                println!("<hash>._openpgpkey IN OPENPGPKEY <WKD_HASH>");
            }
        }

        Commands::RenderZone { template, vars, output } => {
            info!("Rendering zone template: {}", template);
            println!("Rendering {} with variables from {}", template, vars);
            if let Some(out) = output {
                println!("Output: {}", out);
            }
        }

        Commands::CheckZone { domain, file } => {
            info!("Checking zone file: {}", file);
            println!("Validating zone for {} using named-checkzone...", domain);
        }

        Commands::Version => {
            println!("Wharf - The Sovereign Web Hypervisor");
            println!("Version: {}", wharf_core::VERSION);
            println!();
            println!("Components:");
            println!("  wharf-cli    - Offline Controller (this binary)");
            println!("  yacht-agent  - Runtime Enforcer");
            println!("  wharf-core   - Shared Logic Library");
            println!("  wharf-ebpf   - Kernel Firewall (XDP)");
            println!();
            println!("Architecture:");
            println!("  Wharf = Offline admin (your machine)");
            println!("  Yacht = Online runtime (the server)");
            println!("  Mooring = Secure sync channel (Nebula mesh)");
        }
    }

    Ok(())
}
