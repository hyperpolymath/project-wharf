// SPDX-License-Identifier: PMPL-1.0
// SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>

//! # xtask - Build Tasks for Project Wharf
//!
//! This crate provides workspace-level build tasks, including:
//! - Building the eBPF XDP firewall
//! - Installing the compiled eBPF object file

use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Build tasks for Project Wharf")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build the eBPF XDP firewall (wharf-shield)
    BuildEbpf {
        /// Release mode
        #[arg(long)]
        release: bool,
    },
    /// Install the eBPF object file to /etc/wharf/
    InstallEbpf,
    /// Build everything (eBPF + userspace)
    BuildAll {
        /// Release mode
        #[arg(long)]
        release: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::BuildEbpf { release } => build_ebpf(release),
        Commands::InstallEbpf => install_ebpf(),
        Commands::BuildAll { release } => {
            build_ebpf(release)?;
            build_userspace(release)?;
            Ok(())
        }
    }
}

/// Get the workspace root directory
fn workspace_root() -> Result<PathBuf> {
    let output = Command::new("cargo")
        .args(["locate-project", "--workspace", "--message-format=plain"])
        .output()
        .context("Failed to run cargo locate-project")?;

    let path = String::from_utf8(output.stdout)
        .context("Invalid UTF-8 in cargo output")?;

    Ok(PathBuf::from(path.trim()).parent().unwrap().to_path_buf())
}

/// Build the eBPF XDP firewall
fn build_ebpf(release: bool) -> Result<()> {
    let workspace = workspace_root()?;
    let ebpf_dir = workspace.join("crates/wharf-ebpf");

    println!("Building eBPF XDP firewall...");
    println!("  Directory: {}", ebpf_dir.display());

    // Check for required tools
    check_bpf_linker()?;
    check_rust_nightly()?;

    // Build with nightly and the eBPF target
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir)
        .args(["+nightly", "build", "--target", "bpfel-unknown-none", "-Z", "build-std=core"]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("Failed to run cargo build for eBPF")?;

    if !status.success() {
        bail!("eBPF build failed");
    }

    // Find the built object file
    let profile = if release { "release" } else { "debug" };
    let obj_path = ebpf_dir
        .join("target/bpfel-unknown-none")
        .join(profile)
        .join("wharf-shield");

    if obj_path.exists() {
        println!("eBPF program built successfully: {}", obj_path.display());

        // Copy to workspace root as wharf-shield.o
        let dest = workspace.join("wharf-shield.o");
        std::fs::copy(&obj_path, &dest)
            .context("Failed to copy eBPF object file")?;
        println!("Copied to: {}", dest.display());
    } else {
        bail!("eBPF object file not found at {}", obj_path.display());
    }

    Ok(())
}

/// Check if bpf-linker is installed
fn check_bpf_linker() -> Result<()> {
    let status = Command::new("bpf-linker")
        .arg("--version")
        .output();

    match status {
        Ok(output) if output.status.success() => Ok(()),
        _ => {
            eprintln!("Error: bpf-linker not found");
            eprintln!("Install with: cargo install bpf-linker");
            bail!("bpf-linker not installed");
        }
    }
}

/// Check if rust nightly is available
fn check_rust_nightly() -> Result<()> {
    let status = Command::new("rustup")
        .args(["run", "nightly", "rustc", "--version"])
        .output();

    match status {
        Ok(output) if output.status.success() => Ok(()),
        _ => {
            eprintln!("Error: Rust nightly not installed");
            eprintln!("Install with: rustup install nightly");
            eprintln!("Also run: rustup component add rust-src --toolchain nightly");
            bail!("Rust nightly not available");
        }
    }
}

/// Install the eBPF object file to /etc/wharf/
fn install_ebpf() -> Result<()> {
    let workspace = workspace_root()?;
    let src = workspace.join("wharf-shield.o");

    if !src.exists() {
        bail!("wharf-shield.o not found. Run 'cargo xtask build-ebpf' first");
    }

    let dest_dir = PathBuf::from("/etc/wharf");
    let dest = dest_dir.join("wharf-shield.o");

    // Create directory if it doesn't exist (requires sudo)
    if !dest_dir.exists() {
        println!("Creating /etc/wharf/ (requires sudo)...");
        let status = Command::new("sudo")
            .args(["mkdir", "-p", "/etc/wharf"])
            .status()
            .context("Failed to create /etc/wharf")?;

        if !status.success() {
            bail!("Failed to create /etc/wharf directory");
        }
    }

    // Copy the file (requires sudo)
    println!("Installing wharf-shield.o to /etc/wharf/ (requires sudo)...");
    let status = Command::new("sudo")
        .args(["cp", src.to_str().unwrap(), dest.to_str().unwrap()])
        .status()
        .context("Failed to copy eBPF object file")?;

    if !status.success() {
        bail!("Failed to install eBPF object file");
    }

    println!("eBPF firewall installed to: {}", dest.display());
    Ok(())
}

/// Build userspace components
fn build_userspace(release: bool) -> Result<()> {
    println!("Building userspace components...");

    let mut cmd = Command::new("cargo");
    cmd.args(["build", "--workspace", "--exclude", "wharf-ebpf"]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("Failed to build userspace")?;

    if !status.success() {
        bail!("Userspace build failed");
    }

    println!("Userspace components built successfully");
    Ok(())
}
