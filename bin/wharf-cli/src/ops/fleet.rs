// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>

//! # Fleet Operations
//!
//! Fleet management commands.

use std::path::Path;
use anyhow::{Context, Result};
use tracing::info;

use wharf_core::fleet::{Fleet, Yacht, Adapter};

/// Load fleet configuration from file
pub fn load_fleet(config_path: &Path) -> Result<Fleet> {
    if config_path.exists() {
        Fleet::load(config_path)
            .context("Failed to load fleet configuration")
    } else {
        info!("No fleet configuration found, using defaults");
        Ok(Fleet::default())
    }
}

/// Save fleet configuration to file
pub fn save_fleet(fleet: &Fleet, config_path: &Path) -> Result<()> {
    fleet.save(config_path)
        .context("Failed to save fleet configuration")
}

/// Add a new yacht to the fleet
pub fn add_yacht(
    fleet: &mut Fleet,
    name: &str,
    ip: &str,
    domain: &str,
    adapter: &str,
) -> Result<()> {
    // Check if yacht already exists
    if fleet.get_yacht(name).is_some() {
        anyhow::bail!("Yacht '{}' already exists", name);
    }

    let adapter_type = match adapter.to_lowercase().as_str() {
        "wordpress" => Adapter::WordPress,
        "drupal" => Adapter::Drupal,
        "moodle" => Adapter::Moodle,
        "joomla" => Adapter::Joomla,
        "custom" => Adapter::Custom,
        _ => anyhow::bail!("Unknown adapter type: {}", adapter),
    };

    let mut yacht = Yacht::new(name, ip, domain);
    yacht.adapter = adapter_type;

    fleet.add_yacht(yacht);
    info!("Added yacht '{}' to fleet", name);

    Ok(())
}

/// Remove a yacht from the fleet
pub fn remove_yacht(fleet: &mut Fleet, name: &str) -> Result<()> {
    if fleet.remove_yacht(name).is_none() {
        anyhow::bail!("Yacht '{}' not found", name);
    }
    info!("Removed yacht '{}' from fleet", name);
    Ok(())
}

/// List all yachts in the fleet
pub fn list_yachts(fleet: &Fleet, detailed: bool) {
    let yachts = fleet.list_yachts();

    if yachts.is_empty() {
        println!("No yachts in fleet.");
        println!("Add one with: wharf fleet add <name> --ip <ip> --domain <domain>");
        return;
    }

    if detailed {
        println!("{:<15} {:<16} {:<25} {:<10} {:<8}",
                 "NAME", "IP", "DOMAIN", "ADAPTER", "STATUS");
        println!("{}", "-".repeat(80));

        for name in yachts {
            if let Some(yacht) = fleet.get_yacht(name) {
                let status = if yacht.enabled { "enabled" } else { "disabled" };
                let adapter = format!("{:?}", yacht.adapter).to_lowercase();
                println!("{:<15} {:<16} {:<25} {:<10} {:<8}",
                         yacht.name, yacht.ip, yacht.domain, adapter, status);
            }
        }
    } else {
        for name in yachts {
            println!("{}", name);
        }
    }
}

/// Show status of a specific yacht or all yachts
pub fn show_status(fleet: &Fleet, name: &str) {
    if name == "all" {
        for yacht in fleet.list_enabled() {
            print_yacht_status(yacht);
            println!();
        }
    } else if let Some(yacht) = fleet.get_yacht(name) {
        print_yacht_status(yacht);
    } else {
        println!("Yacht '{}' not found", name);
    }
}

fn print_yacht_status(yacht: &Yacht) {
    println!("Yacht: {}", yacht.name);
    println!("  Domain:   {}", yacht.domain);
    println!("  IP:       {}", yacht.ip);
    println!("  SSH:      {}:{}", yacht.ssh_user, yacht.ssh_port);
    println!("  Adapter:  {:?}", yacht.adapter);
    println!("  Database: {} ({}:{})",
             yacht.database.variant,
             yacht.database.public_port,
             yacht.database.shadow_port);
    println!("  Enabled:  {}", yacht.enabled);

    if !yacht.tags.is_empty() {
        println!("  Tags:     {}", yacht.tags.join(", "));
    }
}
