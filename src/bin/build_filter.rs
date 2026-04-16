//! CLI tool to build a serialized XOR16 filter from blocklist files.
//!
//! Usage:
//!   build_filter -o filter.bin blocklist1.txt blocklist2.txt ...
//!   build_filter --stats blocklist.txt
//!
//! Reads one or more blocklist files (hosts/domains/adblock format),
//! deduplicates domains, builds a compact XOR16 filter, and writes
//! the serialized binary to the output path.
//!
//! This binary is intended to run at CI/server time. The output
//! `filter.bin` is distributed to devices via OTA or app bundle.

use std::fs;
use std::process;

use halal_filter::{merge_results, parse_blocklist, BlocklistFilter};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage(&args[0]);
        process::exit(1);
    }

    let mut output_path = "filter.bin".to_string();
    let mut input_files: Vec<String> = Vec::new();
    let mut stats_only = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: -o requires an argument");
                    process::exit(1);
                }
                output_path = args[i].clone();
            }
            "--stats" => {
                stats_only = true;
            }
            "-h" | "--help" => {
                print_usage(&args[0]);
                process::exit(0);
            }
            arg if arg.starts_with('-') => {
                eprintln!("error: unknown option: {arg}");
                process::exit(1);
            }
            _ => {
                input_files.push(args[i].clone());
            }
        }
        i += 1;
    }

    if input_files.is_empty() {
        eprintln!("error: no input files specified");
        print_usage(&args[0]);
        process::exit(1);
    }

    // Parse all input files
    let mut results = Vec::new();
    for path in &input_files {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("error: cannot read {path}: {e}");
                process::exit(1);
            }
        };

        eprintln!("parsing: {path}");
        let result = parse_blocklist(&content);
        eprintln!(
            "  {} blocked, {} allowed, {} skipped, {} errors",
            result.blocked.len(),
            result.allowed.len(),
            result.lines_skipped,
            result.errors.len()
        );

        for error in &result.errors {
            eprintln!("  warn: line {}: {} — {}", error.line_number, error.reason, error.line);
        }

        results.push(result);
    }

    // Merge and deduplicate
    let merged = merge_results(&results);
    eprintln!("\nmerged:");
    eprintln!("  {} unique blocked domains", merged.blocked.len());
    eprintln!("  {} unique allowed domains", merged.allowed.len());
    eprintln!(
        "  {} total lines processed",
        merged.lines_processed
    );

    if stats_only {
        // Print top blocked domains (first 20) for review
        eprintln!("\nsample blocked domains:");
        for domain in merged.blocked.iter().take(20) {
            eprintln!("  {domain}");
        }
        if merged.blocked.len() > 20 {
            eprintln!("  ... and {} more", merged.blocked.len() - 20);
        }
        return;
    }

    if merged.blocked.is_empty() {
        eprintln!("error: no domains to block after parsing");
        process::exit(1);
    }

    // Build filter
    eprintln!("\nbuilding XOR16 filter...");
    let refs: Vec<&str> = merged.blocked.iter().map(|s| s.as_str()).collect();
    let filter = match BlocklistFilter::build(refs.into_iter()) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: failed to build filter: {e}");
            process::exit(1);
        }
    };

    eprintln!("  {} domains in filter", filter.domain_count());

    // Serialize
    let bytes = match filter.to_bytes() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: failed to serialize filter: {e}");
            process::exit(1);
        }
    };

    eprintln!(
        "  filter size: {} bytes ({:.2} KB)",
        bytes.len(),
        bytes.len() as f64 / 1024.0
    );

    // Write output
    if let Err(e) = fs::write(&output_path, &bytes) {
        eprintln!("error: cannot write {output_path}: {e}");
        process::exit(1);
    }

    eprintln!("\nwritten: {output_path}");

    // Write allowlist as separate file if any
    if !merged.allowed.is_empty() {
        let allowlist_path = output_path.replace(".bin", ".allowlist.txt");
        let allowlist_content = merged.allowed.join("\n");
        if let Err(e) = fs::write(&allowlist_path, &allowlist_content) {
            eprintln!("warn: cannot write allowlist file: {e}");
        } else {
            eprintln!("written: {allowlist_path} ({} domains)", merged.allowed.len());
        }
    }
}

fn print_usage(program: &str) {
    eprintln!("halal-filter build tool");
    eprintln!();
    eprintln!("usage: {program} [OPTIONS] <blocklist-files...>");
    eprintln!();
    eprintln!("options:");
    eprintln!("  -o, --output <path>   Output file (default: filter.bin)");
    eprintln!("  --stats               Parse and show statistics only (no build)");
    eprintln!("  -h, --help            Show this help");
    eprintln!();
    eprintln!("supported formats:");
    eprintln!("  hosts     — 0.0.0.0 domain.com (StevenBlack)");
    eprintln!("  domains   — one domain per line (HaGeZi)");
    eprintln!("  adblock   — ||domain.com^ (AdGuard)");
}
