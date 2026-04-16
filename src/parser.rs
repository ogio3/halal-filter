//! Blocklist format parser.
//!
//! Supports three standard formats used by DNS filtering communities:
//! - **Hosts**: `0.0.0.0 domain.com` or `127.0.0.1 domain.com` (StevenBlack, etc.)
//! - **Domains**: One domain per line (HaGeZi, plain lists)
//! - **AdBlock**: `||domain.com^` with `@@||domain.com^` for allowlist (AdGuard)
//!
//! Auto-detects format per line, so mixed-format files are handled gracefully.

/// Result of parsing one or more blocklist sources.
#[derive(Debug, Clone)]
pub struct ParseResult {
    pub blocked: Vec<String>,
    pub allowed: Vec<String>,
    pub lines_processed: usize,
    pub lines_skipped: usize,
    pub errors: Vec<ParseError>,
}

#[derive(Debug, Clone)]
pub struct ParseError {
    pub line_number: usize,
    pub line: String,
    pub reason: &'static str,
}

/// Parse blocklist text content into normalized domain lists.
///
/// Handles all three formats in a single pass (auto-detection per line).
/// Domains are normalized: lowercase, trimmed, trailing dot removed.
pub fn parse_blocklist(content: &str) -> ParseResult {
    let mut result = ParseResult {
        blocked: Vec::new(),
        allowed: Vec::new(),
        lines_processed: 0,
        lines_skipped: 0,
        errors: Vec::new(),
    };

    for (line_number, raw_line) in content.lines().enumerate() {
        result.lines_processed += 1;

        let line = raw_line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            result.lines_skipped += 1;
            continue;
        }

        // AdBlock allowlist: @@||domain.com^
        if let Some(rest) = line.strip_prefix("@@||") {
            if let Some(domain) = extract_adblock_domain(rest) {
                if let Some(normalized) = normalize_domain(&domain) {
                    result.allowed.push(normalized);
                } else {
                    result.errors.push(ParseError {
                        line_number: line_number + 1,
                        line: raw_line.to_string(),
                        reason: "invalid domain in adblock allowlist rule",
                    });
                }
            } else {
                result.lines_skipped += 1;
            }
            continue;
        }

        // AdBlock block rule: ||domain.com^
        if let Some(rest) = line.strip_prefix("||") {
            if let Some(domain) = extract_adblock_domain(rest) {
                if let Some(normalized) = normalize_domain(&domain) {
                    result.blocked.push(normalized);
                } else {
                    result.errors.push(ParseError {
                        line_number: line_number + 1,
                        line: raw_line.to_string(),
                        reason: "invalid domain in adblock rule",
                    });
                }
            } else {
                result.lines_skipped += 1;
            }
            continue;
        }

        // Hosts format: 0.0.0.0 domain.com or 127.0.0.1 domain.com
        if line.starts_with("0.0.0.0 ")
            || line.starts_with("0.0.0.0\t")
            || line.starts_with("127.0.0.1 ")
            || line.starts_with("127.0.0.1\t")
        {
            if let Some(domain) = extract_hosts_domain(line) {
                if let Some(normalized) = normalize_domain(&domain) {
                    // Skip localhost entries
                    if normalized != "localhost"
                        && normalized != "localhost.localdomain"
                        && normalized != "local"
                        && normalized != "broadcasthost"
                        && normalized != "ip6-localhost"
                        && normalized != "ip6-loopback"
                    {
                        result.blocked.push(normalized);
                    } else {
                        result.lines_skipped += 1;
                    }
                } else {
                    result.errors.push(ParseError {
                        line_number: line_number + 1,
                        line: raw_line.to_string(),
                        reason: "invalid domain in hosts entry",
                    });
                }
            } else {
                result.lines_skipped += 1;
            }
            continue;
        }

        // Plain domain format: just a domain per line (with optional inline comment)
        let domain_part = line.split_once('#').map(|(d, _)| d.trim()).unwrap_or(line);
        if let Some(normalized) = normalize_domain(domain_part) {
            result.blocked.push(normalized);
        } else {
            // Could be a format we don't understand (e.g., regex rules, IP-only lines)
            result.lines_skipped += 1;
        }
    }

    result
}

/// Extract domain from adblock rule like `domain.com^` or `domain.com^$third-party`.
fn extract_adblock_domain(rest: &str) -> Option<String> {
    // Find the caret separator
    let domain_end = rest.find('^').unwrap_or(rest.len());
    let domain = &rest[..domain_end];

    if domain.is_empty() {
        return None;
    }

    // Skip rules with wildcards or regex (e.g., ||*cdn*.com^)
    if domain.contains('*') || domain.contains('/') {
        return None;
    }

    Some(domain.to_string())
}

/// Extract domain from hosts file line.
/// Format: `<ip> <domain> [# comment]`
fn extract_hosts_domain(line: &str) -> Option<String> {
    // Remove inline comment
    let without_comment = line.split('#').next().unwrap_or(line).trim();

    // Split on whitespace: first token is IP, second is domain
    let mut parts = without_comment.split_whitespace();
    let _ip = parts.next()?;
    let domain = parts.next()?;

    // If there's a third token, it might be another domain on the same line
    // (some hosts files list multiple domains per IP). We take only the first.
    // Additional domains would need separate entries.
    if domain.is_empty() {
        return None;
    }

    Some(domain.to_string())
}

/// Normalize a domain string for consistent hashing.
/// Returns None if the input doesn't look like a valid domain.
fn normalize_domain(raw: &str) -> Option<String> {
    let domain = raw.trim().to_ascii_lowercase();
    let domain = domain.strip_suffix('.').unwrap_or(&domain);

    // Basic validation: must contain a dot, no spaces, no protocol
    if domain.is_empty()
        || !domain.contains('.')
        || domain.contains(' ')
        || domain.contains("://")
        || domain.contains('/')
    {
        return None;
    }

    // Must start and end with alphanumeric or hyphen-containing labels
    let labels: Vec<&str> = domain.split('.').collect();
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        // Labels must start with alphanumeric
        if !label.as_bytes()[0].is_ascii_alphanumeric() {
            return None;
        }
        // Labels must contain only alphanumeric, hyphens, underscores
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
    }

    // TLD must be at least 2 chars
    if labels.last().map(|tld| tld.len()).unwrap_or(0) < 2 {
        return None;
    }

    Some(domain.to_string())
}

/// Merge multiple ParseResults, deduplicating domains.
pub fn merge_results(results: &[ParseResult]) -> ParseResult {
    let mut blocked: Vec<String> = results.iter().flat_map(|r| r.blocked.iter().cloned()).collect();
    let mut allowed: Vec<String> = results.iter().flat_map(|r| r.allowed.iter().cloned()).collect();

    blocked.sort_unstable();
    blocked.dedup();
    allowed.sort_unstable();
    allowed.dedup();

    ParseResult {
        blocked,
        allowed,
        lines_processed: results.iter().map(|r| r.lines_processed).sum(),
        lines_skipped: results.iter().map(|r| r.lines_skipped).sum(),
        errors: results.iter().flat_map(|r| r.errors.iter().cloned()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hosts_format() {
        let content = "\
# StevenBlack hosts file
0.0.0.0 localhost
0.0.0.0 api.xmode.io
127.0.0.1 track.muslimpro.com
0.0.0.0 ads.example.com # inline comment
";
        let result = parse_blocklist(content);

        assert_eq!(result.blocked.len(), 3);
        assert!(result.blocked.contains(&"api.xmode.io".to_string()));
        assert!(result.blocked.contains(&"track.muslimpro.com".to_string()));
        assert!(result.blocked.contains(&"ads.example.com".to_string()));
        // localhost should be skipped
        assert!(!result.blocked.contains(&"localhost".to_string()));
    }

    #[test]
    fn parse_domain_list_format() {
        let content = "\
# HaGeZi blocklist
api.xmode.io
predicio.fr
api.smartechmetrics.com
locatex.babelstreet.com
";
        let result = parse_blocklist(content);

        assert_eq!(result.blocked.len(), 4);
        assert!(result.blocked.contains(&"api.xmode.io".to_string()));
        assert!(result.blocked.contains(&"predicio.fr".to_string()));
    }

    #[test]
    fn parse_adblock_format() {
        let content = "\
! AdGuard DNS filter
||api.xmode.io^
||ads.example.com^$third-party
||track.muslimpro.com^
@@||safe.example.com^
";
        let result = parse_blocklist(content);

        assert_eq!(result.blocked.len(), 3);
        assert_eq!(result.allowed.len(), 1);
        assert!(result.blocked.contains(&"api.xmode.io".to_string()));
        assert!(result.allowed.contains(&"safe.example.com".to_string()));
    }

    #[test]
    fn parse_mixed_format() {
        let content = "\
# This file mixes formats
0.0.0.0 ads.example.com
||tracker.example.com^
plain.domain.com
! comment line
@@||allowed.example.com^
";
        let result = parse_blocklist(content);

        assert_eq!(result.blocked.len(), 3);
        assert_eq!(result.allowed.len(), 1);
    }

    #[test]
    fn normalizes_domains() {
        let content = "\
0.0.0.0 API.XMODE.IO
0.0.0.0 Track.MuslimPro.Com.
";
        let result = parse_blocklist(content);

        assert!(result.blocked.contains(&"api.xmode.io".to_string()));
        assert!(result.blocked.contains(&"track.muslimpro.com".to_string()));
    }

    #[test]
    fn skips_invalid_lines() {
        let content = "\
# valid
0.0.0.0 valid.example.com
# invalid entries:
not-a-domain
192.168.1.1
http://not-a-bare-domain.com/path
||*wildcard*.com^
";
        let result = parse_blocklist(content);

        assert_eq!(result.blocked.len(), 1);
        assert!(result.blocked.contains(&"valid.example.com".to_string()));
    }

    #[test]
    fn handles_tabs_in_hosts() {
        let content = "0.0.0.0\tapi.xmode.io\n127.0.0.1\tads.example.com\n";
        let result = parse_blocklist(content);

        assert_eq!(result.blocked.len(), 2);
    }

    #[test]
    fn merge_deduplicates() {
        let r1 = parse_blocklist("api.xmode.io\nads.example.com\n");
        let r2 = parse_blocklist("api.xmode.io\nother.tracker.com\n");
        let merged = merge_results(&[r1, r2]);

        assert_eq!(merged.blocked.len(), 3);
    }

    #[test]
    fn rejects_single_label_domains() {
        assert!(normalize_domain("localhost").is_none());
        assert!(normalize_domain("com").is_none());
    }

    #[test]
    fn accepts_valid_domains() {
        assert_eq!(
            normalize_domain("api.xmode.io"),
            Some("api.xmode.io".to_string())
        );
        assert_eq!(
            normalize_domain("sub-domain.example.co.uk"),
            Some("sub-domain.example.co.uk".to_string())
        );
        assert_eq!(
            normalize_domain("a_b.example.com"),
            Some("a_b.example.com".to_string())
        );
    }

    #[test]
    fn parse_empty_input() {
        let result = parse_blocklist("");
        assert!(result.blocked.is_empty());
        assert!(result.allowed.is_empty());
    }

    #[test]
    fn parse_only_comments() {
        let content = "# comment 1\n! comment 2\n# comment 3\n";
        let result = parse_blocklist(content);
        assert!(result.blocked.is_empty());
        assert_eq!(result.lines_skipped, 3);
    }
}
