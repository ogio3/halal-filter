//! Minimal DNS packet parser/builder for VpnService packet processing.
//!
//! Extracts QNAME from raw IPv4/UDP packets on port 53 and constructs
//! blocked responses returning `0.0.0.0` (IPv4) or `::` (IPv6).

#[derive(Debug)]
pub enum DnsError {
    TooShort,
    NotDns,
    InvalidQname,
    NotQuery,
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::TooShort => write!(f, "packet too short"),
            DnsError::NotDns => write!(f, "not a DNS packet (port != 53)"),
            DnsError::InvalidQname => write!(f, "malformed QNAME"),
            DnsError::NotQuery => write!(f, "not a DNS query"),
        }
    }
}

impl std::error::Error for DnsError {}

/// Parsed DNS query extracted from a raw IP/UDP packet.
pub struct DnsPacket {
    /// Transaction ID (for response matching)
    pub tx_id: u16,
    /// Queried domain name (e.g., "api.xmode.io")
    pub qname: String,
    /// Query type (1 = A, 28 = AAAA)
    pub qtype: u16,
    /// Query class (1 = IN)
    pub qclass: u16,
    /// Source port (for building response UDP header)
    pub src_port: u16,
    /// Destination port (should be 53)
    pub dst_port: u16,
    /// Source IP (for routing response back)
    pub src_ip: [u8; 4],
    /// Destination IP (VPN's virtual DNS IP)
    pub dst_ip: [u8; 4],
}

impl DnsPacket {
    /// Parse a raw IPv4/UDP/DNS packet from VpnService FileDescriptor.
    /// Expects: IPv4 header (20 bytes) + UDP header (8 bytes) + DNS payload.
    pub fn parse(raw: &[u8]) -> Result<Self, DnsError> {
        // IPv4 minimum: 20 bytes
        if raw.len() < 28 {
            return Err(DnsError::TooShort);
        }

        let version = (raw[0] >> 4) & 0xF;
        if version != 4 {
            return Err(DnsError::NotDns); // IPv6 handled separately
        }

        let ihl = (raw[0] & 0xF) as usize * 4;

        // IHL must be at least 20 (standard IPv4 header) and fit within the packet
        if ihl < 20 || ihl + 8 > raw.len() {
            return Err(DnsError::TooShort);
        }

        let protocol = raw[9];
        if protocol != 17 {
            return Err(DnsError::NotDns);
        }

        let src_ip = [raw[12], raw[13], raw[14], raw[15]];
        let dst_ip = [raw[16], raw[17], raw[18], raw[19]];

        // UDP header starts at IHL offset
        let udp = &raw[ihl..];
        if udp.len() < 8 {
            return Err(DnsError::TooShort);
        }

        let src_port = u16::from_be_bytes([udp[0], udp[1]]);
        let dst_port = u16::from_be_bytes([udp[2], udp[3]]);

        if dst_port != 53 {
            return Err(DnsError::NotDns);
        }

        // DNS payload starts after UDP header
        let dns = &udp[8..];
        if dns.len() < 12 {
            return Err(DnsError::TooShort);
        }

        let tx_id = u16::from_be_bytes([dns[0], dns[1]]);
        let flags = u16::from_be_bytes([dns[2], dns[3]]);

        // QR bit = 0 means query
        if flags & 0x8000 != 0 {
            return Err(DnsError::NotQuery);
        }

        // Parse QNAME starting at byte 12
        let (qname, qname_end) = Self::parse_qname(&dns[12..])?;

        let question_rest = &dns[12 + qname_end..];
        if question_rest.len() < 4 {
            return Err(DnsError::TooShort);
        }

        let qtype = u16::from_be_bytes([question_rest[0], question_rest[1]]);
        let qclass = u16::from_be_bytes([question_rest[2], question_rest[3]]);

        Ok(DnsPacket {
            tx_id,
            qname,
            qtype,
            qclass,
            src_port,
            dst_port,
            src_ip,
            dst_ip,
        })
    }

    fn parse_qname(data: &[u8]) -> Result<(String, usize), DnsError> {
        let mut labels = Vec::new();
        let mut pos = 0;

        loop {
            if pos >= data.len() {
                return Err(DnsError::InvalidQname);
            }

            let len = data[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }

            // Label length sanity check (max 63 per RFC 1035)
            if len > 63 || pos + 1 + len > data.len() {
                return Err(DnsError::InvalidQname);
            }

            let label = std::str::from_utf8(&data[pos + 1..pos + 1 + len])
                .map_err(|_| DnsError::InvalidQname)?;
            labels.push(label.to_string());
            pos += 1 + len;
        }

        if labels.is_empty() {
            return Err(DnsError::InvalidQname);
        }

        Ok((labels.join("."), pos))
    }
}

/// Builds a DNS response for blocked domains.
pub struct DnsResponse;

impl DnsResponse {
    /// Build a complete IPv4/UDP/DNS response packet that returns 0.0.0.0 for A queries
    /// or :: for AAAA queries. Written back to VpnService FileDescriptor.
    pub fn blocked(query: &DnsPacket) -> Vec<u8> {
        let dns_payload = Self::build_dns_response(query);
        let udp_packet = Self::wrap_udp(&dns_payload, query.dst_port, query.src_port);
        Self::wrap_ipv4(&udp_packet, query.dst_ip, query.src_ip)
    }

    fn build_dns_response(query: &DnsPacket) -> Vec<u8> {
        let mut resp = Vec::with_capacity(64);

        // Transaction ID
        resp.extend_from_slice(&query.tx_id.to_be_bytes());
        // Flags: QR=1, AA=1, RCODE=0 (no error)
        resp.extend_from_slice(&0x8400u16.to_be_bytes());
        // QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());

        // Question section (echo back)
        Self::encode_qname(&mut resp, &query.qname);
        resp.extend_from_slice(&query.qtype.to_be_bytes());
        resp.extend_from_slice(&query.qclass.to_be_bytes());

        // Answer section
        // Name pointer to question (0xC00C = offset 12)
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&query.qtype.to_be_bytes());
        resp.extend_from_slice(&query.qclass.to_be_bytes());
        // TTL: 300 seconds
        resp.extend_from_slice(&300u32.to_be_bytes());

        match query.qtype {
            1 => {
                // A record: 0.0.0.0
                resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
                resp.extend_from_slice(&[0, 0, 0, 0]);
            }
            28 => {
                // AAAA record: ::
                resp.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH
                resp.extend_from_slice(&[0u8; 16]);
            }
            _ => {
                // For other query types, return empty RDATA
                resp.extend_from_slice(&0u16.to_be_bytes());
            }
        }

        resp
    }

    fn encode_qname(buf: &mut Vec<u8>, domain: &str) {
        for label in domain.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // root terminator
    }

    fn wrap_udp(payload: &[u8], src_port: u16, dst_port: u16) -> Vec<u8> {
        let length = 8 + payload.len() as u16;
        let mut udp = Vec::with_capacity(length as usize);
        udp.extend_from_slice(&src_port.to_be_bytes());
        udp.extend_from_slice(&dst_port.to_be_bytes());
        udp.extend_from_slice(&length.to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes()); // checksum (optional for IPv4 UDP)
        udp.extend_from_slice(payload);
        udp
    }

    fn wrap_ipv4(payload: &[u8], src_ip: [u8; 4], dst_ip: [u8; 4]) -> Vec<u8> {
        let total_len = 20 + payload.len() as u16;
        let mut ip = Vec::with_capacity(total_len as usize);

        ip.push(0x45); // Version=4, IHL=5 (20 bytes)
        ip.push(0x00); // DSCP/ECN
        ip.extend_from_slice(&total_len.to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes()); // ID
        ip.extend_from_slice(&0x4000u16.to_be_bytes()); // Flags: Don't Fragment
        ip.push(64); // TTL
        ip.push(17); // Protocol: UDP
        ip.extend_from_slice(&0u16.to_be_bytes()); // Checksum placeholder
        ip.extend_from_slice(&src_ip);
        ip.extend_from_slice(&dst_ip);
        ip.extend_from_slice(payload);

        // Calculate IPv4 header checksum
        let checksum = Self::ipv4_checksum(&ip[..20]);
        ip[10] = (checksum >> 8) as u8;
        ip[11] = (checksum & 0xFF) as u8;

        ip
    }

    fn ipv4_checksum(header: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for i in (0..header.len()).step_by(2) {
            let word = if i + 1 < header.len() {
                u16::from_be_bytes([header[i], header[i + 1]])
            } else {
                u16::from_be_bytes([header[i], 0])
            };
            sum += word as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_packet(domain: &str) -> Vec<u8> {
        let mut pkt = Vec::new();

        // IPv4 header (20 bytes)
        pkt.push(0x45); // Version=4, IHL=5
        pkt.push(0x00);
        pkt.extend_from_slice(&0u16.to_be_bytes()); // Total length (filled later)
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ID
        pkt.extend_from_slice(&0u16.to_be_bytes()); // Flags
        pkt.push(64); // TTL
        pkt.push(17); // UDP
        pkt.extend_from_slice(&0u16.to_be_bytes()); // Checksum
        pkt.extend_from_slice(&[192, 168, 1, 100]); // src IP
        pkt.extend_from_slice(&[10, 0, 0, 1]); // dst IP (virtual DNS)

        // UDP header (8 bytes)
        pkt.extend_from_slice(&12345u16.to_be_bytes()); // src port
        pkt.extend_from_slice(&53u16.to_be_bytes()); // dst port
        pkt.extend_from_slice(&0u16.to_be_bytes()); // UDP length (filled later)
        pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum

        // DNS header (12 bytes)
        pkt.extend_from_slice(&0xABCDu16.to_be_bytes()); // TX ID
        pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: standard query
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // QNAME
        for label in domain.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0); // root

        // QTYPE=A (1), QCLASS=IN (1)
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());

        // Fix lengths
        let total = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&total.to_be_bytes());
        let udp_len = total - 20;
        pkt[24..26].copy_from_slice(&udp_len.to_be_bytes());

        pkt
    }

    #[test]
    fn parse_dns_query() {
        let pkt = build_test_packet("api.xmode.io");
        let parsed = DnsPacket::parse(&pkt).unwrap();

        assert_eq!(parsed.qname, "api.xmode.io");
        assert_eq!(parsed.tx_id, 0xABCD);
        assert_eq!(parsed.qtype, 1);
        assert_eq!(parsed.src_port, 12345);
        assert_eq!(parsed.dst_port, 53);
        assert_eq!(parsed.src_ip, [192, 168, 1, 100]);
        assert_eq!(parsed.dst_ip, [10, 0, 0, 1]);
    }

    #[test]
    fn blocked_response_returns_0000() {
        let pkt = build_test_packet("api.xmode.io");
        let query = DnsPacket::parse(&pkt).unwrap();
        let resp = DnsResponse::blocked(&query);

        // Response should be a valid IPv4 packet
        assert_eq!(resp[0] >> 4, 4); // IPv4
        assert_eq!(resp[9], 17); // UDP

        // IPs should be swapped
        assert_eq!(&resp[12..16], &[10, 0, 0, 1]); // src = was dst
        assert_eq!(&resp[16..20], &[192, 168, 1, 100]); // dst = was src

        // Ports should be swapped
        let resp_src = u16::from_be_bytes([resp[20], resp[21]]);
        let resp_dst = u16::from_be_bytes([resp[22], resp[23]]);
        assert_eq!(resp_src, 53);
        assert_eq!(resp_dst, 12345);

        // DNS TX ID should match
        let resp_txid = u16::from_be_bytes([resp[28], resp[29]]);
        assert_eq!(resp_txid, 0xABCD);

        // DNS flags: QR=1
        let flags = u16::from_be_bytes([resp[30], resp[31]]);
        assert!(flags & 0x8000 != 0);
    }

    #[test]
    fn rejects_non_dns_port() {
        let mut pkt = build_test_packet("example.com");
        // Change dst port to 80
        pkt[22..24].copy_from_slice(&80u16.to_be_bytes());
        assert!(matches!(DnsPacket::parse(&pkt), Err(DnsError::NotDns)));
    }

    #[test]
    fn rejects_tcp() {
        let mut pkt = build_test_packet("example.com");
        pkt[9] = 6; // TCP
        assert!(matches!(DnsPacket::parse(&pkt), Err(DnsError::NotDns)));
    }
}
