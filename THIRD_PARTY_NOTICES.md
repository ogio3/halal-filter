# Third-Party Blocklist Sources

Halal Filter uses community-maintained blocklists compiled into a binary
filter at build time. The following sources are used:

## Standard Tier (included by default)

### Steven Black Unified Hosts
- URL: https://github.com/StevenBlack/hosts
- License: MIT
- Approximate domains: 77,500

### Peter Lowe's Ad Servers List
- URL: https://pgl.yoyo.org/adservers/
- License: McRae GPL (redistribution explicitly permitted)
- Approximate domains: 3,500

### AdGuard DNS Filter
- URL: https://github.com/AdguardTeam/AdGuardSDNSFilter
- License: GPL-3.0
- Approximate domains: 50,000
- Note: Includes EasyList and EasyPrivacy content

### HaGeZi Multi Pro
- URL: https://github.com/hagezi/dns-blocklists
- License: GPL-3.0
- Approximate domains: 198,000

### 1Hosts Lite
- URL: https://github.com/badmojr/1Hosts
- License: MPL-2.0
- Approximate domains: 93,000

## GPL-3.0 Compliance

Sources licensed under GPL-3.0 are compiled into a binary XOR16 filter
(`filter.bin`) at build time. The build script (`src/bin/build_filter.rs`)
and fetch script (`scripts/fetch_lists.sh`) are open-source, enabling
anyone to regenerate the filter from the original sources.

Source list URLs are documented in `data/sources.toml`.

## Our Curated List

The Islamic app surveillance tracker list (`data/trackers/islamic_apps.txt`)
is original research by the Halal Filter project, licensed under MIT.
