# Network Inventory Tool - MAC/IP Merger (v5)

A Python tool to collect ARP and MAC address tables from Cisco SD-WAN routers and Palo Alto firewalls, merge the data, and produce a comprehensive CSV inventory with vendor lookups.

## What's New in v5

✅ **Simplified Vendor Lookup** - Now uses `mac-vendor-lookup` Python module instead of manual Wireshark file
- Automatic vendor database management
- Always up-to-date with IEEE OUI registry
- One-time setup, automatic updates available
- No manual file downloads needed

## Features

### Core Capabilities
- **Concurrent Collection**: Collect from multiple devices simultaneously
- **Progress Indicators**: Real-time progress bars using `tqdm`
- **Rich Output**: Beautiful tables and formatting (if `rich` is installed)
- **Automatic Vendor Lookup**: Uses IEEE OUI database via `mac-vendor-lookup`
- **Comprehensive Logging**: Detailed logs saved to file
- **Configurable VRFs**: Specify VRF list via CLI
- **Summary Statistics**: See vendor distribution and collection stats
- **DNS Fallback**: Automatic FQDN resolution

### Collected Data

**From Cisco Devices:**
- ARP tables (global + VRFs)
- MAC address tables
- Interface information
- VLAN assignments

**From Palo Alto Firewalls:**
- ARP tables with interface mappings

### Output Format

CSV with the following columns:
- `ip` - IP address (from ARP)
- `mac` - MAC address
- `vlan` - VLAN ID (from MAC table)
- `switch` - Device hostname/IP
- `switchport` - Interface name
- `port_type` - "access" or "trunk" (auto-detected)
- `firewall` - Palo Alto hostname (if applicable)
- `fw_intf` - Firewall interface (if applicable)
- `vendor` - Manufacturer (from IEEE OUI database)

## Installation

### 1. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 2. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. First-Time Vendor Database Setup (Automatic)

The first time you run the script, it will automatically download the IEEE OUI database:

```bash
# First run - downloads vendor database automatically
python mac_ip_merge_live_v4.py --csv devices.csv --out inventory.csv
```

That's it! No manual downloads needed.

## Usage

### Basic Usage

```bash
python mac_ip_merge_live_v4.py --csv devices.csv --out inventory.csv
```

### Update Vendor Database

To update the vendor database with the latest IEEE data:

```bash
python mac_ip_merge_live_v4.py \
  --csv devices.csv \
  --out inventory.csv \
  --update-vendors
```

**Recommendation**: Update vendor database monthly to catch new vendors.

### Advanced Usage

```bash
python mac_ip_merge_live_v4.py \
  --csv devices.csv \
  --out inventory.csv \
  --domain yourcompany.com \
  --timeout 15 \
  --max-workers 10 \
  --vrf-list "10,20,30,MGMT" \
  --update-vendors \
  --verbose
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--csv` | Input CSV file with devices | **Required** |
| `--out` | Output CSV file | **Required** |
| `--domain` | DNS domain for hostname resolution | `williams.com` |
| `--timeout` | SSH timeout in seconds | `10` |
| `--update-vendors` | Update vendor database from IEEE | `False` |
| `--only-matched` | Only output rows with IP addresses | `False` |
| `--vrf-list` | Comma-separated VRF list | Built-in list |
| `--max-workers` | Max concurrent connections | `5` |
| `--log` | Log file path | Auto-generated |
| `--verbose` | Verbose logging | `False` |

## Input CSV Format

### Required Columns

Your input CSV must have:
1. A **host** column (accepted names: `hostname`, `host`, `device`, `name`, `ip`)
2. A **type** column (accepted names: `type`, `device_type`, `devicetype`, `platform`, `vendor`)

### Example `devices.csv`

```csv
hostname,type
192.168.1.1,cisco
192.168.1.2,cisco
core-sw-01,cisco
firewall-01,palo
10.0.0.1,paloalto
```

### Accepted Device Types

**Cisco devices:**
- `cisco`, `ios`, `iosxe`, `nxos`, `router`, `switch`

**Palo Alto devices:**
- `palo`, `panos`, `paloalto`, `pa`

## Vendor Lookup Details

### How It Works

The script uses the `mac-vendor-lookup` Python module which:
1. **First run**: Downloads IEEE OUI database (one-time, ~2MB)
2. **Subsequent runs**: Uses cached database (instant lookups)
3. **Updates**: Use `--update-vendors` to refresh from IEEE

### Vendor Database Location

The database is stored in your home directory:
- **Linux/Mac**: `~/.cache/mac-vendor-lookup/`
- **Windows**: `%USERPROFILE%\.cache\mac-vendor-lookup\`

### Update Frequency

- **Recommended**: Update monthly
- **When to update**:
  - New hardware deployed
  - Unknown vendors appearing
  - After major network changes

```bash
# Monthly update via cron (first Monday at 3 AM)
0 3 * * 1 [ $(date +\%d) -le 7 ] && /path/to/venv/bin/python /path/to/script.py --csv devices.csv --out inventory.csv --update-vendors
```

## Output Examples

### Sample Output CSV

```csv
ip,mac,vlan,switch,switchport,port_type,firewall,fw_intf,vendor
10.1.1.100,00:50:56:ab:cd:ef,100,192.168.1.1,Gi0/0/1,access,,,VMware, Inc.
10.1.1.101,00:0c:29:12:34:56,100,192.168.1.1,Gi0/0/2,access,,,VMware, Inc.
10.1.2.1,f0:18:98:ab:cd:ef,200,192.168.1.2,Gi1/0/1,trunk,,,Apple, Inc.
```

### Console Output

```
=== Collecting Data ===
Collecting from devices: 100%|████████████| 10/10 [00:45<00:00,  4.5s/device]

=== Merging Data ===
Processing MAC entries: 100%|████████| 1234/1234 [00:02<00:00, 512 entries/s]

=== Writing Output ===

============================================================
COLLECTION SUMMARY
============================================================
Total Devices................................          10
Succeeded....................................           9
Failed/Skipped...............................           1

MAC Table Entries............................        1234
Cisco ARP Entries............................         567
Palo ARP MACs................................          89
Vendor Lookup................................     Enabled

Output Rows..................................        1890

============================================================
TOP 10 VENDORS
============================================================
Cisco Systems, Inc...........................         456
VMware, Inc..................................         234
Hewlett Packard..............................         123
Apple, Inc...................................          89
Dell Inc.....................................          78
Intel Corporate..............................          67
Microsoft Corporation........................          45
Ubiquiti Networks............................          34
Aruba, a Hewlett Packard Enterprise company..          23
Juniper Networks.............................          12
```

## Performance Tips

### 1. Concurrent Collection

Adjust `--max-workers` based on your network:
- **Small networks (<10 devices)**: Use `--max-workers 5`
- **Medium networks (10-50 devices)**: Use `--max-workers 10`
- **Large networks (>50 devices)**: Use `--max-workers 20`

**Note**: Too many workers can overwhelm your network or hit device connection limits.

### 2. Timeouts

- Fast, reliable network: `--timeout 10`
- Slower network or busy devices: `--timeout 20`
- Very slow WAN links: `--timeout 30`

### 3. Vendor Database Updates

**First run of the day**: Expect 5-10 second delay for database download
**Subsequent runs**: Instant lookups (database cached)

## Troubleshooting

### Common Issues

#### 1. "mac_vendor_lookup module not installed"

**Fix:**
```bash
pip install mac-vendor-lookup
```

#### 2. "TCP/22 unreachable"
- Device is down or SSH is disabled
- Firewall blocking SSH
- Wrong IP address or hostname

**Fix:** Verify device is reachable:
```bash
ping <device-ip>
telnet <device-ip> 22
```

#### 3. "Connection failed: NetmikoAuthenticationException"
- Wrong username or password
- Authentication method mismatch

**Fix:** Verify credentials and try manually:
```bash
ssh username@device-ip
```

#### 4. Vendor lookup shows "UNKNOWN" for known vendors

**Fix:** Update vendor database:
```bash
python mac_ip_merge_live_v4.py --csv devices.csv --out inventory.csv --update-vendors
```

#### 5. First run is slow

**Normal behavior**: First run downloads IEEE OUI database (~2MB). Subsequent runs use cached database.

### Debug Mode

Enable verbose logging to see detailed output:

```bash
python mac_ip_merge_live_v4.py --csv devices.csv --out inventory.csv --verbose
```

Check the log file for detailed information:
```bash
cat mac_ip_merge_20240131_143022.log
```

## Comparison: v3 vs v4 vs v5

| Feature | v3 | v4 | v5 |
|---------|----|----|-----|
| Progress bars | ❌ | ✅ | ✅ |
| Concurrent collection | ❌ | ✅ | ✅ |
| Rich output | ❌ | ✅ | ✅ |
| Vendor lookup | ⚠️ Manual file | ⚠️ Manual file | ✅ Auto-managed |
| Database updates | ❌ Manual | ❌ Manual | ✅ One command |
| Setup complexity | ⚠️ Medium | ⚠️ Medium | ✅ Simple |
| Detailed logging | ⚠️ Basic | ✅ Comprehensive | ✅ Comprehensive |
| Configurable VRFs | ❌ | ✅ | ✅ |

## Deployment for Production

### Installation Script

```bash
#!/bin/bash
# install.sh - Production deployment script

# 1. Create directory structure
sudo mkdir -p /opt/network-inventory
sudo chown $USER:$USER /opt/network-inventory
cd /opt/network-inventory

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 4. Initialize vendor database
python mac_ip_merge_live_v4.py --help  # This triggers initial database download

echo "Installation complete!"
```

### Cron Job Setup

```bash
# Daily collection at 2 AM
0 2 * * * /opt/network-inventory/venv/bin/python /opt/network-inventory/mac_ip_merge_live_v4.py --csv /opt/network-inventory/devices.csv --out /opt/network-inventory/inventory_$(date +\%Y\%m\%d).csv --log /var/log/network-inventory/$(date +\%Y\%m\%d).log

# Monthly vendor database update (first Monday at 3 AM)
0 3 * * 1 [ $(date +\%d) -le 7 ] && /opt/network-inventory/venv/bin/python /opt/network-inventory/mac_ip_merge_live_v4.py --csv /opt/network-inventory/devices.csv --out /opt/network-inventory/inventory_$(date +\%Y\%m\%d).csv --update-vendors
```

### Performance Tuning

| Network Size | Recommended --max-workers |
|--------------|---------------------------|
| 1-10 devices | 5 |
| 11-50 devices | 10 |
| 51-100 devices | 20 |
| 100+ devices | 30 (test for optimal) |

## Migration from v3/v4

### From v3 (Wireshark manuf file)

**Old command:**
```bash
python mac_ip_merge_live_v3.py --csv devices.csv --out inventory.csv --manuf wireshark_Manuf
```

**New command (v5):**
```bash
python mac_ip_merge_live_v4.py --csv devices.csv --out inventory.csv
```

**Benefits:**
- ✅ No manual file download
- ✅ Auto-updating database
- ✅ Always current vendor info
- ✅ Simpler command line

### From v4 (if you used Wireshark file)

Just remove the `--manuf` argument. Everything else stays the same!

## Security Notes

- **Credentials**: Never commit credentials to version control
- **Logs**: Log files may contain sensitive information - secure appropriately
- **Output**: CSV may contain network topology - treat as confidential
- **SSH Keys**: Consider using SSH keys instead of passwords for production
- **Vendor Database**: Downloaded from IEEE official source (https://standards-oui.ieee.org/)

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review log files with `--verbose`
3. Update vendor database with `--update-vendors`
4. Contact the network automation team

## License

Internal use only - Williams Companies

## Version History

### v5 (Current)
- Replaced Wireshark manuf file with mac-vendor-lookup module
- Simplified setup (no manual downloads)
- Auto-updating vendor database
- Removed online API dependency

### v4
- Added concurrent collection
- Rich terminal output
- Online vendor lookup option
- Comprehensive logging

### v3
- Multi-VRF support
- Palo Alto integration
- Wireshark manuf support

### v2
- Basic Cisco support
- CSV output

### v1
- Initial release
