# Simple Python Script - No Docker Required

This is a standalone Python script that runs directly on Windows without Docker.

## Quick Setup

### 1. Install Python

Download and install Python 3.9+ from https://www.python.org/downloads/

**Important:** Check "Add Python to PATH" during installation!

### 2. Install Dependencies

Open Command Prompt or PowerShell and run:

```powershell
pip install netmiko macaddress tqdm rich mac-vendor-lookup
```

Or use the requirements file:

```powershell
pip install -r requirements-simple.txt
```

### 3. Create Your Device CSV

Create `devices.csv` with your network devices:

```csv
device,device_type
router1.williams.com,cisco_ios
192.168.1.1,cisco_xe
switch1,cisco_ios
firewall1,paloalto_panos
```

**Device types:**
- `cisco_ios` - Cisco IOS routers and switches
- `cisco_xe` - Cisco IOS-XE (SD-WAN)
- `paloalto_panos` - Palo Alto firewalls

### 4. Run the Script

```powershell
python mac_ip_merge_simple.py devices.csv output.csv
```

## Usage Examples

### Basic Usage

```powershell
# Simple run
python mac_ip_merge_simple.py devices.csv results.csv

# You'll be prompted for credentials:
# Username: admin
# Password: ******
```

### With VRF Discovery

```powershell
python mac_ip_merge_simple.py devices.csv results.csv --discover-vrfs router1
```

### With Custom VRF List

```powershell
python mac_ip_merge_simple.py devices.csv results.csv --vrf-list "10,20,821,841"
```

### Verbose Logging

```powershell
python mac_ip_merge_simple.py devices.csv results.csv --verbose
```

### Only Export Matched IPs

```powershell
python mac_ip_merge_simple.py devices.csv results.csv --only-matched
```

### Update Vendor Database

```powershell
python mac_ip_merge_simple.py devices.csv results.csv --update-vendors
```

### Combine Options

```powershell
python mac_ip_merge_simple.py devices.csv results.csv --discover-vrfs core-router --verbose --only-matched
```

## Command Line Options

```
positional arguments:
  csv                   Input CSV with devices
  output                Output CSV file

options:
  --domain DOMAIN       DNS domain (default: williams.com)
  --timeout TIMEOUT     SSH timeout in seconds (default: 10)
  --update-vendors      Update vendor database from IEEE
  --only-matched        Only output rows with IP addresses
  --vrf-list VRF_LIST   Comma-separated VRF list
  --discover-vrfs DEVICE
                        Discover VRFs from specified Cisco device
  --max-workers N       Max concurrent connections (default: 5)
  --verbose, -v         Verbose logging
```

## Example Session

```
C:\Users\Casey\network-tools> python mac_ip_merge_simple.py devices.csv output.csv

============================================================
MAC/IP Merge Tool - Simple Version
============================================================

Loaded 10 devices from devices.csv

=== Device Credentials ===
Username: admin
Password: ******

Using default VRF list: 10, 821, 841, 999, ICS-S2H-821, ICS-S2S-822

=== Collecting Data ===
Collecting from devices: 100%|██████████████| 10/10 [00:32<00:00,  3.25s/device]

=== Merging Data ===
Processing MAC entries: 100%|████████████| 2547/2547 [00:01<00:00, 1892.34entry/s]

=== Writing Output ===
✓ Wrote 2547 rows to output.csv

============================================================
SUMMARY
============================================================
Total Devices................................         10
Succeeded....................................          9
Failed/Skipped...............................          1

MAC Table Entries............................       2547
Cisco ARP Entries............................        832
Palo ARP MACs................................        156

Output Rows..................................       2547

============================================================
TOP 10 VENDORS
============================================================
Cisco Systems, Inc..........................       1243
Hewlett Packard.............................        324
Dell Inc....................................        156
UNKNOWN.....................................        142
Aruba, a Hewlett Packard Enterprise Company         98
VMware, Inc.................................         87
Apple, Inc..................................         76
Ubiquiti Networks...........................         54
Fortinet, Inc...............................         43
Microsoft Corporation.......................         32

✓ Log file: mac_ip_merge_20250203_142315.log
✓ Output file: output.csv
```

## Output Format

The script creates a CSV file with these columns:

- **ip** - IP address (if matched)
- **mac** - MAC address (normalized)
- **vlan** - VLAN ID
- **switch** - Switch/router hostname
- **switchport** - Port identifier
- **port_type** - Port type (access/trunk)
- **firewall** - Palo Alto firewall (if applicable)
- **fw_intf** - Firewall interface (if applicable)
- **vendor** - MAC vendor from IEEE database

## Troubleshooting

### Problem: "pip is not recognized"

**Solution:** Python is not in your PATH. Reinstall Python and check "Add Python to PATH"

Or use full path:
```powershell
C:\Users\Casey\AppData\Local\Programs\Python\Python311\python.exe -m pip install netmiko
```

### Problem: "Module not found"

**Solution:** Install missing module:
```powershell
pip install netmiko
pip install macaddress
pip install tqdm
```

### Problem: Can't connect to devices

**Solution:** Check network connectivity:
```powershell
# Test ping
ping router1

# Test SSH port
Test-NetConnection router1 -Port 22
```

### Problem: Slow performance

**Solutions:**
- Reduce concurrent connections: `--max-workers 2`
- Increase timeout: `--timeout 20`
- Check network latency

### Problem: Wrong VRFs

**Solution:** Use manual VRF list:
```powershell
python mac_ip_merge_simple.py devices.csv output.csv --vrf-list "10,821,841"
```

### Problem: Permission errors on output file

**Solution:** Close Excel or any program that has the file open

## Logs

Each run creates a log file: `mac_ip_merge_YYYYMMDD_HHMMSS.log`

View logs:
```powershell
# PowerShell
Get-Content mac_ip_merge_*.log | Select-String "ERROR"

# Command Prompt
type mac_ip_merge_*.log | findstr ERROR
```

## Tips

### Run in Background

Create a batch file `run_collection.bat`:

```batch
@echo off
python mac_ip_merge_simple.py devices.csv output_%date:~-4,4%%date:~-10,2%%date:~-7,2%.csv --discover-vrfs core-router
pause
```

### Schedule Regular Collections

1. Save your script and CSV
2. Open Task Scheduler
3. Create Basic Task
4. Set trigger (daily, weekly, etc.)
5. Action: Start a program
   - Program: `C:\Users\Casey\AppData\Local\Programs\Python\Python311\python.exe`
   - Arguments: `mac_ip_merge_simple.py devices.csv output.csv`
   - Start in: `C:\Users\Casey\network-tools`

### Use Virtual Environment (Optional)

```powershell
# Create virtual environment
python -m venv venv

# Activate it
.\venv\Scripts\Activate.ps1

# Install packages
pip install -r requirements-simple.txt

# Run script
python mac_ip_merge_simple.py devices.csv output.csv

# Deactivate when done
deactivate
```

## Comparison: Simple Script vs Docker

### Simple Script (This One)
✅ No Docker installation needed  
✅ Runs directly on Windows  
✅ Faster to get started  
✅ Easy to debug and modify  
❌ Requires Python installation  
❌ Dependencies on your system  

### Docker Version
✅ Isolated environment  
✅ No system dependencies  
✅ Reproducible builds  
❌ Requires Docker Desktop  
❌ Larger download  
❌ More complex setup  

**Recommendation:** Use the simple script for quick runs and testing. Use Docker for production deployments and scheduled tasks.

## Advanced Usage

### Custom Domain

```powershell
python mac_ip_merge_simple.py devices.csv output.csv --domain example.com
```

### Different Timeout

```powershell
python mac_ip_merge_simple.py devices.csv output.csv --timeout 20
```

### More Concurrent Connections

```powershell
python mac_ip_merge_simple.py devices.csv output.csv --max-workers 10
```

### Combine with Other Tools

```powershell
# Export to Excel format (requires pandas and openpyxl)
python mac_ip_merge_simple.py devices.csv temp.csv
python -c "import pandas as pd; pd.read_csv('temp.csv').to_excel('output.xlsx', index=False)"

# Filter results
python mac_ip_merge_simple.py devices.csv output.csv --only-matched

# Count by vendor
python mac_ip_merge_simple.py devices.csv output.csv
Get-Content output.csv | ConvertFrom-Csv | Group-Object vendor | Sort-Object Count -Descending
```

## Getting Help

View help:
```powershell
python mac_ip_merge_simple.py --help
```

Check Python version:
```powershell
python --version
```

Check installed packages:
```powershell
pip list
```

## What's Next?

- Read VRF-DISCOVERY.md for details on VRF discovery
- Check the Docker version for production deployments
- See CHANGELOG.md for version history
