
Workflow:
1. Copy devices_example.csv → devices.csv (your input)
2. Edit devices.csv with your real device names/IPs
3. Run script: python3 mac_ip_merge.py devices.csv output.csv
4. Script reads devices.csv (input) and creates output.csv (results)


devices_example.csv shows:

device,device_type

router1.example.com,cisco_ios

router2.example.com,cisco_ios

192.168.1.1,cisco_ios

switch1.example.com,cisco_ios

switch2.example.com,cisco_ios


To use:
1. Copy devices_example.csv → devices.csv
2. Edit with your actual device names/IPs
3. Run: python3 mac_ip_merge.py devices.csv output.csv

use --update-vendors flag to refresh the IEEE database

python3 mac_ip_merge.py devices.csv output.csv --update-vendors
