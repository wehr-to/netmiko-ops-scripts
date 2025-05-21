# netmiko-ops-scripts
A collection of 50+ real-world network automation scripts using Netmiko. Built to streamline day-to-day operations—backups, config pushes, audits, VLAN management, and more across multi-vendor CLI environments.

Future Scripts: 

🔧 Configuration & Deployment
Backup running-config to local storage
Push a standardized banner to all devices
Automate hostname updates from a CSV
Configure interface descriptions in bulk
Deploy NTP server config across all routers
Push SNMP configuration to switches
Enable/disable specific interfaces in bulk
Push AAA authentication config
Set up logging servers on all core devices
Apply a basic port-security config to all access ports
Configure VLANs based on site template
Deploy interface IP addresses from an Excel or YAML file

🛡️ Security & Hardening 
Disable unused services (CDP, HTTP, finger)
Push ACLs to edge routers
Check for weak enable passwords
Verify SSH version and encryption settings
Enforce login banners for compliance
Disable Telnet across all devices
Audit password encryption settings
Scan for unused VLANs
Verify login attempt thresholds
Detect and log config differences (running vs startup)
Check devices for unconfigured enable secret
Identify devices missing a line vty ACL

📡 Monitoring & Auditing 
Pull interface status (up/down) for all devices
Parse show ip int brief to JSON or CSV
Monitor CPU/memory usage
Pull ARP tables and search for specific MACs
Audit VLAN to port mappings
Gather version info across the fleet
Detect routing protocol neighbors (EIGRP, OSPF)
Log devices that haven't been rebooted in X days
Pull current clock time across devices
Detect duplex/speed mismatches
Log serial interface bandwidth for reporting
Scan interfaces for input/output errors

⚙️ Troubleshooting Utilities
Ping test from each device to a destination
Run traceroute from all edge routers
Check CDP neighbors across a topology
Verify redundant links (port-channel members)
Gather BGP neighbor states
Detect devices missing HSRP or VRRP configs

🧰 Device Inventory & Tagging
Create device inventory file from show version
Generate topology summary (hostname, IP, model)
Group devices by platform (IOS vs NX-OS vs ASA)
Parse serial numbers for asset tracking
Tag interfaces based on connected device names
Export interface MAC tables for endpoint mapping



