# Netmiko Ops Scripts 

A collection of real-world network automation scripts built with Python and Netmiko.

These scripts are designed for Cisco CLI environments and solve day-to-day operational problems across enterprise networks, from backups and configuration pushes to audits, inventory enrichment, and control plane validation.

## Key Capabilities

- **Config Automation** – Push hostnames, banners, SNMP, AAA, VLANs, and more
- **Backups** – Archive running-configs across all devices
- **Monitoring & Auditing** – Check interface status, BGP neighbors, CPU/memory, and duplex mismatches
- **Security Hardening** – Enforce port-security, ACLs, SSH-only access, password policies
- **Device Inventory** – Collect models, serials, platform types, connected neighbors
- **Device Mapping** – Export MAC tables, trace endpoint connections, build CDP topology
- **Protocol Validation** – Monitor OSPF, HSRP/VRRP, routing neighbor health
- **Data Inputs** – YAML, CSV, Excel

## Example Scripts

| Task                                   | Script Path                                                |
| -------------------------------------- | ---------------------------------------------------------- |
| Push SNMPv3 Config                     | `config_push/push_snmpv3_config.py`                        |
| Backup All Running Configs             | `backups/backup_running_config.py`                         |
| Detect BGP Neighbor Failures           | `monitoring_auditing/check_bgp_neighbor_states.py`         |
| Enforce Login Banners                  | `config_push/push_standard_banner.py`                      |
| Group Devices by Platform              | `device_inventory/group_devices_by_platform.py`            |
| Export MAC Tables for Endpoint Mapping | `device_mapping/export_mac_tables_for_endpoint_mapping.py` |
| Verify OSPF Timers and Area Configs    | `protocols/ospf/validate_ospf_areas.py`                    |

## Requirements
- Python 3.8+
- Netmiko
- pyyaml, pandas, openpyxl, tabulate
- argparse, logging (built-in Python modules)
Install all dependencies:
pip install -r requirements.txt

## Testing

Run the unit tests with [pytest](https://docs.pytest.org/):

```bash
pytest
```






