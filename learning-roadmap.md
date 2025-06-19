# Network Automation Learning Path

## Phase 1: Foundation

### 1. Learn Networking Fundamentals
Master core networking concepts before diving into automation:

- OSI & TCP/IP Models
- Subnetting & VLANs
- Routing Protocols (OSPF, BGP, EIGRP)
- Switching Concepts (STP, VTP, Port Security)
- Network Security Basics (ACLs, Firewalls, VPNs)

#### Resources
- Cisco CCNA (200-301) Official Guide
- Packet Tracer / GNS3 for network simulation

#### Hands-on Labs
- Build a home lab (GNS3, Eve-NG, Cisco VIRL)
- Configure VLANs, STP, and routing in Packet Tracer
- Create and test ACLs and firewall rules

### 2. Learn Linux & Shell Scripting
Build the skills to automate using Linux systems:

- Linux CLI: Files, permissions, users, processes
- Bash scripting: loops, conditionals, functions
- SSH automation with `expect`
- Log parsing with `awk`, `sed`, `grep`

#### Resources
- Linux+ Study Guide
- Bash Scripting Crash Course (YouTube/Udemy)

#### Hands-on Labs
- Automate log analysis (awk/sed)
- Write a Bash script to SSH into routers and backup configs

## Phase 2: Python for Network Automation

### 3. Learn Python Basics

- Variables, loops, conditionals, functions
- File I/O, JSON & YAML handling
- Error handling, logging
- HTTP requests using `requests`

#### Resources
- *Automate the Boring Stuff with Python*
- Python Crash Course (YouTube/Udemy)

#### Hands-on Labs
- Script to backup switch/router configurations
- Parse JSON/YAML network config files

### 4. Python for Networking

- Netmiko (SSH library)
- Paramiko (Advanced SSH interactions)
- NAPALM (Multi-vendor automation)
- Ansible (IaC intro)
- REST APIs (Cisco DNA, Arista, Juniper)

#### Hands-on Labs
- Automate VLAN setup using Netmiko
- Python ping reachability check
- Pull device facts using NAPALM
- Push configs via Ansible Playbooks

## Phase 3: Advanced Network Automation

### 5. Infrastructure as Code (IaC)

- Ansible: Advanced Playbooks, Jinja2 templates, Roles
- Terraform: Automate network infrastructure in the cloud
- Git, GitHub Actions, CI/CD for automation workflows

#### Hands-on Labs
- Role-based config automation via Ansible
- Provision cloud network infra with Terraform
- Create CI/CD pipeline for NetOps

### 6. Containers & Orchestration

- Docker & Kubernetes for automation tool deployment
- Deploy NetBox (IPAM/DCIM) in Docker
- Automate and orchestrate via K8s

#### Hands-on Labs
- Run network scripts inside Docker containers
- Orchestrate automation pipelines in Kubernetes

### 7. Final Projects & Advanced Topics

- Build network monitoring with Prometheus & Grafana
- Create a self-healing network system
- Automate hybrid/multi-cloud networking (AWS, Azure, GCP)

#### Additional Resources
- Cisco DevNet Learning Labs
- Network Automation Communities (Slack/Discord)
