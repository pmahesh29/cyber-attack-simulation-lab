# Cyber Attack Simulation Home Lab

An isolated, host-only virtualized environment for offensive security practice and defensive security operations center (SOC) training. This lab demonstrates end-to-end security analysis from reconnaissance to detection.

## 🏗️ Architecture

**Environment:** VMware Workstation host-only network (10.0.0.0/24)

**Virtual Machines:**
- **Kali Linux (10.0.0.100)** - Attacker machine for offensive security operations
- **Metasploitable2 (10.0.0.101)** - Intentionally vulnerable target for penetration testing
- **pfSense (10.0.0.254)** - Network gateway with integrated Suricata IDS for traffic analysis

## 🎯 Project Objectives

- Conduct systematic reconnaissance and service enumeration
- Perform vulnerability assessment on intentionally vulnerable systems
- Capture and analyze network traffic using packet capture tools
- Implement custom intrusion detection rules
- Practice both offensive and defensive security techniques in a safe, isolated environment

## 🔧 Tools & Technologies

**Offensive Tools:**
- Nmap (network reconnaissance and service enumeration)
- Nikto & Gobuster (web application scanning)
- Metasploit Framework
- Netcat, curl, enum4linux

**Defensive Tools:**
- Suricata IDS (custom rule development)
- tcpdump & Wireshark (packet capture and analysis)
- pfSense firewall (network segmentation and monitoring)

## 📊 Key Activities

### Reconnaissance & Enumeration
Performed comprehensive network scanning to identify:
- 23+ open services including FTP (vsftpd 2.3.4), SSH, Telnet, HTTP, SMB, MySQL, PostgreSQL
- Known vulnerable services (UnrealIRCd backdoor, vsftpd backdoor, Samba 3.x)
- Web applications (Apache, Tomcat Manager)

```bash
sudo nmap -sV -sC -A -T4 -oN metasploitable_full.txt 10.0.0.101
```

### Traffic Analysis
- Captured network traffic during reconnaissance and exploitation phases
- Analyzed cleartext protocols (FTP, Telnet, HTTP) for credential exposure
- Identified attack patterns including SYN scans and service enumeration

### Intrusion Detection
Developed custom Suricata rules to detect:
- TCP SYN scan patterns
- Connections to known vulnerable services (bindshell port 1524)
- Specific service banner interactions (vsftpd 2.3.4)

**Example Rule:**
```snort
alert tcp any any -> any any (msg:"LAB Possible TCP SYN scan"; flags:S; detection_filter: track by_src, count 20, seconds 60; sid:1000001; rev:1;)
```

## 🔐 Security Highlights

### Vulnerabilities Identified
- Anonymous FTP access with directory traversal
- Cleartext authentication protocols (Telnet, FTP)
- Outdated and vulnerable service versions
- Weak database configurations
- Exposed management interfaces

### Detection Capabilities
- Real-time alerting on reconnaissance activity
- Traffic pattern analysis for anomaly detection
- Packet-level inspection of suspicious connections
- Custom signature matching for known exploits

## 📁 Artifacts & Documentation

**Pre-Snapshot Evidence:**
- System configuration snapshots (IP addressing, routing tables, listening services)
- Service enumeration outputs
- Network traffic captures (PCAP files)

**Analysis Outputs:**
- Comprehensive Nmap scan results
- Wireshark/tshark packet analysis
- Suricata alert logs (fast.log, eve.json)
- Custom IDS rules with detection logic

## 🎓 Learning Outcomes

- **Offensive Security:** Practiced systematic reconnaissance, service enumeration, and vulnerability identification
- **Defensive Security:** Developed detection signatures, analyzed network traffic, and implemented monitoring solutions
- **Network Analysis:** Gained experience with packet capture, protocol analysis, and traffic pattern recognition
- **Lab Management:** Implemented proper isolation, evidence preservation through snapshots, and reproducible testing methodologies

## ⚠️ Disclaimer

This lab environment is completely isolated on a host-only network and contains intentionally vulnerable systems for educational purposes only. All activities were performed on systems I own and control. These techniques should never be applied to systems without explicit authorization.

## 🔄 Reproducibility

All commands, configurations, and procedures are documented for reproducibility. The lab can be reset to clean snapshots for repeated testing scenarios, making it ideal for:
- Penetration testing practice
- SOC analyst training
- Network security research
- Incident response exercises

---

**Technologies:** VMware Workstation | Kali Linux | Metasploitable2 | pfSense | Suricata IDS | Wireshark | Nmap | Python
