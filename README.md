# Cyber Attack Simulation Home Lab

An isolated, host-only virtualized environment for offensive security practice and defensive security operations center (SOC) training. This lab demonstrates end-to-end security analysis from reconnaissance to detection across host, network, and application layers.

## 🏗️ Architecture

**Environment:** VMware Workstation host-only network (10.0.0.0/24)

**Virtual Machines:**
- **Kali Linux (10.0.0.100)** – Attacker machine for offensive security operations, Burp Suite proxy, and Juice Shop host
- **Metasploitable2 (10.0.0.101)** – Intentionally vulnerable target for penetration testing
- **pfSense (10.0.0.254)** – Network gateway with integrated Suricata IDS for traffic inspection and alerting

## 🎯 Project Objectives

- Conduct systematic reconnaissance and service enumeration
- Perform vulnerability assessment on intentionally vulnerable systems
- Capture and analyze network traffic using packet capture tools
- Implement custom intrusion detection rules
- Perform modern web application penetration testing
- Practice both offensive and defensive security techniques in a safe, isolated environment

## 🔧 Tools & Technologies

**Offensive Tools:**
- Nmap (network reconnaissance and service enumeration)
- Nikto & Gobuster (web application scanning)
- Metasploit Framework
- Netcat, curl, enum4linux
- **Burp Suite Community Edition**
- **OWASP Juice Shop (Docker)**

**Defensive Tools:**
- Suricata IDS (custom rule development)
- tcpdump & Wireshark (packet capture and analysis)
- pfSense firewall (network segmentation and monitoring)

---

## 📊 Key Activities

### Reconnaissance & Enumeration
Performed comprehensive network scanning to identify:
- 23+ open services including FTP (vsftpd 2.3.4), SSH, Telnet, HTTP, SMB, MySQL, PostgreSQL
- Known vulnerable services (UnrealIRCd backdoor, vsftpd backdoor, Samba 3.x)
- Web applications (Apache, Tomcat Manager)

```bash
sudo nmap -sV -sC -A -T4 -oN metasploitable_full.txt 10.0.0.101
````

### Traffic Analysis

* Captured network traffic during reconnaissance and exploitation phases
* Analyzed cleartext protocols (FTP, Telnet, HTTP) for credential exposure
* Identified attack patterns including SYN scans and service enumeration

### Intrusion Detection

Developed custom Suricata rules to detect:

* TCP SYN scan patterns
* Connections to known vulnerable services (bindshell port 1524)
* Specific service banner interactions (vsftpd 2.3.4)

**Example Rule:**

```snort
alert tcp any any -> any any (
    msg:"LAB Possible TCP SYN scan";
    flags:S;
    detection_filter: track by_src, count 20, seconds 60;
    sid:1000001; rev:1;
)
```

---

## 🧃 Web Application Penetration Testing (OWASP Juice Shop + Burp Suite)

To extend the lab into application-layer security testing, OWASP Juice Shop was deployed and integrated with Burp Suite and pfSense for full-stack traffic analysis and detection engineering.

### Deployment (Kali Linux – Docker)

```bash
sudo docker run --rm -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
```

Accessible via:

* `http://localhost:3000` (local)
* `http://10.0.0.100:3000` (LAN access for pfSense monitoring)

### Burp Suite Integration

Burp Suite Community Edition was configured as an interception proxy to analyze, intercept, and replay HTTP requests.

**Browser Proxy Configuration:**

* HTTP Proxy: `127.0.0.1`
* Port: `8080`
* “Use this proxy for all protocols” enabled

All HTTP traffic to Juice Shop was routed through Burp for inspection and attack execution.

### Web Application Reconnaissance & Exploitation

Performed modern web penetration testing techniques including:

* Manual SQL Injection (`admin' OR 1=1--`)
* Reflected & Stored XSS
* Authentication bypass exploration
* API endpoint enumeration under `/rest/*`
* Replay and modification of intercepted requests

**Example Intercepted Request (Burp Suite):**

```
POST /rest/user/login HTTP/1.1
Host: 10.0.0.100:3000
Content-Type: application/json

{"email":"admin' OR 1=1--","password":"invalid"}
```

### Network Traffic Capture (pfSense + Wireshark)

Application traffic was captured at the network layer using pfSense:

```sh
tcpdump -i em1 -w /tmp/juice_traffic.pcap host 10.0.0.100
```

PCAPs were transferred to Kali for Wireshark analysis:

```bash
scp admin@10.0.0.254:/tmp/juice_traffic.pcap ~/
wireshark juice_traffic.pcap &
```

Captured traffic included:

* HTTP GET/POST requests
* Login attempts and JSON payloads
* JWT tokens and cookies
* Burp Suite scanning artifacts

### Suricata IDS Detection Engineering

Custom IDS rules were developed to detect exploitation attempts against the Juice Shop application.

**Detect Login Requests:**

```snort
alert http any any -> 10.0.0.100 3000 (
    msg:"LAB Juice Shop Login Attempt";
    http.method; content:"POST";
    http.uri; content:"/rest/user/login";
    sid:2000001; rev:1;
)
```

**Detect SQL Injection Patterns:**

```snort
alert http any any -> 10.0.0.100 3000 (
    msg:"LAB Possible SQL Injection Attempt";
    content:"' OR 1=1--";
    nocase;
    sid:2000002; rev:1;
)
```

**Detect Burp Suite Scanner Behavior:**

```snort
alert http any any -> 10.0.0.100 3000 (
    msg:"LAB Burp Suite Scanner Activity Detected";
    content:"Mozilla/5.0"; http_header;
    content:"Burp"; http_header;
    sid:2000003; rev:1;
)
```

---

## 🔐 Security Highlights

### Vulnerabilities Identified

* Anonymous FTP access with directory traversal
* Cleartext authentication protocols (Telnet, FTP)
* Outdated and vulnerable service versions
* Weak database configurations
* Exposed management interfaces
* SQL Injection and XSS vulnerabilities in Juice Shop
* API endpoint weaknesses and improper authentication flows

### Detection Capabilities

* Real-time alerting on reconnaissance activity
* Traffic pattern analysis for anomaly detection
* Packet-level inspection of suspicious connections
* Detection of malicious HTTP requests and payloads
* Identification of Burp Suite scanner activity
* Custom signature matching for known exploits and Juice Shop attack patterns

---

## 📁 Artifacts & Documentation

**Pre-Snapshot Evidence:**

* System configuration snapshots (IP addressing, routing tables, listening services)
* Service enumeration outputs
* Network traffic captures (PCAP files)

**Analysis Outputs:**

* Comprehensive Nmap scan results
* Wireshark/tshark packet analysis
* Suricata alert logs (fast.log, eve.json)
* Custom IDS rules with detection logic
* Burp Suite HTTP history & intercepted payloads

---

## 🎓 Learning Outcomes

* **Offensive Security:** Performed systematic reconnaissance, service enumeration, modern web exploitation, and vulnerability identification
* **Defensive Security:** Developed custom detection signatures, analyzed network traffic, and implemented IDS-based monitoring
* **Application Security:** Conducted real-world web application testing with Burp Suite and Juice Shop
* **Network Analysis:** Gained experience with packet capture, protocol dissection, and correlation analysis
* **Lab Management:** Maintained proper isolation, evidence preservation through snapshots, and reproducible testing methodologies

---

## ⚠️ Disclaimer

This lab environment is completely isolated on a host-only network and contains intentionally vulnerable systems for educational purposes only. All activities were performed on systems I own and control. These techniques should never be applied to systems without explicit authorization.

---

## 🔄 Reproducibility

All commands, configurations, and procedures are documented for reproducibility. The lab can be reset to clean snapshots for repeated testing scenarios, making it ideal for:

* Penetration testing practice
* SOC analyst training
* Web application security research
* Incident response exercises

---

**Technologies:** VMware Workstation | Kali Linux | Metasploitable2 | pfSense | Suricata IDS | Wireshark | Nmap | Burp Suite | Docker | OWASP Juice Shop | Python

---
