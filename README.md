# Network-Discovery-Playbook

A personal repository to store attacker/defender commands, detection playbooks, SIEM queries, IDS rules and example scripts for analyzing network discovery behaviors. Designed for future reference and SOC use.

---

## Repo Structure

```
Network-Discovery-Playbook/
├── README.md                # This file (human-friendly overview)
├── LICENSE                  # MIT License
├── playbooks/
│   ├── 01_ip_port_os.md     # IP/Port/OS fingerprinting playbook
│   ├── 02_banner_grab.md
│   ├── 03_dir_bruteforce.md
│   ├── 04_cms_fingerprinting.md
│   ├── 05_headers_cookies.md
│   ├── 06_tls_cert_checks.md
│   ├── 07_dns_subdomains.md
│   ├── 08_file_shares.md
│   ├── 09_bruteforce.md
│   ├── 10_api_testing.md
│   ├── 11_cloud_metadata_buckets.md
│   ├── 12_iot_upnp.md
│   ├── 13_public_leaks.md
│   ├── 14_snmp_ldap.md
│   └── 15_fuzzing.md
├── detection_rules/
│   ├── suricata/
│   │   └── scanning_rules.rules
│   ├── zeek/
│   │   └── local.zeek
│   └── elastic_query_examples/
│       └── detection_queries.md
├── scripts/
│   ├── run_curl_headers.sh
│   ├── tls_scan.sh
│   └── parse_nginx_404s.py
├── siem_queries/
│   ├── splunk_queries.md
│   └── elastic_queries.md
├── examples/
│   ├── sample_capture.pcap  # placeholder (add your own)
│   └── sample_access.log
└── CONTRIBUTING.md
```

---

## What I included per playbook (short)

Each `playbooks/*.md` contains:

* Attack commands (nmap, masscan, curl, gobuster, ffuf, whatweb, wpscan, etc.) with quick flags.
* Defender detection commands/log snippets (tcpdump, tshark, grep on logs, jq) to triage and investigate.
* Quick detection indicators (e.g., many distinct destination ports, high 404 counts, TLS handshake spikes).
* Recommended automation (Suricata/Zeek rules, scheduled header checks, CloudTrail alerts).

---

## Example: quick `README` snippet for `01_ip_port_os.md`

```md
# 01 - IP / Port / OS fingerprinting

## Attacker commands
- `nmap -sS -Pn -p- 10.0.0.0/24`  # full TCP port scan
- `masscan 10.0.0.0/24 -p1-65535 --rate=10000`
- `nmap -O -sV target`

## Defender detections
- Capture SYN floods / scans:
  - `sudo tcpdump -n 'tcp[tcpflags] & (tcp-syn) != 0'`
- SIEM example (Splunk):
  - `index=netfw | stats dc(dest_port) as unique_ports by src_ip | where unique_ports > 100`

## Indicators of Compromise
- Rapid connections to many ports from the same external IP.
```

---

## Detection rules examples

* `detection_rules/suricata/scanning_rules.rules` contains Suricata rules to alert on:

  * Mass-scan signatures, TLS handshake spikes, HTTP 404 storms, DNS AXFR attempts.
* `detection_rules/zeek/local.zeek` contains Zeek scripts to flag port sweeps, repeated 404s and suspicious header probing.

---

## Useful scripts

* `scripts/run_curl_headers.sh` — run periodic curl header checks against a list of hosts and output differences (for config drift detection).
* `scripts/tls_scan.sh` — wrapper around `openssl` / `testssl.sh` to collect cert info and send to SIEM (stdout JSON).
* `scripts/parse_nginx_404s.py` — parse nginx logs and generate a list of IPs causing many 404s.

---

## How to turn this into a GitHub repo (commands)

1. Create a new repo on GitHub (via web UI) named `Network-Discovery-Playbook` (or your chosen name).
2. Locally:

```bash
git init
git branch -M main
# copy files into folder (or `git clone` if you created remote first)
git add .
git commit -m "Initial commit: network discovery playbook"
# replace <your-github-remote-url> with the URL shown by GitHub
git remote add origin <your-github-remote-url>
git push -u origin main
```

If you prefer using SSH remote, use `git@github.com:USERNAME/Network-Discovery-Playbook.git`.

---

## Licensing

This repo uses the MIT license by default. See `LICENSE`.

---

## CONTRIBUTING

`CONTRIBUTING.md` contains small guidelines for commits, branch naming, PRs, and adding new playbooks/rules.

---

## Next steps I can do for you

* Generate the actual files (playbooks, detection rules, scripts) inside this repo here so you can copy-paste.
* Produce a ready-to-download ZIP of the repo.
* Create Suricata and Zeek rules tuned for your environment (I will need brief env details).

Tell me which next step you want and I'll add the files.

---

*Generated for Satya Prakash — keep it safe, update often.*

---

# 15 Command Playbooks (Attacker & Defender)

Below are the 15 behaviours with attacker (A) and defender (D) commands, cleaned up for clarity and ready to copy-paste into individual playbook files. Each block uses code fences so you can drop them straight into Markdown.

## 1) IPs / Ports / OS fingerprinting

**A (attack)**

```bash
nmap -sS -Pn -p- 10.0.0.0/24   # full TCP port scan
masscan 10.0.0.0/24 -p1-65535 --rate=10000
nmap -O -sV target             # OS + service versions
```

**D (defend / detect)**

```bash
# Flag many SYNs from same IP (live capture)
sudo tcpdump -n 'tcp[tcpflags] & (tcp-syn) != 0'

# Summarise TCP conversations from a capture
tshark -r capture.pcap -q -z conv,tcp

# Splunk/SIEM example: count distinct destination ports by source
index=netfw src_ip=1.2.3.4 | stats dc(dest_port) as ports by src_ip
```

---

## 2) Service / app banners & versions

**A**

```bash
nmap -sV --version-all -p22,80,443 target
# SMTP banner grab
nc target 25
# then type: EHLO

# HTTP server header
curl -I http://target
```

**D**

```bash
# Find banner-grab patterns in web/proxy logs
grep -E "Nmap|masscan|curl" /var/log/nginx/access.log

# Implement IDS/Suricata rules to alert on common banner-grab signatures
# (seen as HTTP probes, unusual TCP connections, or banner strings)
```

---

## 3) Web endpoints / directories / files (dir brute)

**A**

```bash
gobuster dir -u https://target -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
ffuf -u https://target/FUZZ -w wordlist.txt -mc 200,301
wget --recursive --no-clobber --page-requisites https://target
```

**D**

```bash
# Count 404 spikes from single IP (nginx)
cat /var/log/nginx/access.log | awk '{print $1,$9,$7}' | grep ' 404 ' | awk '{print $1}' | sort | uniq -c | sort -nr

# From a pcap, list IPs generating many 404 responses
tshark -r capture.pcap -Y "http.response.code == 404" -T fields -e ip.src | sort | uniq -c
```

---

## 4) CMS / frameworks / plugins fingerprinting

**A**

```bash
whatweb target
wpscan --url http://target --enumerate p   # WordPress plugins
nikto -host http://target
```

**D**

```bash
# Alert on requests to known plugin paths
# Example: URIs containing "/wp-content/plugins/"
grep "/wp-content/plugins" /var/log/nginx/access.log | awk '{print $1}' | sort | uniq -c
```

---

## 5) HTTP headers, cookies, config misconfigs

**A**

```bash
curl -I https://target
# nikto and whatweb also show headers/configs
```

**D**

```bash
# Periodic header checks can be automated and compared against a baseline
curl -I https://target

# Find unexpected Server tokens in logs
grep -i "Server:" /var/log/nginx/access.log | sort | uniq -c
```

---

## 6) SSL/TLS configuration & certs

**A**

```bash
openssl s_client -connect target:443 -showcerts
# or use testssl.sh / sslyze
./testssl.sh target
sslyze --regular target:443
```

**D**

```bash
# Detect many TLS handshakes from the same IP in a pcap
tshark -r capture.pcap -Y tls -T fields -e ip.src | sort | uniq -c

# Ingest cert metadata into SIEM and alert on self-signed / unusual CN
```

---

## 7) Subdomains & DNS records / zone transfers

**A**

```bash
amass enum -d example.com
subfinder -d example.com
# Try an AXFR (zone transfer)
dig axfr @ns1.example.com example.com
```

**D**

```bash
# Watch DNS server logs for many subdomain lookups
grep "example.com" /var/log/named/* | awk '{print $1,$5}' | sort | uniq -c

# Alert on AXFR attempts in authoritative DNS logs
```

---

## 8) Open file shares & exposed services (SMB, DBs)

**A**

```bash
smbclient -L //target -U ''
enum4linux -a target
nmap -p 137,139,445 --script=smb-os-discovery target
```

**D**

```bash
# Detect unusual SMB sessions in Samba logs
grep -i "SMB" /var/log/samba/log.*

# From pcap, filter SMB/NBSS traffic
tshark -r capture.pcap -Y "nbss || smb" -T fields -e ip.src -e smb2.cmd
```

---

## 9) Authentication endpoints & default creds / brute force

**A**

```bash
hydra -L users.txt -P pass.txt ssh://target
# Use ffuf to discover login pages and then script attempts
```

**D**

```bash
# Monitor auth failures (Linux example)
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c

# Use fail2ban and SIEM alerts for >X failed logins in Y seconds
```

---

## 10) APIs (REST/GraphQL) & parameter testing

**A**

```bash
curl -X GET 'https://api.target/resource?id=1'
sqlmap -u "https://target/api?id=1" --data="param=1" --batch
ffuf -u https://target/api?param=FUZZ -w params.txt
```

**D**

```bash
# Inspect API logs for many different parameter values from one source
# Use jq to parse JSON logs and highlight error spikes (500s)
jq '. | select(.status==500)' api_logs.json
```

---

## 11) Cloud metadata / public buckets / IAM misconfigs

**A**

```bash
# EC2 metadata access (from instance)
curl http://169.254.169.254/latest/meta-data/

# Check public S3/GCS buckets
aws s3 ls s3://target-bucket --no-sign-request
gsutil ls gs://target-bucket
```

**D**

```bash
# Alert on external requests to instance metadata endpoints (WAF/IDS)
# Monitor CloudTrail for S3 ACL changes
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketAcl
```

---

## 12) IoT / embedded firmware & UPnP / Telnet exposure

**A**

```bash
nmap -sV --script=banner -p 23,554,1900 target
upnpc -l
# or
gupnp-discover
```

**D**

```bash
# IDS rule / pcap analysis for SSDP/UPnP
tshark -r capture.pcap -Y "ssdp"

# Detect telnet daemons/connections in logs
grep "telnetd" /var/log/*
```

---

## 13) Public leaks / search engines / GitHub reconnaissance

**A**

```bash
shodan host target
shodan search "hostname:example.com"
theharvester -d example.com -b all
# Repo reconnaissance
gitrob orgname
truffleHog --regex --entropy=True https://github.com/orgname/repo.git
```

**D**

```bash
# Monitor public GitHub for mentions of internal domains (use GitHub alerts)
# Ingest Shodan/OTX feeds into SIEM to flag externally indexed hosts
```

---

## 14) SNMP, NetBIOS, LDAP enumeration

**A**

```bash
snmpwalk -v2c -c public target
nbtscan -r 10.0.0.0/24
ldapsearch -x -h target -b "dc=example,dc=com"
```

**D**

```bash
# Alert on SNMP Walks from external IPs in network-device logs
# Check LDAP/AD logs for anonymous binds
grep "anonymous bind" /var/log/ldap.log
```

---

## 15) Fuzzing / input testing / exploit-finding

**A**

```bash
wfuzz -c -w payloads.txt --hc 404 https://target/FUZZ
# Use Burp Intruder or sqlmap for automated payloads
```

**D**

```bash
# Find many encoded payloads in web logs
grep -P "%2[0-9A-F]" /var/log/nginx/access.log | awk '{print $1}' | sort | uniq -c

# Alert on high error rate (500s) following many unique requests
awk '$9==500 {print $1}' /var/log/nginx/access.log | sort | uniq -c
```

---

## Quick defender playbook — practical commands to run now

```bash
# Capture live suspicious scan
sudo tcpdump -i eth0 host 1.2.3.4 -w probe.pcap

# Summarise top scanners in web logs
awk '{print $1,$12}' /var/log/nginx/access.log | sort | uniq -c | sort -nr | head

# Find hosts with lots of 404s (dir brute)
awk '$9==404 {print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -nr | head
```

---


