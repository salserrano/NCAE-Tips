<p align="center">
<img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRKU1BVVs896ySnNEnDxULc37i5AbG5TilaDw&s"/>
</p>

# **NCAE Cyber Games: Essential Linux Commands for Defense & Blue Team**

This guide provides essential commands and strategies for competing in NCAE Cyber Games or any Red vs Blue team competitions. Use these tips to protect your infrastructure, detect anomalies, and respond effectively to threats.

---

## Introduction
In Red vs Blue team competitions, your goal is to defend your infrastructure (Blue Team) while identifying and mitigating attacks from the Red Team. A well-coordinated team with a strong understanding of system administration, network monitoring, and incident response is key to success.

---

## Top Linux Commands

### Protect Your Infrastructure
- **Check all running services:**
  ```bash
  service --status-all
  ```
- **View detailed service information:**
  ```bash
  ps -aux
  ```
- **Check for startup jobs:**
  ```bash
  ls /etc/init/*.conf
  ```
- **Backup existing firewall (iptables) rules:**
  ```bash
  iptables-save > iptables_rules.out
  ```
- **Modify firewall rules (if needed):**
  ```bash
  vi iptables_rules.out
  ```
- **Restore iptables rules:**
  ```bash
  iptables-restore < iptables_rules.out
  ```
- **List current iptables rules:**
  ```bash
  iptables -L
  ```
- **Change user password:**
  ```bash
  passwd
  ```

---

### Detect Anomalies

#### Network Monitoring
- **Capture live network traffic:**
  ```bash
  tcpdump
  ```
- **Save PCAP file to a remote host (e.g., Kali):**
  ```bash
  tcpdump -w - | ssh <remote_ip> -p <port> "cat - > /tmp/<filename>.pcap"
  ```
- **Monitor for new TCP connections (install `net-tools` if needed):**
  ```bash
  netstat -ac 5 | grep tcp
  ```
- **Monitor traffic remotely (from Kali):**
  ```bash
  ssh <user>@<remote_ip> tcpdump -i any -U -s -w - 'not host <kali_ip>'
  ```

#### Log Analysis
- **View log file:**
  ```bash
  cat /path/to/log
  ```
- **Monitor log file in real time:**
  ```bash
  tail -f /path/to/log
  ```
- **Search for a keyword in log file:**
  ```bash
  grep -i "<keyword>" /path/to/log
  ```
- **Check for sudo activity:**
  ```bash
  grep -i sudo /var/log/auth.log
  ```

---

### Triage and Respond

#### User and Account Management
- **View logged-in users:**
  ```bash
  w
  ```
- **Check remote login activity:**
  ```bash
  lastlog
  ```
- **Check failed login attempts:**
  ```bash
  faillog -a
  ```
- **View local accounts and groups:**
  ```bash
  cat /etc/passwd
  cat /etc/shadow
  cat /etc/group
  cat /etc/sudoers
  ```
- **Identify root accounts:**
  ```bash
  awk -F: '($3 == "0") {print}' /etc/passwd
  ```

#### Network and Process Analysis
- **Check active network connections:**
  ```bash
  netstat -antup
  ```
- **View routing table:**
  ```bash
  route
  ```
- **List processes listening on ports:**
  ```bash
  lsof -i
  ```
- **Check cron jobs:**
  ```bash
  crontab -l
  cat /etc/crontab
  ls /etc/cron.*
  ```

#### Malicious Process and File Handling
- **Stop a process (use `ps -aux` or `lsof -i` to find process info):**
  ```bash
  kill <process_pid>
  kill -9 -I <process_name>
  ```
- **Remove execution permissions from a malicious file:**
  ```bash
  chmod -x /path/to/malicious/file
  ```
- **Move malicious file to quarantine for analysis:**
  ```bash
  mv /path/to/malicious/file ~/quarantine
  strings ~/quarantine/<malicious_file>
  ```

---

## Final Notes
- **Collaborate:** Work closely with your team to divide tasks and share findings.
- **Document:** Keep track of changes, anomalies, and actions taken during the competition.
- **Stay Calm:** Competitions can be intense, but a clear and focused approach will yield the best results.

Good luck, and may the best team win!
