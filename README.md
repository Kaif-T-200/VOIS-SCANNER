# VOIS Port Scanner v3.0
## Professional Network Security Scanning Tool

**VOIS** is a modern, user-friendly alternative to Nmap that's built for cybersecurity professionals, penetration testers, and security researchers who want **powerful scanning without the complexity**.

---

## 🎯 What Makes VOIS Different?

### ✅ Simple & Intuitive
- **Web-based interface** - No command line needed
- **Real-time results** - Watch ports open as they're discovered
- **Smart profiles** - Quick, Common, Thorough, or Custom
- **Beautiful visualizations** - Charts, statistics, and risk meters

### 🔒 Built for Security Professionals
- **CVE Intelligence** - Automatic vulnerability detection
- **Risk Scoring** - Understand which ports matter most
- **Service Detection** - Identify what's running on each port
- **OS Detection** - Determine operating systems
- **Certificate Analysis** - SSL/TLS vulnerability scanning
- **Continuous Monitoring** - Track changes over time

### ⚡ Reliable & Fast
- **Async scanning** - Ultra-fast concurrent port scanning
- **Smart timing** - Auto-adjust speed based on target responsiveness
- **No root required** - Works on Windows, Mac, Linux
- **Minimal dependencies** - Just Python + a few packages

---

## 🚀 Quick Start

### Installation
```bash
# 1. Clone or navigate to project
cd portscanner

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the server
python run.py
```

The server will automatically:
- Open your browser to http://localhost:8000
- Initialize the database
- Create scan history storage

### First Scan
1. **Enter a target**: IP address or hostname (e.g., `scanme.nmap.org` or `192.168.1.1`)
2. **Choose a profile**:
   - **Quick** (20 common ports) - 2-5 seconds
   - **Common** (1000+ common ports) - 30-60 seconds  
   - **Thorough** (all 65535 ports) - 2-5 minutes
   - **Custom** (specify your ports) - Your choice
3. **Click Scan** - Watch real-time results appear

---

## �️ Script Engine
VOIS includes a high-performance **Script Engine** for automated vulnerability testing:
- **Parallel Execution**: Run multiple security scripts simultaneously.
- **Detailed Findings**: Get structured reports with risk levels and mitigation steps.
- **Custom Scripts**: Easily add new `.py` scripts to the `backend/scripts/` directory.
- **Categories**: Filter scripts by Vulnerability, Brute Force, Discovery, and more.

---

## �📊 Scanning Profiles Explained

### Quick Scan (Default)
- **Ports**: Top 20 most common
- **Time**: 2-5 seconds
- **Use case**: Quick recon, endpoint checks
- **Best for**: Fast sweeps across many targets

### Common Scan 
- **Ports**: Top 1000 common ports
- **Time**: 30-60 seconds
- **Use case**: Standard penetration testing
- **Best for**: Web apps, databases, standard services

### Thorough Scan
- **Ports**: All 65,535 ports
- **Time**: 2-5 minutes (10GbE networks faster)
- **Use case**: Complete picture, nothing missed
- **Best for**: Red team operations, compliance audits

### Custom Scan
- **Ports**: You specify (e.g., "80,443,8080-8090,3306")
- **Time**: Depends on quantity
- **Use case**: Targeted scanning
- **Best for**: Known infrastructure, specific testing

---

## 🛠️ Advanced Features

### Version Detection
Find exact software versions running on open ports.
- Automatically runs on TCP and UDP services
- Matches against service fingerprints
- Links to known CVEs

### OS Detection
Determine the operating system running on the target.
- Based on network behavior analysis
- Covers Windows, Linux, macOS, network devices
- ~85% confidence level

### Service Detection
Identify what's actually running on each port.
- Probes ports with appropriate handshakes
- Detects web servers, databases, SSH, FTP, etc.
- Shows detected services in real-time

### CVE Intel
Get vulnerability information for discovered services.
- Cross-references against NVD database
- Shows CVSS scores and severity levels
- Links to vulnerability details

### Risk Assessment
Automatic risk scoring based on:
- Port criticality (some ports are higher value targets)
- Known CVEs on detected services
- Host-level risk aggregation
- Easy-to-read risk meter (green → red)

### Continuous Monitoring
Track how a target changes over time.
1. Add a target to monitoring
2. Set scan interval (5 minutes to 1 day)
3. Get alerts on changes:
   - New ports opening
   - Services disappearing
   - New vulnerabilities detected

### Export Results
Download scan reports in multiple formats:
- **JSON** - For tool integration and automation
- **CSV** - Open in Excel/Sheets
- **TXT** - Human-readable
- **PDF** - Professional reports

---

## 🔍 Understanding Results

### Port States
- **OPEN** - Port is accepting connections (service running)
- **CLOSED** - Port is not accepting connections (firewall or service not running)
- **FILTERED** - Port is not responding (likely firewall blocking)

### Risk Levels
- **CRITICAL** (Red) - Vulnerability with CVSS 9.0+, or critical service exposed
- **HIGH** (Orange) - Significant vulnerability or sensitive service
- **MEDIUM** (Yellow) - Moderate risk, should investigate
- **LOW** (Green) - Low priority but should be reviewed
- **INFO** (Blue) - Informational only

### Service Confidence
- **10/10** - Definitely this service (matched known signature)
- **8-9/10** - Very likely (strong fingerprint match)
- **5-7/10** - Probable (pattern match)
- **3-5/10** - Guessing (similar services on this port usually)

---

## 💡 Real-World Examples

### Example 1: Quick Website Security Check
```
Target: company.com
Profile: Common Scan
Expected: 80 (HTTP), 443 (HTTPS), maybe 22 (SSH)
Time: ~1 minute
Action: Review open ports, check for unexpected services
```

### Example 2: Internal Network Assessment
```
Target: 192.168.1.0/24 (or 192.168.1.1 individually)
Profile: Quick Scan
Expected: Various services across network
Time: 30 seconds per host
Action: Map network assets, identify security issues
```

### Example 3: Deep Vulnerability Assessment
```
Target: critical-server.internal
Profile: Thorough Scan
Expected: All ports, service versions, CVEs
Time: 3-5 minutes
Action: Generate full security report
```

### Example 4: Continuous Monitoring
```
Target: api.company.com
Setup: Hourly scans for 1 week
Usage: Detect unauthorized changes, port openings, new services launching
```

---

## ⚙️ Command Line Usage (Advanced)

For automation and CI/CD pipelines:

```bash
# Coming soon - API documentation
# Currently use Web UI or directly call endpoints:

curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.1",
    "scan_type": "tcp_connect",
    "profile": "common",
    "timing": 3,
    "grab_banners": true,
    "detect_os": true
  }'
```

---

## 🔒 Security & Privacy

### Local Scanning
- **All scans run locally** on your machine
- **No data sent to external servers** (except for optional integrations)
- **Scan history stored locally** in SQLite database

### Optional Integrations (Disabled by Default)
These require API keys and are opt-in:
- **Shodan** - Lookup external visibility
- **VirusTotal** - Check IP reputation
- **HaveIBeenPwned** - Check breach databases
- **Censys** - Additional host intelligence

To use: Set environment variables with API keys.

### Responsible Scanning
- **Only scan networks you own or have permission to scan**
- **Respect rate limits** on public targets
- **Use appropriate scan timing** to avoid disruption
- **Review law** - Some scans may be illegal without authorization

---

## 📈 Performance Tips

### For Faster Scans
1. Use **"Quick"** profile instead of "Thorough"
2. Increase **timing** from "Normal" to "Aggressive"
3. Check your network connection
4. Scan fewer ports with "Custom" profile

### For More Accurate Results
1. Use **"Thorough"** profile
2. Enable **version detection** and **OS detection**
3. Use lower timing ("Polite") for firewalled targets
4. Let scans run fully (don't interrupt)

### For Network Mapping
1. Use **"Quick"** profile
2. Scan your gateway (192.168.1.1 or 10.0.0.1)
3. Use "Topology" tab to visualize network
4. Periodically re-scan to find new devices

---

## ❓ FAQ

**Q: Why is it different from Nmap?**
A: VOIS is simpler, web-based, and includes modern features like real-time results, CVE intelligence, and a risk meter. It trades some advanced Nmap features for usability.

**Q: Does it need root/admin?**
A: No. Basic TCP scanning works without root. Some advanced features (raw packets, privilege scanning) need elevated privileges.

**Q: How accurate is the service detection?**
A: ~85-95% accurate for common services. Some services actively hide versions, making detection harder.

**Q: Can I scan the whole internet?**
A: Not from this tool - it's designed for networks you have permission to test. Scanning without permission is illegal.

**Q: Why does scanning slow down?**
A: Network latency, firewalls, or the target rate-limiting connections. Try lower timing profile.

**Q: How do I export results for reports?**
A: After scanning, click "Export" and choose JSON, CSV, or TXT format.

---

## 🐛 Troubleshooting

### Scanner won't start
```bash
# Make sure port 8000 is not in use
# Try:
python start.py --port 8001
```

### Scans very slow
- Switch to "Quick" profile
- Target might be firewalled or rate-limiting
- Try from different network/location

### No ports detected (all filtered)
- Target is likely heavily firewalled
- Try different scan type or profile
- Check target accepts network traffic

### Version detection not working
- Enable "Grab Banners" option
- Some services don't respond to probes
- This is normal for security-conscious targets

### Can't connect to localhost:8000
- Make sure server started successfully
- Check Python isn't blocked by antivirus
- Try http://127.0.0.1:8000 instead

---

## ⚖️ Legal Notice

**VOIS is for authorized security testing only.**

- Only scan networks you own or have explicit written permission to test
- Unauthorized network scanning may violate laws in your jurisdiction
- Users are responsible for the legality of their scanning activities
- The authors are not liable for misuse of this tool

---

## 📄 License

VOIS Port Scanner is provided as-is for security testing purposes.

---

## 🤝 Contributing

Found a bug? Have a feature request? Contributions welcome!

Key areas for improvement:
- Additional service fingerprints
- Network visualization improvements
- Mobile-friendly UI
- Docker support
- More export formats

---

## 👤 Connect with Author

<h1 align="center"> Kaif Tarasgar </h1>

<p align="center">
<a href="https://www.linkedin.com/in/kaif-tarasgar-0b5425326/"><img src="https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white"></a>
&nbsp;<b></b>&nbsp;
<a href="https://github.com/Kaif-T-200"><img src="https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white"></a>
&nbsp;<b></b>&nbsp;
<a href="https://x.com/Kaif_T_200"><img src="https://img.shields.io/badge/Twitter-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white"></a>
&nbsp;<b></b>&nbsp;
<a href="https://kaif-t-200.github.io/Portfolio/"><img src="https://img.shields.io/badge/Portfolio-FF5722?style=for-the-badge&logo=todoist&logoColor=white"></a>
&nbsp;<b></b>&nbsp;
</p>

---

**Made with ❤️ by Kaif Tarasgar**

*VOIS - Vision Of Integrated Security*
