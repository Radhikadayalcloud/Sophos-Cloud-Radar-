# Sophos Cloud Radar

> AI-powered cloud security analyzer built on Claude AI — instantly detects misconfigurations, threats, and compliance gaps across AWS, Azure, GCP and IaC environments.

---

## Overview

Sophos Cloud Radar is a React-based security tool that lets security engineers, DevOps teams, and compliance professionals paste any cloud configuration, flow log, or activity log and receive an instant AI-powered security analysis — complete with MITRE ATT&CK mapping, compliance scoring, and remediation guidance.

Built as a companion tool to fill the gap left by the deprecation of Sophos Cloud Optix, it delivers cloud configuration compliance and visibility without requiring a full platform deployment.

---

## Screenshot

```
SOPHOS CLOUD RADAR - AI SECURITY CLOUD ANALYZER
------------------------------------------------
Step 1: Config Files | Flow Logs | Activity Logs
Step 2: AWS | Azure | GCP | IaC
Step 3: Config Type (IAM Policy, NSG, Terraform, Container Image...)
Step 4: Compliance Framework (CIS, NIST, SOC 2, ISO 27001...)
Step 5: Multi-tab config editor
         [Analyze Config]
```

---

## Features

### Three Analysis Modes

| Mode | What It Analyzes |
|---|---|
| Config Files | IAM policies, Security Groups, Terraform, ARM templates, S3, NSG rules, Container Images |
| Flow Logs | VPC Flow Logs, Azure NSG Flow Logs, GCP VPC Logs - detects suspicious traffic |
| Activity Logs | CloudTrail, Azure Monitor, GCP Audit Logs - hunts threats in audit events |

### Four Environment Types

| Environment | Coverage |
|---|---|
| AWS | IAM wildcards, Security Hub, GuardDuty, CloudTrail, S3 public access, VPC flow threats |
| Azure | NSG Flow Logs, Azure AD Sign-ins, Defender alerts, Key Vault audit, RBAC escalation |
| GCP | IAM policies, Firewall rules, Cloud Audit logs, Security Command Center |
| IaC | Terraform, CloudFormation, ARM, Bicep, Pulumi, Ansible, CDK, Container Images |

### Results Dashboard

- **Risk Score** — 0-100 gauge with SECURE / NEEDS ATTENTION / AT RISK status
- **Domain Breakdown** — IAM, Network, Data Protection, Logging, Encryption, Compliance scored individually
- **Findings Table** — filterable by severity with expandable rows showing plain English explanation, business impact, remediation steps, and copy-paste CLI commands
- **MITRE ATT&CK Visualizer** — 12-tactic kill chain matrix with detected techniques highlighted and linked to attack.mitre.org
- **Scan History** — persistent posture tracking with delta comparison, trend chart, and improvement callouts
- **PDF Export** — branded HTML report downloadable as PDF

### Compliance Frameworks

- General Best Practices
- CIS AWS Benchmark v2.0
- CIS Azure Benchmark v2.0
- NIST CSF
- SOC 2 Type II
- PCI-DSS v4.0
- ISO 27001
- HIPAA
- UK Cyber Essentials
- AWS Well-Architected Framework

### IaC Config Types

Terraform, CloudFormation, ARM Template, Bicep, Pulumi, Ansible, CDK, Container Image, Kubernetes YAML, Helm Chart, Docker Compose

---

## Getting Started

### Prerequisites

- Node.js 18+
- An Anthropic API key — get one free at [console.anthropic.com](https://console.anthropic.com)

### Run Locally

```bash
# Clone the repo
git clone https://github.com/YOUR-USERNAME/sophos-cloud-radar.git
cd sophos-cloud-radar

# Install dependencies
npm create vite@latest . -- --template react
npm install

# Replace src/App.jsx with SophosCloudRadar.jsx
cp SophosCloudRadar.jsx src/App.jsx

# Start dev server
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

### Usage

1. Paste your Anthropic API key in the header field
2. Select your analysis mode (Config / Flow Logs / Activity Logs)
3. Select your environment (AWS / Azure / GCP / IaC)
4. Select the config type in Step 3
5. Choose a compliance framework
6. Paste your config or log data into the editor
7. Click **Analyze**

---

## Deploy to Lovable

This tool can be deployed as a full web application using [Lovable](https://lovable.dev):

1. Go to [lovable.dev](https://lovable.dev) and create a new project
2. Connect Supabase for secure backend API calls
3. Add your `ANTHROPIC_API_KEY` as a Supabase Edge Function secret
4. Paste the contents of `SophosCloudRadar.jsx` as your main component
5. Lovable generates a shareable public URL

**Note:** When deploying to Lovable, move the Anthropic API call to a Supabase Edge Function so the API key is never exposed in the frontend.

---

## Architecture

```
User Input
    |
    v
Multi-Tab Config Editor
    |
    v
Claude AI (claude-sonnet-4-6)
    |
    v
JSON Response Parser + Repair
    |
    v
Results Dashboard
    |-- Findings Table
    |-- MITRE ATT&CK Visualizer
    |-- Scan History (persistent storage)
    |-- PDF Export
```

---

## Demo Configs

The tool ships with built-in demo data — click **Load Demo** to auto-fill:

| Demo | Provider | Mode |
|---|---|---|
| AWS IAM Wildcard Policy | AWS | Config |
| Insecure Security Group | AWS | Config |
| AWS VPC Flow Logs | AWS | Flow Logs |
| AWS CloudTrail with suspicious activity | AWS | Activity Logs |
| Azure NSG Flow Logs with RDP attacks | Azure | Flow Logs |
| Azure Monitor with MFA bypass and privilege escalation | Azure | Activity Logs |
| Terraform with public S3 and hardcoded secrets | IaC | Config |
| Dockerfile with root user and exposed secrets | IaC | Config |

---

## MITRE ATT&CK Coverage

Sophos Cloud Radar maps findings to MITRE ATT&CK techniques across all 12 tactics:

| Tactic | Example Techniques Detected |
|---|---|
| Initial Access | T1078 Valid Accounts, T1190 Exploit Public App |
| Privilege Escalation | T1548 Abuse Elevation, T1134 Token Impersonation |
| Defense Evasion | T1562 Impair Defenses, T1562.008 Disable CloudTrail |
| Credential Access | T1552 Unsecured Credentials, T1528 Steal App Token |
| Lateral Movement | T1021 Remote Services, T1021.001 RDP |
| Exfiltration | T1537 Transfer to Cloud, T1048 Exfil Alt Protocol |
| Impact | T1485 Data Destruction, T1490 Inhibit Recovery |

---

## Project Structure

```
sophos-cloud-radar/
├── SophosCloudRadar.jsx     # Main React component (single file)
├── README.md                # This file
└── lovable-prompt.md        # Lovable deployment prompt
```

---

## Technology Stack

- **React** with hooks (useState, useEffect)
- **Claude AI** — claude-sonnet-4-6 via Anthropic API
- **Persistent Storage** — window.storage API for scan history
- **Pure CSS-in-JS** — no external UI libraries required
- **SVG** — animated radar logo, score gauge, MITRE matrix

---

## Contributing

Pull requests are welcome. For major changes please open an issue first.

1. Fork the repo
2. Create your feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m 'Add your feature'`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a Pull Request

---

## Roadmap

- [ ] Jira / ServiceNow ticket creation from findings
- [ ] Slack / Teams webhook for critical alerts
- [ ] Multi-file upload (drag and drop entire Terraform folder)
- [ ] Live AWS / Azure API connection (read-only)
- [ ] Custom compliance profile builder
- [ ] Follow-up chat with Claude about specific findings
- [ ] What-if simulator (predict impact of config changes)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Built With

- [Anthropic Claude](https://anthropic.com) — AI analysis engine
- [Sophos](https://sophos.com) — Security product context and brand
- [MITRE ATT&CK](https://attack.mitre.org) — Threat framework mapping
- [Lovable](https://lovable.dev) — Deployment platform

---

## Acknowledgements

Built to address the compliance visibility gap created by the deprecation of Sophos Cloud Optix. Sophos Cloud Radar provides AI-native, real-time cloud configuration analysis without the overhead of a full platform deployment.

---

*Sophos Cloud Radar - Powered by Claude AI*
