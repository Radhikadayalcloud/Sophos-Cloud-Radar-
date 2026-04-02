# Sophos Cloud Radar

> AI-powered cloud security analyzer — instantly detects misconfigurations, threats and compliance gaps across AWS, Azure, GCP and IaC environments. Powered by Claude AI.

---

## What It Does

Sophos Cloud Radar lets security engineers, DevOps teams and compliance professionals paste any cloud configuration, flow log or activity log and receive an instant AI-powered security analysis,complete with MITRE ATT&CK mapping, compliance scoring, remediation CLI commands and Jira ticket creation.

Built as a modern companion tool to fill the visibility gap left by the deprecation of Sophos Cloud Optix.

---

## Features

### Three Analysis Modes

| Mode | What It Analyzes |
|---|---|
| Config Files | IAM policies, Security Groups, Terraform, CloudFormation, ARM templates, Dockerfiles, Kubernetes YAML |
| Flow Logs | VPC Flow Logs, Azure NSG Flow Logs, GCP VPC Logs |
| Activity Logs | CloudTrail, Azure Monitor, GCP Audit Logs |

### Four Environments

| Environment | Coverage |
|---|---|
| AWS | IAM wildcards, GuardDuty, CloudTrail, S3 public access, VPC flow threats |
| Azure | NSG Flow Logs, Azure AD, Defender alerts, Key Vault, RBAC escalation |
| GCP | IAM policies, Firewall rules, Cloud Audit logs, Security Command Center |
| IaC | Terraform, CloudFormation, ARM, Bicep, Pulumi, CDK, Container Images, K8s YAML |

### Results Dashboard

- Risk Score gauge (0-100) with SECURE / NEEDS ATTENTION / AT RISK status
- Domain Breakdown — IAM, Network, Data Protection, Logging, Encryption, Compliance
- Findings Table — filterable by severity, expandable with CLI remediation commands
- MITRE ATT&CK Visualizer — 12-tactic kill chain matrix linked to attack.mitre.org
- Scan History — persistent posture tracking with trend chart and delta comparison
- Jira Integration — one-click ticket creation per finding, bulk create all critical
- PDF Export — branded HTML report

### Compliance Frameworks (12)

General Best Practices, CIS AWS v2.0, CIS Azure v2.0, NIST CSF, SOC 2 Type II, PCI-DSS v4.0, ISO 27001, HIPAA, UK Cyber Essentials, AWS Well-Architected Framework, NCSC CAF v4.0, ASD Essential Eight

### Multi-Tab Editor

- Up to 8 tabs, drag to reorder, double-click to rename
- Right-click context menu — duplicate, color code, clear, remove
- Environment lock — prevents mixing configs from different providers
- Per-tab type selection, bottom summary bar

---

## Getting Started

### Prerequisites

- Node.js 18+
- Anthropic API key from [console.anthropic.com](https://console.anthropic.com/keys)

### Run Locally

```bash
git clone https://github.com/YOUR-USERNAME/sophos-cloud-radar.git
cd sophos-cloud-radar
npm create vite@latest . -- --template react
npm install
cp SophosCloudRadar.jsx src/App.jsx
npm run dev
```

Open http://localhost:5173 and enter your API key.

---

## Jira Integration

1. Click Jira Settings on results screen
2. Enter Jira base URL, project key, email and API token
3. Click Create Jira Ticket on any finding
4. Or click Create All Critical for bulk creation

Priority mapping: Critical=Highest, High=High, Medium=Medium, Low=Low

---

## Performance

Runs on Claude Haiku 4.5 with optimised prompts.

| Config Type | Expected Time |
|---|---|
| IAM JSON | 1-2 seconds |
| Terraform template | 2-3 seconds |
| CloudFormation | 2-4 seconds |
| Multi-tab (2 configs) | 3-5 seconds |

Optimisations: Haiku model, 1000 max tokens, 1-sentence system prompt, 2000 char input cap, max 5 findings.

---

## Demo Configs

| Demo | Provider | Mode |
|---|---|---|
| AWS IAM Wildcard Policy | AWS | Config |
| AWS Insecure Security Group | AWS | Config |
| AWS CloudFormation Stack | AWS | Config |
| AWS VPC Flow Logs | AWS | Flow Logs |
| AWS CloudTrail Events | AWS | Activity Logs |
| Azure NSG Flow Logs | Azure | Flow Logs |
| Azure Monitor Logs | Azure | Activity Logs |
| Terraform Insecure | IaC | Config |
| Dockerfile Insecure | IaC | Config |

---

## MITRE ATT&CK Coverage

12 tactics covered: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Command and Control, Impact.

---

## Architecture

```
Config input (up to 2000 chars per tab)
        |
Claude Haiku 4.5 - ultra-lean prompts
        |
JSON parsed and displayed
        |
Findings + MITRE + History + Jira + PDF
```

---

## Roadmap

- [ ] Streaming responses
- [ ] Remediation script generator
- [ ] Risk acceptance workflow
- [ ] Follow-up chat with Claude
- [ ] Multi-file upload
- [ ] Slack and Teams webhooks
- [ ] Custom rule builder

---

## License

MIT

---


