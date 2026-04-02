# Changelog

All notable changes to Sophos Cloud Radar are documented here.

---

## [2.0.0] - 2026

### Added
- IaC as a fourth environment alongside AWS, Azure, GCP
- IaC config types: Terraform, CloudFormation, ARM Template, Bicep, Pulumi, Ansible, CDK, Container Image, Kubernetes YAML, Helm Chart, Docker Compose
- Jira integration - one-click ticket creation per finding with bulk create for all critical findings
- NCSC Cyber Assessment Framework v4.0 compliance framework
- ASD Essential Eight compliance framework
- AWS Well-Architected Framework compliance framework
- Multi-tab config editor with up to 8 tabs
- Drag to reorder tabs
- Right-click context menu on tabs (rename, duplicate, color, clear, remove)
- 6-color tab coding system
- Environment lock - prevents mixing configs from different providers
- Demo not available message when no demo matches current provider and mode
- API key sanitisation - strips non-ISO-8859-1 characters from clipboard paste
- Input trimming - 2000 character cap per tab for performance
- HTML escaping in PDF report to handle special characters

### Changed
- Model switched from claude-sonnet to claude-haiku-4-5 for 5x faster analysis
- max_tokens reduced from 8000 to 1000
- System prompt reduced to single sentence
- JSON schema moved to user message for faster TTFT
- Max findings reduced from 8 to 5
- PDF export switched from appendChild/click to window.open approach
- Step numbering: Config Type and Compliance Framework both now Step 3, Editor is Step 4
- Font changed to Aptos with Segoe UI and Arial fallbacks
- Background changed to dark blue gradient
- Provider description badges removed from Step 2 (duplicated Step 3)
- Paste and Fetch Live button font size increased for consistency

### Fixed
- Invalid or unexpected token errors from Unicode characters
- JSX comment missing closing brace
- JSON schema curly braces causing parse error in JSX
- PDF export blocked in sandboxed iframe environments
- API key header error from non-ISO-8859-1 characters

---

## [1.0.0] - 2025

### Added
- Initial release
- AWS, Azure, GCP environment support
- Config Files, Flow Logs, Activity Logs analysis modes
- MITRE ATT&CK visualizer with 12-tactic kill chain matrix
- Scan history with posture trend tracking
- PDF export as HTML report
- Azure enhanced analysis: NSG Flow Logs, Azure AD Sign-ins, Defender alerts
- CIS AWS, CIS Azure, NIST CSF, SOC 2, PCI-DSS, ISO 27001, HIPAA, UK Cyber Essentials frameworks
- Live config fetcher with CLI commands per provider
- Demo configs for AWS IAM, Security Groups, VPC Flow Logs, CloudTrail
- Demo configs for Azure NSG Flow Logs, Azure Monitor activity logs
- Demo configs for IaC Terraform and Dockerfile
