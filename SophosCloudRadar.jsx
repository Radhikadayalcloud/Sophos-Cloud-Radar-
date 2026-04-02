import { useState, useEffect } from "react";

const MITRE_TACTICS = [
  { id:"TA0001", name:"Initial Access",       short:"Initial Access",      color:"#7C3AED" },
  { id:"TA0002", name:"Execution",            short:"Execution",           color:"#DC2626" },
  { id:"TA0003", name:"Persistence",          short:"Persistence",         color:"#D97706" },
  { id:"TA0004", name:"Privilege Escalation", short:"Priv Escalation",     color:"#EA580C" },
  { id:"TA0005", name:"Defense Evasion",      short:"Defense Evasion",     color:"#0891B2" },
  { id:"TA0006", name:"Credential Access",    short:"Credential Access",   color:"#7C3AED" },
  { id:"TA0007", name:"Discovery",            short:"Discovery",           color:"#059669" },
  { id:"TA0008", name:"Lateral Movement",     short:"Lateral Movement",    color:"#B45309" },
  { id:"TA0009", name:"Collection",           short:"Collection",          color:"#0369A1" },
  { id:"TA0010", name:"Exfiltration",         short:"Exfiltration",        color:"#BE123C" },
  { id:"TA0011", name:"Command & Control",    short:"C2",                  color:"#6D28D9" },
  { id:"TA0040", name:"Impact",               short:"Impact",              color:"#991B1B" },
];

const TECHNIQUE_TO_TACTIC = {
  "T1078":"TA0001","T1190":"TA0001","T1133":"TA0001","T1566":"TA0001",
  "T1059":"TA0002","T1059.001":"TA0002","T1203":"TA0002",
  "T1098":"TA0003","T1136":"TA0003","T1078.004":"TA0003","T1531":"TA0003",
  "T1548":"TA0004","T1548.002":"TA0004","T1134":"TA0004",
  "T1562":"TA0005","T1562.001":"TA0005","T1562.008":"TA0005","T1070":"TA0005",
  "T1552":"TA0006","T1552.001":"TA0006","T1555":"TA0006","T1528":"TA0006",
  "T1087":"TA0007","T1069":"TA0007","T1526":"TA0007","T1619":"TA0007",
  "T1021":"TA0008","T1021.001":"TA0008","T1550":"TA0008",
  "T1530":"TA0009","T1213":"TA0009","T1005":"TA0009",
  "T1537":"TA0010","T1041":"TA0010","T1048":"TA0010",
  "T1071":"TA0011","T1071.001":"TA0011","T1572":"TA0011",
  "T1485":"TA0040","T1490":"TA0040","T1496":"TA0040","T1499":"TA0040",
};

const TECHNIQUE_NAMES = {
  "T1078":"Valid Accounts","T1190":"Exploit Public App","T1133":"External Remote Services","T1566":"Phishing",
  "T1059":"Command Scripting","T1059.001":"PowerShell","T1203":"Exploitation",
  "T1098":"Account Manipulation","T1136":"Create Account","T1078.004":"Cloud Accounts","T1531":"Account Removal",
  "T1548":"Abuse Elevation","T1548.002":"Bypass UAC","T1134":"Token Impersonation",
  "T1562":"Impair Defenses","T1562.001":"Disable AV/EDR","T1562.008":"Disable Logging","T1070":"Indicator Removal",
  "T1552":"Unsecured Credentials","T1552.001":"Credentials in Files","T1555":"Password Stores","T1528":"Steal App Token",
  "T1087":"Account Discovery","T1069":"Permission Groups","T1526":"Cloud Discovery","T1619":"Cloud Storage Discovery",
  "T1021":"Remote Services","T1021.001":"RDP","T1550":"Use Alt Auth Material",
  "T1530":"Cloud Storage Object","T1213":"Data from Info Repos","T1005":"Local System Data",
  "T1537":"Transfer to Cloud","T1041":"Exfil Over C2","T1048":"Exfil Alt Protocol",
  "T1071":"App Layer Protocol","T1071.001":"Web Protocols","T1572":"Protocol Tunneling",
  "T1485":"Data Destruction","T1490":"Inhibit Recovery","T1496":"Resource Hijacking","T1499":"Endpoint DoS",
};

const SEV = {
  critical:{ bg:"#3D1515", text:"#FF5C5C", border:"#FF5C5C" },
  high:    { bg:"#3D2810", text:"#FF9A3C", border:"#FF9A3C" },
  medium:  { bg:"#3D3510", text:"#FFD43B", border:"#FFD43B" },
  low:     { bg:"#10243D", text:"#60AAFF", border:"#60AAFF" },
  info:    { bg:"#1A1A2E", text:"#A0A0C0", border:"#A0A0C0" },
};

const DOMAIN_ICONS = {
  "IAM & Access Control":"[KEY]",
  "Network Security":"[NET]",
  "Data Protection":"[DATA]",
  "Logging & Monitoring":"[LOG]",
  "Encryption":"[ENC]",
  "Compliance Posture":"[COMP]",
  "Threat Detection":"[THREAT]",
  "Suspicious Activity":"[ALERT]",
  "Identity & Access":"[ID]",
};

const MODE_COLOR = { config:"#3B82F6", flowlog:"#06B6D4", activitylog:"#A855F7" };

const FRAMEWORKS = [
  "General Best Practices",
  "CIS AWS Benchmark v2.0",
  "CIS Azure Benchmark v2.0",
  "NIST CSF",
  "SOC 2 Type II",
  "PCI-DSS v4.0",
  "ISO 27001",
  "HIPAA",
  "UK Cyber Essentials",
  "AWS Well-Architected Framework",
  "NCSC Cyber Assessment Framework v4.0",
  "ASD Essential Eight",
];

const PROVIDERS = ["AWS","Azure","GCP","IaC"];

const PROVIDER_COLORS = {
  AWS:   "#FF9A3C",
  Azure: "#0085CA",
  GCP:   "#34A853",
  IaC:   "#A855F7",
};

const PROVIDER_LABELS = {
  AWS:   "AWS",
  Azure: "Azure",
  GCP:   "GCP",
  IaC:   "IaC",
};

const INPUT_MODES = [
  { id:"config",      label:"Config Files",  desc:"IAM, NSG, ARM Templates, Storage, Policies" },
  { id:"flowlog",     label:"Flow Logs",      desc:"VPC Flow, Azure NSG Flow, GCP VPC" },
  { id:"activitylog", label:"Activity Logs",  desc:"CloudTrail, Azure Monitor, GCP Audit" },
];

const IAC_TOOLS = ["Terraform","CloudFormation","ARM Template","Bicep","Pulumi","Ansible","CDK"];

const CONFIG_TYPES = {
  config: {
    AWS:   ["IAM Policy","Security Groups","S3 Bucket","CloudFormation","Lambda Policy","RDS Config","Network ACL"],
    Azure: ["Azure RBAC Policy","NSG Rules","Storage Account","Key Vault Config","Azure AD Policy","App Service","Azure Firewall"],
    GCP:   ["GCP IAM Policy","Firewall Rules","Cloud Storage","GKE Config","Cloud Functions","VPC Config"],
    IaC:   ["Terraform","CloudFormation","ARM Template","Bicep","Pulumi","Ansible","CDK","Container Image","Kubernetes YAML","Helm Chart","Docker Compose"],
  },
  flowlog: {
    AWS:   ["VPC Flow Logs","ELB Access Logs","CloudFront Logs"],
    Azure: ["NSG Flow Logs","Azure Firewall Logs","Application Gateway Logs","Traffic Analytics"],
    GCP:   ["VPC Flow Logs","Cloud Armor Logs","Load Balancer Logs"],
    IaC:   ["Pipeline Logs","Container Build Logs","Deployment Logs"],
  },
  activitylog: {
    AWS:   ["CloudTrail Events","Config Rules","GuardDuty Findings","Security Hub Alerts"],
    Azure: ["Azure Monitor / Activity Log","Azure AD Sign-in Logs","Microsoft Defender Alerts","Key Vault Audit Logs","Azure Policy Events"],
    GCP:   ["Cloud Audit Logs","Security Command Center","Cloud Armor Events"],
    IaC:   ["CI/CD Pipeline Audit","Terraform State Logs","Deployment Change Logs"],
  },
};

const LOAD_MSGS = {
  config:      ["Parsing configuration...","Checking permissions...","Mapping compliance controls...","Generating findings..."],
  flowlog:     ["Parsing flow log entries...","Detecting anomalous traffic...","Identifying suspicious IPs...","Generating threat findings..."],
  activitylog: ["Parsing activity events...","Hunting for threats...","Mapping to MITRE ATT&CK...","Generating incident findings..."],
};

const AZURE_FLOW_DEMO = '[{"time":"2024-03-18T02:00:00Z","category":"NetworkSecurityGroupFlowEvent","properties":{"flows":[{"rule":"AllowRDP","flows":[{"mac":"000D3A123456","flowTuples":["1710727200,185.220.101.45,10.0.1.10,52341,3389,T,I,A,C","1710727260,45.33.32.156,10.0.1.10,48291,3389,T,I,A,C"]}]},{"rule":"AllowSQL","flows":[{"mac":"000D3A654321","flowTuples":["1710727380,10.0.1.10,10.0.2.50,54231,1433,T,I,A,B","1710727440,10.0.2.50,203.99.44.12,55000,443,T,O,A,E,,,9000,52428800"]}]}]}}]';
const AZURE_ACTIVITY_DEMO = '[{"time":"2024-03-18T02:14:33Z","operationName":"Sign-in activity","category":"SignInLogs","properties":{"userPrincipalName":"admin@company.com","ipAddress":"185.220.101.45","authenticationRequirement":"singleFactorAuthentication","riskLevelDuringSignIn":"high","location":{"city":"Moscow","countryOrRegion":"RU"}}},{"time":"2024-03-18T02:18:00Z","operationName":"Microsoft.Authorization/roleAssignments/write","properties":{"principalName":"svc-deploy@company.com","roleDefinitionName":"Owner","scope":"/subscriptions/abc123"}},{"time":"2024-03-18T02:25:00Z","operationName":"Microsoft.Insights/diagnosticSettings/delete","properties":{"resourceId":"/subscriptions/abc123/resourceGroups/prod-rg","callerIpAddress":"185.220.101.45"}}]';

const DEMO_CONFIGS = [
  { label:"AWS IAM - Wildcard", type:"IAM Policy", provider:"AWS", mode:"config",
    config:'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::*"}]}' },
  { label:"AWS - Insecure SG", type:"Security Groups", provider:"AWS", mode:"config",
    config:'resource "aws_security_group" "web" {\n  ingress { from_port=22, to_port=22, protocol="tcp", cidr_blocks=["0.0.0.0/0"] }\n  ingress { from_port=3389, to_port=3389, protocol="tcp", cidr_blocks=["0.0.0.0/0"] }\n}' },
  { label:"AWS VPC Flow Logs", type:"VPC Flow Logs", provider:"AWS", mode:"flowlog",
    config:"version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action\n2 123456789012 eni-0a1b2c3d 203.0.113.5 10.0.1.50 45832 22 6 10 4000 1620000000 1620000060 ACCEPT\n2 123456789012 eni-0a1b2c3d 45.33.32.156 10.0.1.50 39842 22 6 500 185000 1620000360 1620000420 ACCEPT" },
  { label:"AWS CloudTrail", type:"CloudTrail Events", provider:"AWS", mode:"activitylog",
    config:'[{"eventTime":"2024-03-18T02:14Z","eventName":"ConsoleLogin","userIdentity":{"userName":"admin"},"sourceIPAddress":"185.220.101.45","additionalEventData":{"MFAUsed":"No"}},{"eventTime":"2024-03-18T02:15Z","eventName":"AttachUserPolicy","requestParameters":{"policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}}]' },
  { label:"Azure NSG Flow Logs", type:"NSG Flow Logs", provider:"Azure", mode:"flowlog", config:AZURE_FLOW_DEMO },
  { label:"Azure Activity Logs", type:"Azure Monitor / Activity Log", provider:"Azure", mode:"activitylog", config:AZURE_ACTIVITY_DEMO },
  { label:"Terraform - Insecure", type:"Terraform", provider:"IaC", mode:"config",
    config:'resource "aws_s3_bucket" "data" {\n  bucket = "company-prod-data"\n}\nresource "aws_s3_bucket_acl" "data" {\n  bucket = aws_s3_bucket.data.id\n  acl    = "public-read-write"\n}\nvariable "db_password" {\n  default = "supersecret123"\n}' },
  { label:"Dockerfile - Insecure", type:"Container Image", provider:"IaC", mode:"config",
    config:"FROM ubuntu:latest\nRUN apt-get update\nENV DB_PASSWORD=mysecretpassword\nENV API_KEY=sk-prod-abc123\nRUN useradd -m appuser\nCOPY . /app\nUSER root\nEXPOSE 22 80 443 3306 5432\nCMD [\"/app/start.sh\"]" },
];

const STORAGE_KEY = "sophos-cloud-radar-v3";
const MAX_HISTORY = 10;

async function loadHistory() {
  try {
    const r = await window.storage.get(STORAGE_KEY);
    return r ? JSON.parse(r.value) : [];
  } catch { return []; }
}
async function saveHistory(scans) {
  try { await window.storage.set(STORAGE_KEY, JSON.stringify(scans)); }
  catch(e) { console.warn("Storage save failed:", e); }
}
function buildScanRecord(results, provider, framework, inputMode) {
  const counts = (results.findings||[]).reduce((a,f)=>({...a,[f.severity]:(a[f.severity]||0)+1}),{});
  return {
    id: Date.now().toString(),
    timestamp: new Date().toISOString(),
    label: provider + " - " + (results.analysis_type||inputMode) + " - " + framework,
    provider, framework, inputMode,
    overall_risk_score: results.overall_risk_score,
    compliance_score: results.compliance_score,
    total_findings: results.findings?.length||0,
    critical: counts.critical||0, high: counts.high||0,
    medium: counts.medium||0, low: counts.low||0,
    top_critical_finding: results.top_critical_finding||"",
    executive_summary: results.executive_summary||"",
    domains: results.domains||[],
  };
}
function getDelta(curr, prev) {
  if (!prev) return null;
  return {
    score:      curr.overall_risk_score - prev.overall_risk_score,
    compliance: curr.compliance_score   - prev.compliance_score,
    findings:   curr.total_findings     - prev.total_findings,
    critical:   (curr.critical||0)      - (prev.critical||0),
  };
}

function buildPrompt(mode, provider) {
  if(mode==="flowlog")     return "Security analyst. Find threats in "+provider+" flow logs. Return ONLY the JSON in user message. No prose.";
  if(mode==="activitylog") return "Threat hunter. Find threats in "+provider+" logs. Map findings to MITRE. Return ONLY the JSON in user message. No prose.";
  return "Security engineer. Find vulnerabilities in "+provider+" config. Return ONLY the JSON in user message. No prose.";
}

function repairJSON(str) {
  let s = str.replace(/,\s*$/,"").replace(/,\s*"[^"]*$/,"").replace(/:\s*"[^"]*$/,':"\"\"');
  const closes={"{":"}","[":"]"};
  const stack=[];
  let inStr=false, esc=false;
  for (let i=0;i<s.length;i++) {
    const c=s[i];
    if(esc){esc=false;continue;}
    if(c==="\\"){esc=true;continue;}
    if(c==='"'){inStr=!inStr;continue;}
    if(!inStr){if(c==="{"||c==="[")stack.push(closes[c]);else if(c==="}"||c==="]")stack.pop();}
  }
  if(inStr)s+='"';
  return s+stack.reverse().join("");
}


const RESPONSE_SCHEMA = '{"overall_risk_score":0,"compliance_score":0,"estimated_fix_hours":0,"analysis_type":"","executive_summary":"","top_critical_finding":"","quick_wins_count":0,"domains":[{"name":"","score":0,"top_issue":""}],"findings":[{"id":"f1","control_id":"","title":"","severity":"critical","domain":"","affected_resource":"","what_it_means":"","business_impact":"","remediation_steps":"","cli_command":"","framework_reference":"","quick_win":false,"mitre_technique_id":"","mitre_tactic":""}]}';

function extractMitreTechniques(findings) {
  const techs = {};
  (findings||[]).forEach(f => {
    const raw = (f.mitre_technique_id||f.control_id||"").trim();
    const matches = raw.match(/T\d{4}(?:\.\d{3})?/g)||[];
    matches.forEach(id => {
      if (!techs[id]) techs[id] = { id, name:TECHNIQUE_NAMES[id]||id, tactic:TECHNIQUE_TO_TACTIC[id], findings:[] };
      techs[id].findings.push(f);
    });
  });
  return Object.values(techs);
}

function generatePDF(results, framework, provider) {
  const sc = {critical:"#dc2626",high:"#ea580c",medium:"#ca8a04",low:"#2563eb",info:"#6b7280"};
  const date = new Date().toLocaleDateString("en-GB",{day:"2-digit",month:"long",year:"numeric"});
  const scoreColor = results.overall_risk_score>=75?"#16a34a":results.overall_risk_score>=50?"#d97706":"#dc2626";
  const counts = (results.findings||[]).reduce((a,f)=>({...a,[f.severity]:(a[f.severity]||0)+1}),{});
  const techniques = extractMitreTechniques(results.findings||[]);

  const mitreHTML = techniques.length ? "<div style=\"margin:12px 0\"><div style=\"font-size:11px;font-weight:700;color:#3b82f6;text-transform:uppercase;margin-bottom:6px\">MITRE ATT&CK Techniques</div><div style=\"display:flex;flex-wrap:wrap;gap:5px\">" + techniques.map(t=>"<div style=\"border:1px solid "+(sc[t.findings[0]?.severity]||"#e5e7eb")+";border-radius:4px;padding:4px 7px\"><div style=\"font-size:9px;font-weight:700;color:"+(sc[t.findings[0]?.severity]||"#374151")+";font-family:monospace\">"+t.id+"</div><div style=\"font-size:10px\">"+t.name+"</div></div>").join("") + "</div></div>" : "";

  const esc = s => (s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
  const findingsHTML = (results.findings||[]).map(f=>"<div style=\"margin-bottom:7px;padding:7px;border:1px solid #e5e7eb;border-radius:4px;border-left:3px solid "+(sc[f.severity]||"#6b7280")+"\"><div style=\"display:flex;justify-content:space-between;margin-bottom:3px\"><span style=\"font-weight:700;font-size:11px\">"+esc(f.title)+"</span><span style=\"font-size:9px;font-weight:700;color:"+(sc[f.severity]||"#6b7280")+";text-transform:uppercase;padding:1px 5px;border:1px solid "+(sc[f.severity]||"#6b7280")+";border-radius:3px\">"+f.severity+"</span></div><div style=\"font-size:9px;color:#6b7280;margin-bottom:3px\">"+f.control_id+" | "+f.affected_resource+" | "+f.domain+"</div><div style=\"font-size:10px\"><b>Meaning:</b> "+esc(f.what_it_means)+"</div><div style=\"font-size:10px\"><b>Fix:</b> "+esc(f.remediation_steps)+"</div>"+(f.cli_command&&f.cli_command!=="N/A"?"<div style=\"margin-top:4px;padding:4px;background:#f3f4f6;border-radius:3px;font-family:monospace;font-size:9px;color:#047857\">"+esc(f.cli_command)+"</div>":"")+"</div>").join("");

  const domainsHTML = (results.domains||[]).map(d=>{const dc=d.score>=75?"#16a34a":d.score>=50?"#d97706":"#dc2626";return "<div style=\"margin-bottom:6px\"><div style=\"display:flex;justify-content:space-between;margin-bottom:2px\"><span style=\"font-size:10px;font-weight:600\">"+d.name+"</span><span style=\"font-size:10px;font-weight:700;color:"+dc+"\">"+d.score+"%</span></div><div style=\"background:#e5e7eb;height:5px;border-radius:3px\"><div style=\"background:"+dc+";width:"+d.score+"%;height:100%;border-radius:3px\"></div></div></div>";}).join("");

  const html = "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Sophos Cloud Radar Report</title><style>body{font-family:Arial,sans-serif;color:#111;margin:0;padding:0}.hdr{background:linear-gradient(135deg,#0c1a2e,#1e3a5f);color:white;padding:20px 28px}.body{padding:20px 28px}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:10px 0}.card{background:#f8fafc;border:1px solid #e2e8f0;border-radius:5px;padding:10px;text-align:center}.num{font-size:22px;font-weight:900;margin:4px 0 2px}.lbl{font-size:8px;color:#6b7280;text-transform:uppercase;letter-spacing:1px}.footer{background:#f8fafc;border-top:1px solid #e5e7eb;padding:10px 28px;font-size:9px;color:#9ca3af;display:flex;justify-content:space-between}.sec{font-size:11px;font-weight:700;color:#3b82f6;text-transform:uppercase;letter-spacing:2px;margin:14px 0 7px;border-bottom:2px solid #e5e7eb;padding-bottom:4px}</style></head><body>"
    + "<div class=\"hdr\"><div style=\"font-size:16px;font-weight:900;letter-spacing:3px;margin-bottom:2px\">SOPHOS CLOUD RADAR</div><div style=\"font-size:9px;color:#94a3b8;letter-spacing:2px\">AI SECURITY CLOUD ANALYZER</div><div style=\"margin-top:8px;font-size:9px;color:#94a3b8\">Type: "+(results.analysis_type||"Security Analysis")+" | Provider: "+provider+" | Framework: "+framework+" | "+date+"</div></div>"
    + "<div class=\"body\"><div class=\"sec\">Executive Summary</div>"+(results.top_critical_finding?"<div style=\"background:#fef2f2;border:1px solid #fecaca;border-radius:4px;padding:7px 10px;margin-bottom:8px\"><strong style=\"color:#dc2626\">TOP CRITICAL FINDING:</strong> "+results.top_critical_finding+"</div>":"")+"<div style=\"background:#eff6ff;border:1px solid #bfdbfe;border-radius:4px;padding:10px;margin-bottom:10px\"><p style=\"margin:0;font-size:11px;line-height:1.7\">"+results.executive_summary+"</p></div>"
    + "<div class=\"sec\">Risk Scorecard</div><div class=\"cards\"><div class=\"card\"><div class=\"num\" style=\"color:"+scoreColor+"\">"+results.overall_risk_score+"</div><div class=\"lbl\">Risk Score /100</div></div><div class=\"card\"><div class=\"num\">"+(results.findings?.length||0)+"</div><div class=\"lbl\">Issues Found</div></div><div class=\"card\"><div class=\"num\" style=\"color:"+(results.compliance_score>=70?"#16a34a":"#dc2626")+"\">"+results.compliance_score+"%</div><div class=\"lbl\">Compliance</div></div><div class=\"card\"><div class=\"num\">"+results.estimated_fix_hours+"h</div><div class=\"lbl\">Fix Time</div></div></div>"
    + "<div style=\"display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px\">"+["critical","high","medium","low"].map(s=>counts[s]?"<span style=\"font-size:9px;padding:2px 7px;background:#f3f4f6;border-radius:3px;border-left:2px solid "+sc[s]+"\"><strong>"+counts[s]+"</strong> "+s+"</span>":"").join("")+"</div>"
    + "<div class=\"sec\">Domain Risk Breakdown</div>"+domainsHTML+mitreHTML
    + "<div class=\"sec\">Security Findings</div>"+findingsHTML+"</div>"
    + "<div class=\"footer\"><span>Sophos Cloud Radar - Powered by Claude AI</span><span>"+date+" - "+framework+"</span></div></body></html>";

  // Open report in new tab - user can File > Print > Save as PDF
  try {
    const win = window.open("","_blank");
    if(win) {
      win.document.write(html);
      win.document.close();
    } else {
      // Fallback: blob URL
      const blob = new Blob([html],{type:"text/html;charset=utf-8"});
      const url  = URL.createObjectURL(blob);
      window.open(url,"_blank");
      setTimeout(()=>URL.revokeObjectURL(url),10000);
    }
  } catch(e) {
    // Final fallback: data URI
    window.open("data:text/html;charset=utf-8,"+encodeURIComponent(html),"_blank");
  }
}

function ScoreGauge({ score }) {
  const color = score>=75?"#10B981":score>=50?"#F59E0B":"#EF4444";
  const label = score>=75?"SECURE":score>=50?"NEEDS ATTENTION":"AT RISK";
  const r=54, circ=2*Math.PI*r;
  return (
    <div style={{display:"flex",flexDirection:"column",alignItems:"center"}}>
      <svg width="120" height="120" viewBox="0 0 128 128">
        <circle cx="64" cy="64" r={r} fill="none" stroke="#1E293B" strokeWidth="10"/>
        <circle cx="64" cy="64" r={r} fill="none" stroke={color} strokeWidth="10"
          strokeDasharray={circ} strokeDashoffset={circ-(score/100)*circ}
          strokeLinecap="round" transform="rotate(-90 64 64)"
          style={{transition:"stroke-dashoffset 1s ease"}}/>
        <text x="64" y="60" textAnchor="middle" fill="white" fontSize="22" fontWeight="bold" fontFamily="monospace">{score}</text>
        <text x="64" y="78" textAnchor="middle" fill="#94A3B8" fontSize="9" fontFamily="monospace">/100</text>
      </svg>
      <span style={{color,fontSize:"10px",fontWeight:"700",letterSpacing:"2px",marginTop:"4px"}}>{label}</span>
    </div>
  );
}

function SevBadge({ s }) {
  const c = SEV[s]||SEV.info;
  return (
    <span style={{background:c.bg,color:c.text,border:"1px solid "+c.border,borderRadius:"3px",padding:"2px 6px",fontSize:"9px",fontWeight:"700",letterSpacing:"1px",textTransform:"uppercase",fontFamily:"monospace"}}>{s}</span>
  );
}

function DomainBar({ d }) {
  const color = d.score>=75?"#10B981":d.score>=50?"#F59E0B":"#EF4444";
  return (
    <div style={{background:"#0F1A2E",border:"1px solid #1E3A5F",borderRadius:"8px",padding:"10px 12px"}}>
      <div style={{display:"flex",justifyContent:"space-between",marginBottom:"5px"}}>
        <span style={{color:"#E2E8F0",fontSize:"10px",fontWeight:"600"}}>{DOMAIN_ICONS[d.name]||"+"} {d.name}</span>
        <span style={{color,fontWeight:"700",fontSize:"10px",fontFamily:"monospace"}}>{d.score}%</span>
      </div>
      <div style={{background:"#1E293B",borderRadius:"3px",height:"4px",marginBottom:"4px"}}>
        <div style={{background:color,width:d.score+"%",height:"100%",borderRadius:"3px",transition:"width 1s ease"}}/>
      </div>
      <p style={{color:"#64748B",fontSize:"8px",margin:0}}>{d.top_issue}</p>
    </div>
  );
}

function FindingRow({ f, onCreateJira, jiraKey, jiraCreating }) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const copy = t => { navigator.clipboard.writeText(t); setCopied(true); setTimeout(()=>setCopied(false),1500); };
  return (
    <div style={{borderBottom:"1px solid #1E293B"}}>
      <div onClick={()=>setOpen(!open)}
        style={{display:"grid",gridTemplateColumns:"90px 95px 1fr 145px 20px",alignItems:"center",gap:"10px",padding:"10px 14px",cursor:"pointer"}}
        onMouseEnter={e=>e.currentTarget.style.background="#0F1A2E"}
        onMouseLeave={e=>e.currentTarget.style.background=open?"#0F1A2E":"transparent"}>
        <SevBadge s={f.severity}/>
        <span style={{color:"#60AAFF",fontSize:"10px",fontFamily:"monospace",wordBreak:"break-all"}}>{f.control_id}</span>
        <div>
          <p style={{color:"#E2E8F0",fontSize:"12px",fontWeight:"600",margin:0}}>{f.title}</p>
          <p style={{color:"#64748B",fontSize:"10px",margin:"1px 0 0"}}>{f.affected_resource}</p>
        </div>
        <span style={{color:"#475569",fontSize:"10px"}}>{f.domain}</span>
        <span style={{color:"#475569",fontSize:"14px",transition:"transform 0.2s",transform:open?"rotate(90deg)":"none"}}>{">"}</span>
      </div>
      {open && (
        <div style={{background:"#070F1A",padding:"14px 17px",borderTop:"1px solid #1E293B"}}>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:"12px",marginBottom:"10px"}}>
            <div>
              <p style={{color:"#60AAFF",fontSize:"9px",fontWeight:"700",letterSpacing:"1px",marginBottom:"4px"}}>WHAT THIS MEANS</p>
              <p style={{color:"#CBD5E1",fontSize:"11px",lineHeight:"1.6",margin:0}}>{f.what_it_means}</p>
            </div>
            <div>
              <p style={{color:"#FF9A3C",fontSize:"9px",fontWeight:"700",letterSpacing:"1px",marginBottom:"4px"}}>BUSINESS IMPACT</p>
              <p style={{color:"#CBD5E1",fontSize:"11px",lineHeight:"1.6",margin:0}}>{f.business_impact}</p>
            </div>
          </div>
          <div style={{marginBottom:"10px"}}>
            <p style={{color:"#10B981",fontSize:"9px",fontWeight:"700",letterSpacing:"1px",marginBottom:"4px"}}>HOW TO FIX</p>
            <p style={{color:"#CBD5E1",fontSize:"11px",lineHeight:"1.7",margin:0,whiteSpace:"pre-line"}}>{f.remediation_steps}</p>
          </div>
          {f.cli_command && f.cli_command!=="N/A" && (
            <div style={{background:"#0A0F1A",border:"1px solid #1E3A5F",borderRadius:"6px",padding:"9px 12px"}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"6px"}}>
                <span style={{color:"#60AAFF",fontSize:"9px",fontWeight:"700",letterSpacing:"1px"}}>CLI COMMAND</span>
                <button onClick={()=>copy(f.cli_command)} style={{background:copied?"#10B981":"#1E3A5F",color:"white",border:"none",borderRadius:"3px",padding:"2px 8px",fontSize:"10px",cursor:"pointer"}}>{copied?"Copied":"Copy"}</button>
              </div>
              <code style={{color:"#10B981",fontSize:"10px",fontFamily:"monospace",display:"block",lineHeight:"1.6",whiteSpace:"pre-wrap",wordBreak:"break-all"}}>{f.cli_command}</code>
            </div>
          )}
          {f.mitre_technique_id && (
            <p style={{color:"#475569",fontSize:"10px",marginTop:"7px",marginBottom:0}}>
              <strong style={{color:"#A855F7"}}>MITRE:</strong> {f.mitre_technique_id} - {f.mitre_tactic||""}
              {" "}{f.framework_reference&&<span>| {f.framework_reference}</span>}
              {f.quick_win&&<span style={{marginLeft:"10px",color:"#10B981"}}> Quick Win</span>}
            </p>
          )}
          <div style={{marginTop:"10px",paddingTop:"10px",borderTop:"1px solid #1E293B",display:"flex",alignItems:"center",gap:"8px"}}>
            {jiraKey
              ? <a href="#" style={{display:"flex",alignItems:"center",gap:"5px",background:"#0052CC22",border:"1px solid #0052CC",borderRadius:"5px",padding:"5px 12px",fontSize:"11px",color:"#4C9AFF",textDecoration:"none",fontWeight:"600"}}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="#4C9AFF"><path d="M11.571 11.513H0a5.218 5.218 0 0 0 5.232 5.215h2.13v2.057A5.215 5.215 0 0 0 12.575 24V12.518a1.005 1.005 0 0 0-1.004-1.005zm5.723-5.756H5.736a5.215 5.215 0 0 0 5.215 5.214h2.129v2.058a5.218 5.218 0 0 0 5.215 5.214V6.762a1.005 1.005 0 0 0-1.001-1.005zM23.013 0H11.455a5.215 5.215 0 0 0 5.215 5.215h2.129v2.057A5.215 5.215 0 0 0 24 12.485V1.005A1.005 1.005 0 0 0 23.013 0z"/></svg>
                  {jiraKey} - View in Jira
                </a>
              : <button
                  onClick={e=>{e.stopPropagation();onCreateJira(f);}}
                  disabled={jiraCreating===f.id}
                  style={{display:"flex",alignItems:"center",gap:"5px",background:"#0052CC",border:"none",borderRadius:"5px",padding:"5px 12px",fontSize:"11px",color:"white",cursor:jiraCreating===f.id?"not-allowed":"pointer",fontFamily:"inherit",fontWeight:"600",opacity:jiraCreating===f.id?0.7:1}}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="white"><path d="M11.571 11.513H0a5.218 5.218 0 0 0 5.232 5.215h2.13v2.057A5.215 5.215 0 0 0 12.575 24V12.518a1.005 1.005 0 0 0-1.004-1.005zm5.723-5.756H5.736a5.215 5.215 0 0 0 5.215 5.214h2.129v2.058a5.218 5.218 0 0 0 5.215 5.214V6.762a1.005 1.005 0 0 0-1.001-1.005zM23.013 0H11.455a5.215 5.215 0 0 0 5.215 5.215h2.129v2.057A5.215 5.215 0 0 0 24 12.485V1.005A1.005 1.005 0 0 0 23.013 0z"/></svg>
                  {jiraCreating===f.id?"Creating...":"Create Jira Ticket"}
                </button>
            }
            {f.quick_win && <span style={{background:"#10B98122",color:"#10B981",border:"1px solid #10B98144",borderRadius:"4px",padding:"3px 8px",fontSize:"10px",fontWeight:"600"}}>Quick Win</span>}
          </div>
        </div>
      )}
    </div>
  );
}

const TAB_COLORS = ["#3B82F6","#10B981","#F59E0B","#EF4444","#A855F7","#06B6D4"];

function MultiConfigEditor({ tabs, activeId, mc, inputMode, provider, onTabChange, onTabUpdate, onTabAdd, onTabRemove, onTabClear, onTabDuplicate, onTabReorder }) {
  const activeTab = tabs.find(t=>t.id===activeId)||tabs[0];
  const [editingLabel, setEditingLabel]   = useState(null);
  const [labelDraft,   setLabelDraft]     = useState("");
  const [contextMenu,  setContextMenu]    = useState(null);
  const [colorPicker,  setColorPicker]    = useState(null);
  const [dragId,       setDragId]         = useState(null);
  const [dragOverId,   setDragOverId]     = useState(null);
  const filledCount = tabs.filter(t=>t.content.trim()).length;

  const placeholder = inputMode==="config"
    ? "Paste "+provider+" config - IAM policy, NSG rules, Terraform, CloudFormation, ARM template, Container Image..."
    : inputMode==="flowlog"
    ? "Paste "+provider+" flow logs - VPC Flow, NSG Flow, GCP VPC..."
    : "Paste "+provider+" activity logs - CloudTrail, Azure Monitor, GCP Audit...";

  const getTabColor = tab => tab.color || mc;

  const handleContextMenu = (e, tabId) => {
    e.preventDefault();
    e.stopPropagation();
    setColorPicker(null);
    setContextMenu({ id:tabId, x:e.clientX, y:e.clientY });
  };

  const closeMenus = () => { setContextMenu(null); setColorPicker(null); };

  const handleDragStart = (e, id) => {
    setDragId(id);
    e.dataTransfer.effectAllowed = "move";
  };
  const handleDragOver = (e, id) => {
    e.preventDefault();
    if(id !== dragId) setDragOverId(id);
  };
  const handleDrop = (e, targetId) => {
    e.preventDefault();
    if(dragId && targetId && dragId !== targetId) onTabReorder(dragId, targetId);
    setDragId(null); setDragOverId(null);
  };
  const handleDragEnd = () => { setDragId(null); setDragOverId(null); };

  return (
    <div style={{background:"#F8FAFF",border:"2px solid "+mc,borderRadius:"10px",overflow:"hidden",position:"relative"}} onClick={closeMenus}>

      {/* Tab bar */}
      <div style={{display:"flex",alignItems:"center",borderBottom:"2px solid "+mc+"44",background:"#EFF6FF",minHeight:"44px",overflowX:"auto"}}>
        <div style={{display:"flex",alignItems:"center",flex:1}}>
          {tabs.map((tab,idx) => {
            const isActive   = tab.id===activeId;
            const isFilled   = tab.content.trim().length>0;
            const isDragging = dragId===tab.id;
            const isDragOver = dragOverId===tab.id;
            const tabColor   = getTabColor(tab);
            return (
              <div key={tab.id}
                draggable
                onDragStart={e=>handleDragStart(e,tab.id)}
                onDragOver={e=>handleDragOver(e,tab.id)}
                onDrop={e=>handleDrop(e,tab.id)}
                onDragEnd={handleDragEnd}
                onContextMenu={e=>handleContextMenu(e,tab.id)}
                style={{
                  display:"flex",alignItems:"center",gap:"5px",
                  padding:"0 10px",height:"44px",cursor:"pointer",
                  borderRight:"1px solid #BFDBFE",flexShrink:0,
                  minWidth:"90px",maxWidth:"155px",
                  background:isDragOver?"#DBEAFE":isActive?"#FFFFFF":"transparent",
                  borderBottom:isActive?"3px solid "+tabColor:"3px solid transparent",
                  opacity:isDragging?0.4:1,
                  transition:"background 0.15s",
                  boxShadow:isActive?"0 2px 8px "+tabColor+"33":"none",
                }}>
                {/* Drag handle */}
                <span style={{color:"#CBD5E1",fontSize:"10px",cursor:"grab",flexShrink:0,lineHeight:1,letterSpacing:"1px"}} title="Drag to reorder">...</span>
                {/* Filled dot */}
                {isFilled && <div style={{width:"6px",height:"6px",borderRadius:"50%",background:tabColor,flexShrink:0,boxShadow:"0 0 4px "+tabColor+"88"}}/>}
                {/* Label */}
                {editingLabel===tab.id
                  ? <input autoFocus value={labelDraft}
                      onChange={e=>setLabelDraft(e.target.value)}
                      onBlur={()=>{onTabUpdate(tab.id,"label",labelDraft.trim()||tab.label);setEditingLabel(null);}}
                      onKeyDown={e=>{if(e.key==="Enter"||e.key==="Escape"){onTabUpdate(tab.id,"label",labelDraft.trim()||tab.label);setEditingLabel(null);}}}
                      onClick={e=>e.stopPropagation()}
                      style={{background:"white",border:"2px solid "+tabColor,borderRadius:"4px",color:"#1E293B",fontSize:"11px",fontFamily:"inherit",width:"80px",padding:"2px 5px",outline:"none"}}/>
                  : <span
                      onClick={()=>onTabChange(tab.id)}
                      onDoubleClick={()=>{onTabChange(tab.id);setEditingLabel(tab.id);setLabelDraft(tab.label);}}
                      title="Double-click to rename | Right-click for options"
                      style={{color:isActive?tabColor:"#64748B",fontSize:"12px",fontWeight:isActive?"700":"500",flex:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",userSelect:"none"}}>
                      {tab.label}
                    </span>
                }
                {/* Remove */}
                {tabs.length>1 && (
                  <button onClick={e=>{e.stopPropagation();onTabRemove(tab.id);}}
                    style={{background:"transparent",border:"none",color:"#CBD5E1",cursor:"pointer",fontSize:"14px",padding:"0 2px",lineHeight:1,flexShrink:0,fontWeight:"700"}}
                    title="Remove tab">x</button>
                )}
              </div>
            );
          })}
        </div>
        {/* Add tab button */}
        {tabs.length<8 && (
          <button onClick={onTabAdd} title="Add new config tab"
            style={{padding:"0 14px",height:"44px",background:"linear-gradient(135deg,#3B82F6,#0085CA)",border:"none",borderLeft:"2px solid #BFDBFE",color:"white",cursor:"pointer",fontSize:"20px",fontWeight:"700",flexShrink:0}}>+</button>
        )}
        <div style={{padding:"0 12px",flexShrink:0}}>
          <span style={{color:"#1D4ED8",fontSize:"12px",fontWeight:"700"}}>{filledCount}/{tabs.length}</span>
        </div>
      </div>

      {/* Type indicator bar */}
      <div style={{display:"flex",alignItems:"center",gap:"8px",padding:"7px 14px",borderBottom:"1px solid "+mc+"22",background:"#F0F7FF",flexWrap:"wrap"}}>
        {activeTab.type
          ? <span style={{background:"#ECFDF5",color:"#059669",border:"1px solid #A7F3D0",borderRadius:"4px",padding:"2px 8px",fontSize:"11px",fontWeight:"700"}}>{activeTab.type}</span>
          : <span style={{color:"#94A3B8",fontSize:"11px"}}>No type selected - choose in Step 3 above</span>
        }
        {activeTab.iac && (
          <span style={{background:"#FAF5FF",color:"#7E22CE",border:"1px solid #E9D5FF",borderRadius:"4px",padding:"2px 8px",fontSize:"11px",fontWeight:"600"}}>+ {activeTab.iac} IaC</span>
        )}
        <div style={{marginLeft:"auto",display:"flex",gap:"5px"}}>
          <button onClick={()=>{if(tabs.length<8)onTabDuplicate(activeTab.id);}}
            disabled={tabs.length>=8}
            title="Duplicate this tab"
            style={{background:"#EFF6FF",border:"1px solid #BFDBFE",color:"#1D4ED8",cursor:tabs.length>=8?"not-allowed":"pointer",fontSize:"11px",padding:"3px 9px",borderRadius:"4px",fontFamily:"inherit",fontWeight:"600",opacity:tabs.length>=8?0.4:1}}>
            Copy Tab
          </button>
          <button onClick={()=>onTabClear(activeTab.id)}
            style={{background:"#FEF2F2",border:"1px solid #FECACA",color:"#DC2626",cursor:"pointer",fontSize:"11px",padding:"3px 9px",borderRadius:"4px",fontFamily:"inherit"}}>
            Clear
          </button>
        </div>
      </div>

      {/* Textarea */}
      <div style={{position:"relative",background:"white"}}>
        <textarea
          value={activeTab.content}
          onChange={e=>onTabUpdate(activeTab.id,"content",e.target.value)}
          placeholder={placeholder}
          style={{width:"100%",minHeight:"200px",background:"white",border:"none",color:"#0F172A",padding:"14px 16px",fontSize:"13px",fontFamily:"inherit",resize:"vertical",outline:"none",lineHeight:"1.8",boxSizing:"border-box"}}/>
        <span style={{position:"absolute",bottom:"8px",right:"10px",color:"#CBD5E1",fontSize:"10px",pointerEvents:"none",fontFamily:"monospace"}}>
          {activeTab.content.length}c
        </span>
      </div>

      {/* Bottom summary bar */}
      <div style={{display:"flex",gap:"8px",padding:"7px 14px",borderTop:"1px solid "+mc+"22",background:"#F0F7FF",flexWrap:"wrap",alignItems:"center"}}>
        {tabs.map(t=>{
          const tc = getTabColor(t);
          return (
            <div key={t.id}
              onClick={()=>onTabChange(t.id)}
              style={{display:"flex",alignItems:"center",gap:"4px",cursor:"pointer",opacity:t.id===activeId?1:0.65}}>
              <div style={{width:"6px",height:"6px",borderRadius:"50%",background:t.content.trim()?tc:"#E2E8F0",boxShadow:t.content.trim()?"0 0 4px "+tc+"77":"none"}}/>
              <span style={{color:t.content.trim()?"#475569":"#CBD5E1",fontSize:"11px",fontWeight:t.id===activeId?"700":"400"}}>{t.label}</span>
              {t.type && <span style={{color:"#94A3B8",fontSize:"10px"}}>({t.type})</span>}
            </div>
          );
        })}
        {filledCount>1 && (
          <span style={{marginLeft:"auto",color:"#1E40AF",fontSize:"11px",fontWeight:"600"}}>All {filledCount} configs analyzed together</span>
        )}
      </div>

      {/* Right-click context menu */}
      {contextMenu && (
        <div
          onClick={e=>e.stopPropagation()}
          style={{position:"fixed",top:contextMenu.y,left:contextMenu.x,background:"white",border:"1px solid #BFDBFE",borderRadius:"8px",boxShadow:"0 8px 24px rgba(0,0,0,0.15)",zIndex:9999,minWidth:"180px",overflow:"hidden"}}>
          <div style={{padding:"4px 0"}}>
            {[
              {label:"Rename",      action:()=>{onTabChange(contextMenu.id);setEditingLabel(contextMenu.id);const t=tabs.find(x=>x.id===contextMenu.id);setLabelDraft(t?.label||"");closeMenus();}},
              {label:"Duplicate",   action:()=>{if(tabs.length<8)onTabDuplicate(contextMenu.id);closeMenus();}, disabled:tabs.length>=8},
              {label:"Change Color",action:()=>setColorPicker(contextMenu.id), hasArrow:true},
              {label:"Clear",       action:()=>{onTabClear(contextMenu.id);closeMenus();}, danger:true},
              {label:"Remove",      action:()=>{if(tabs.length>1){onTabRemove(contextMenu.id);}closeMenus();}, danger:true, disabled:tabs.length===1},
            ].map(item=>(
              <button key={item.label}
                onClick={item.disabled?undefined:item.action}
                style={{display:"flex",justifyContent:"space-between",alignItems:"center",width:"100%",padding:"8px 14px",background:"none",border:"none",textAlign:"left",fontSize:"12px",fontFamily:"inherit",cursor:item.disabled?"not-allowed":"pointer",color:item.danger?"#DC2626":item.disabled?"#CBD5E1":"#1E293B",fontWeight:"500"}}
                onMouseEnter={e=>{if(!item.disabled)e.currentTarget.style.background=item.danger?"#FEF2F2":"#EFF6FF";}}
                onMouseLeave={e=>{e.currentTarget.style.background="none";}}>
                {item.label}
                {item.hasArrow && <span style={{color:"#94A3B8"}}>{">"}</span>}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Color picker submenu */}
      {colorPicker && (
        <div
          onClick={e=>e.stopPropagation()}
          style={{position:"fixed",top:(contextMenu?.y||0)+30,left:(contextMenu?.x||0)+185,background:"white",border:"1px solid #BFDBFE",borderRadius:"8px",boxShadow:"0 8px 24px rgba(0,0,0,0.15)",zIndex:10000,padding:"10px 12px"}}>
          <p style={{color:"#64748B",fontSize:"10px",fontWeight:"600",margin:"0 0 8px",letterSpacing:"1px"}}>TAB COLOR</p>
          <div style={{display:"flex",gap:"8px"}}>
            {TAB_COLORS.map(c=>(
              <button key={c}
                onClick={()=>{onTabUpdate(colorPicker,"color",c);closeMenus();}}
                style={{width:"24px",height:"24px",borderRadius:"50%",background:c,border:tabs.find(t=>t.id===colorPicker)?.color===c?"3px solid #1E293B":"2px solid transparent",cursor:"pointer",transition:"transform 0.1s"}}
                onMouseEnter={e=>e.currentTarget.style.transform="scale(1.2)"}
                onMouseLeave={e=>e.currentTarget.style.transform="scale(1)"}/>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

const LIVE_COMMANDS = {
  AWS:{
    config:     [{label:"IAM Policies",cmd:"aws iam list-policies --scope Local\naws iam get-policy-version --policy-arn <ARN> --version-id v1"},{label:"Security Groups",cmd:"aws ec2 describe-security-groups"},{label:"CloudTrail",cmd:"aws cloudtrail describe-trails"}],
    flowlog:    [{label:"VPC Flow Logs",cmd:"aws ec2 describe-flow-logs\naws logs get-log-events --log-group-name <LOG-GROUP> --log-stream-name <STREAM> --limit 100"}],
    activitylog:[{label:"CloudTrail Events",cmd:"aws cloudtrail lookup-events --start-time $(date -d '24 hours ago' --iso-8601=seconds) --max-results 50"},{label:"Console Logins",cmd:"aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin"}],
  },
  Azure:{
    config:     [{label:"RBAC Assignments",cmd:"az role assignment list --all\naz role definition list --custom-role-only"},{label:"NSG Rules",cmd:"az network nsg list\naz network nsg show --name <NSG> --resource-group <RG>"},{label:"Key Vault",cmd:"az keyvault list\naz keyvault show --name <VAULT>"}],
    flowlog:    [{label:"NSG Flow Logs",cmd:"az network watcher flow-log list --location <REGION>"}],
    activitylog:[{label:"Activity Log",cmd:"az monitor activity-log list --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) --max-events 50"},{label:"Defender Alerts",cmd:"az security alert list --resource-group <RG>"}],
  },
  GCP:{
    config:     [{label:"IAM Policy",cmd:"gcloud projects get-iam-policy <PROJECT-ID> --format=json"},{label:"Firewall Rules",cmd:"gcloud compute firewall-rules list --format=json"}],
    flowlog:    [{label:"VPC Flow Logs",cmd:"gcloud logging read 'logName=\"projects/<PROJECT>/logs/compute.googleapis.com%2Fvpc_flows\"' --limit=100 --format=json"}],
    activitylog:[{label:"Audit Logs",cmd:"gcloud logging read 'logName=\"projects/<PROJECT>/logs/cloudaudit.googleapis.com%2Factivity\"' --freshness=24h --limit=50 --format=json"}],
  },
  IaC:{
    config:     [{label:"Terraform Scan",cmd:"terraform init && terraform plan\ncheckov -f main.tf --framework terraform"},{label:"Docker Image Scan",cmd:"docker scan <IMAGE>:<TAG>\ntrivy image <IMAGE>:<TAG>"},{label:"K8s YAML Scan",cmd:"checkov -f deployment.yaml --framework kubernetes"}],
    flowlog:    [{label:"Pipeline Logs",cmd:"# Retrieve CI/CD pipeline logs from your provider"}],
    activitylog:[{label:"Terraform State",cmd:"terraform show -json terraform.tfstate | jq '.values.root_module.resources'"},{label:"Deployment History",cmd:"kubectl rollout history deployment/<NAME>"}],
  },
};

function LiveConfigPanel({ provider, mode }) {
  const [copied, setCopied] = useState(null);
  const cmds = (LIVE_COMMANDS[provider]||LIVE_COMMANDS["AWS"])[mode]||[];
  const copy = (cmd, i) => { navigator.clipboard.writeText(cmd); setCopied(i); setTimeout(()=>setCopied(null),1500); };
  return (
    <div style={{background:"#060E1A",border:"1px solid #1E3A5F",borderRadius:"8px",padding:"2px"}}>
      <div style={{padding:"7px 11px",borderBottom:"1px solid #1E293B",display:"flex",alignItems:"center",gap:"6px"}}>
        <div style={{width:"6px",height:"6px",borderRadius:"50%",background:"#06B6D4"}}/>
        <span style={{color:"#06B6D4",fontSize:"9px",fontWeight:"600"}}>LIVE CONFIG FETCHER - {provider}</span>
      </div>
      <div style={{padding:"8px",display:"flex",flexDirection:"column",gap:"6px"}}>
        {cmds.map((c,i)=>(
          <div key={i} style={{background:"#0A1628",border:"1px solid #1E293B",borderRadius:"6px",padding:"8px 11px"}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"4px"}}>
              <span style={{color:"#94A3B8",fontSize:"9px",fontWeight:"600"}}>{c.label}</span>
              <button onClick={()=>copy(c.cmd,i)} style={{background:copied===i?"#10B981":"#1E3A5F",color:"white",border:"none",borderRadius:"3px",padding:"2px 7px",fontSize:"9px",cursor:"pointer",fontFamily:"monospace"}}>{copied===i?"Copied":"Copy"}</button>
            </div>
            <code style={{color:"#10B981",fontSize:"9px",fontFamily:"monospace",display:"block",whiteSpace:"pre-wrap",lineHeight:"1.6"}}>{c.cmd}</code>
          </div>
        ))}
        <p style={{color:"#475569",fontSize:"9px",margin:"3px 0 0"}}>Run command, copy JSON output, then paste below and click Analyze</p>
      </div>
    </div>
  );
}

function MitreVisualizer({ findings }) {
  const [sel, setSel] = useState(null);
  const techniques = extractMitreTechniques(findings);
  const tacticMap = {};
  MITRE_TACTICS.forEach(t=>{ tacticMap[t.id]=[]; });
  techniques.forEach(t=>{ if(t.tactic&&tacticMap[t.tactic]) tacticMap[t.tactic].push(t); });
  const activeTactics = MITRE_TACTICS.filter(t=>tacticMap[t.id]?.length>0);

  if (techniques.length===0) return (
    <div style={{background:"#0A1628",border:"1px solid #1E3A5F",borderRadius:"10px",padding:"32px",marginBottom:"18px",textAlign:"center"}}>
      <p style={{color:"#E2E8F0",fontSize:"12px",fontWeight:"600",margin:"0 0 4px"}}>No MITRE ATT&CK techniques detected</p>
      <p style={{color:"#475569",fontSize:"10px",margin:0}}>Techniques are detected from Activity Log and Flow Log analyses.</p>
    </div>
  );

  return (
    <div style={{background:"#0A1628",border:"1px solid #1E3A5F",borderRadius:"10px",padding:"16px",marginBottom:"18px"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"12px"}}>
        <div>
          <p style={{color:"#60AAFF",fontSize:"9px",fontWeight:"700",letterSpacing:"2px",margin:"0 0 3px"}}>MITRE ATT&CK FRAMEWORK</p>
          <p style={{color:"#E2E8F0",fontSize:"12px",fontWeight:"600",margin:0}}>Threat Technique Coverage</p>
        </div>
        <div style={{display:"flex",gap:"8px"}}>
          <div style={{background:"#0F1A2E",border:"1px solid #1E3A5F",borderRadius:"6px",padding:"7px 12px",textAlign:"center"}}>
            <p style={{color:"#FF5C5C",fontSize:"18px",fontWeight:"800",margin:0,fontFamily:"monospace"}}>{techniques.filter(t=>t.findings.some(f=>f.severity==="critical")).length}</p>
            <p style={{color:"#64748B",fontSize:"8px",margin:0}}>CRITICAL</p>
          </div>
          <div style={{background:"#0F1A2E",border:"1px solid #1E3A5F",borderRadius:"6px",padding:"7px 12px",textAlign:"center"}}>
            <p style={{color:"#60AAFF",fontSize:"18px",fontWeight:"800",margin:0,fontFamily:"monospace"}}>{techniques.length}</p>
            <p style={{color:"#64748B",fontSize:"8px",margin:0}}>TECHNIQUES</p>
          </div>
          <div style={{background:"#0F1A2E",border:"1px solid #1E3A5F",borderRadius:"6px",padding:"7px 12px",textAlign:"center"}}>
            <p style={{color:"#FF9A3C",fontSize:"18px",fontWeight:"800",margin:0,fontFamily:"monospace"}}>{activeTactics.length}</p>
            <p style={{color:"#64748B",fontSize:"8px",margin:0}}>TACTICS</p>
          </div>
        </div>
      </div>
      <div style={{overflowX:"auto",marginBottom:"12px"}}>
        <div style={{display:"flex",gap:"3px",minWidth:"700px",paddingBottom:"4px"}}>
          {MITRE_TACTICS.map(tactic=>{
            const techs = tacticMap[tactic.id]||[];
            const active = techs.length>0;
            return (
              <div key={tactic.id} style={{flex:1,minWidth:"70px"}}>
                <div style={{background:active?tactic.color+"22":"#0F1A2E",border:"1px solid "+(active?tactic.color:"#1E293B"),borderRadius:"5px 5px 0 0",padding:"5px 4px",textAlign:"center",position:"relative"}}>
                  <p style={{color:active?tactic.color:"#334155",fontSize:"6px",fontWeight:"700",margin:0,lineHeight:"1.3"}}>{tactic.short}</p>
                </div>
                <div style={{background:"#060E1A",border:"1px solid "+(active?tactic.color+"44":"#1E293B"),borderTop:"none",borderRadius:"0 0 5px 5px",minHeight:"65px",padding:"2px"}}>
                  {techs.map(t=>{
                    const sev = t.findings.sort((a,b)=>["critical","high","medium","low"].indexOf(a.severity)-["critical","high","medium","low"].indexOf(b.severity))[0]?.severity||"info";
                    return (
                      <div key={t.id} onClick={()=>setSel(sel?.id===t.id?null:t)}
                        style={{background:sel?.id===t.id?SEV[sev].bg:"#0F1A2E",border:"1px solid "+SEV[sev].border,borderRadius:"3px",padding:"3px 4px",marginBottom:"2px",cursor:"pointer"}}>
                        <p style={{color:SEV[sev].text,fontSize:"7px",fontWeight:"700",margin:0,fontFamily:"monospace"}}>{t.id}</p>
                        <p style={{color:"#CBD5E1",fontSize:"6px",margin:0,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{t.name}</p>
                      </div>
                    );
                  })}
                  {!active && <div style={{height:"55px",display:"flex",alignItems:"center",justifyContent:"center"}}><span style={{color:"#1E293B",fontSize:"14px"}}>-</span></div>}
                </div>
              </div>
            );
          })}
        </div>
      </div>
      {sel && (
        <div style={{background:"#060E1A",border:"1px solid "+( MITRE_TACTICS.find(t=>t.id===sel.tactic)?.color||"#1E3A5F")+"44",borderRadius:"8px",padding:"12px"}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:"8px"}}>
            <div>
              <div style={{display:"flex",alignItems:"center",gap:"7px",marginBottom:"3px"}}>
                <span style={{color:"#60AAFF",fontSize:"12px",fontWeight:"700",fontFamily:"monospace"}}>{sel.id}</span>
                <span style={{color:"white",fontSize:"12px",fontWeight:"600"}}>{sel.name}</span>
              </div>
              <span style={{background:(MITRE_TACTICS.find(t=>t.id===sel.tactic)?.color||"#3B82F6")+"22",color:(MITRE_TACTICS.find(t=>t.id===sel.tactic)?.color||"#3B82F6"),border:"1px solid "+(MITRE_TACTICS.find(t=>t.id===sel.tactic)?.color||"#3B82F6")+"44",borderRadius:"4px",padding:"2px 7px",fontSize:"9px",fontWeight:"600"}}>
                {MITRE_TACTICS.find(t=>t.id===sel.tactic)?.name||sel.tactic}
              </span>
            </div>
            <button onClick={()=>setSel(null)} style={{background:"transparent",border:"none",color:"#475569",cursor:"pointer",fontSize:"14px"}}>x</button>
          </div>
          <div style={{display:"flex",flexDirection:"column",gap:"5px",marginBottom:"8px"}}>
            {sel.findings.map(f=>(
              <div key={f.id} style={{background:"#0A1628",border:"1px solid "+(SEV[f.severity]?.border||"#1E3A5F")+"44",borderRadius:"5px",padding:"8px 10px"}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"4px"}}>
                  <span style={{color:"#E2E8F0",fontSize:"11px",fontWeight:"600"}}>{f.title}</span>
                  <SevBadge s={f.severity}/>
                </div>
                <p style={{color:"#94A3B8",fontSize:"10px",margin:"0 0 3px"}}>{f.affected_resource}</p>
                <p style={{color:"#CBD5E1",fontSize:"10px",margin:0,lineHeight:"1.5"}}>{f.what_it_means}</p>
              </div>
            ))}
          </div>
          <a href={"https://attack.mitre.org/techniques/"+sel.id.replace(".","/")+"/"} target="_blank" rel="noreferrer"
            style={{color:"#3B82F6",fontSize:"10px",textDecoration:"none"}}>
            View {sel.id} on MITRE ATT&CK
          </a>
        </div>
      )}
    </div>
  );
}

function ScanHistoryPanel({ history, onDelete, onClear, deletingId }) {
  const [expanded, setExpanded] = useState(null);
  if (!history||history.length===0) return (
    <div style={{background:"#0A1628",border:"1px solid #1E3A5F",borderRadius:"10px",padding:"32px",marginBottom:"18px",textAlign:"center"}}>
      <p style={{color:"#E2E8F0",fontSize:"12px",fontWeight:"600",margin:"0 0 4px"}}>No scan history yet</p>
      <p style={{color:"#475569",fontSize:"10px",margin:0}}>Run your first analysis to start tracking security posture over time.</p>
    </div>
  );

  const latest = history[0];
  const previous = history[1]||null;
  const delta = getDelta(latest, previous);
  const fmtDate = iso => new Date(iso).toLocaleDateString("en-GB",{day:"2-digit",month:"short",year:"numeric"})+" "+new Date(iso).toLocaleTimeString("en-GB",{hour:"2-digit",minute:"2-digit"});
  const scoreColor = s => s>=75?"#10B981":s>=50?"#F59E0B":"#EF4444";

  return (
    <div style={{marginBottom:"18px"}}>
      <div style={{background:"#0A1628",border:"1px solid #1E3A5F",borderRadius:"10px",padding:"16px",marginBottom:"10px"}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"12px"}}>
          <p style={{color:"#60AAFF",fontSize:"9px",fontWeight:"700",letterSpacing:"2px",margin:0}}>SECURITY POSTURE TREND - {history.length} SCANS</p>
          <button onClick={onClear} style={{background:"transparent",color:"#475569",border:"1px solid #1E293B",borderRadius:"4px",padding:"3px 8px",fontSize:"9px",cursor:"pointer",fontFamily:"inherit"}}>Clear All</button>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:"8px",marginBottom:"12px"}}>
          {[
            {label:"Risk Score",   val:latest.overall_risk_score, delta:delta?.score,      color:scoreColor(latest.overall_risk_score), invert:false},
            {label:"Compliance",   val:latest.compliance_score+"%",delta:delta?.compliance, color:latest.compliance_score>=70?"#10B981":"#EF4444", invert:false},
            {label:"Findings",     val:latest.total_findings,      delta:delta?.findings,   color:"#E2E8F0", invert:true},
            {label:"Critical",     val:latest.critical,            delta:delta?.critical,   color:latest.critical===0?"#10B981":"#FF5C5C", invert:true},
          ].map(c=>(
            <div key={c.label} style={{background:"#060E1A",border:"1px solid #1E293B",borderRadius:"7px",padding:"10px",textAlign:"center"}}>
              <p style={{color:c.color,fontSize:"20px",fontWeight:"800",margin:"0 0 2px",fontFamily:"monospace"}}>{c.val}</p>
              <p style={{color:"#64748B",fontSize:"8px",margin:"0 0 3px",textTransform:"uppercase"}}>{c.label}</p>
              {delta && c.delta!==0 && c.delta!==null && (
                <span style={{color:(c.invert?c.delta<0:c.delta>0)?"#10B981":"#EF4444",fontSize:"10px",fontWeight:"700"}}>
                  {c.delta>0?"+ ":"- "}{Math.abs(c.delta)}
                </span>
              )}
            </div>
          ))}
        </div>
        {history.length>1 && (
          <div>
            <p style={{color:"#475569",fontSize:"8px",letterSpacing:"1px",margin:"0 0 5px"}}>RISK SCORE TREND (newest to oldest)</p>
            <div style={{display:"flex",gap:"3px",alignItems:"flex-end",height:"44px"}}>
              {[...history].slice(0,8).map((s,i)=>{
                const color = scoreColor(s.overall_risk_score);
                const h = Math.max(6,(s.overall_risk_score/100)*40);
                return (
                  <div key={s.id} style={{flex:1,display:"flex",flexDirection:"column",alignItems:"center",gap:"2px"}}>
                    <span style={{color:"#64748B",fontSize:"7px",fontFamily:"monospace"}}>{s.overall_risk_score}</span>
                    <div style={{width:"100%",height:h+"px",background:color,borderRadius:"2px",opacity:i===0?1:Math.max(0.3,1-i*0.1)}}/>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
      {delta && (
        <div style={{background:delta.score>0?"#0A2010":delta.score<0?"#1A0808":"#0A1628",border:"1px solid "+(delta.score>0?"#10B981":delta.score<0?"#EF4444":"#1E3A5F"),borderRadius:"8px",padding:"10px 14px",marginBottom:"10px",display:"flex",alignItems:"center",gap:"8px"}}>
          <span style={{fontSize:"16px"}}>{delta.score>0?"^":delta.score<0?"v":"-"}</span>
          <div>
            <p style={{color:"#E2E8F0",fontSize:"11px",fontWeight:"600",margin:"0 0 2px"}}>
              {delta.score>0?"Security posture improved by "+delta.score+" points since last scan":delta.score<0?"Security posture declined by "+Math.abs(delta.score)+" points since last scan":"Security posture unchanged since last scan"}
            </p>
            <p style={{color:"#64748B",fontSize:"9px",margin:0}}>
              {delta.findings<0?Math.abs(delta.findings)+" findings resolved":delta.findings>0?delta.findings+" new findings detected":"Same number of findings"}
              {delta.critical<0?" | "+Math.abs(delta.critical)+" critical issues fixed":delta.critical>0?" | "+delta.critical+" new critical issues":""}
            </p>
          </div>
        </div>
      )}
      <div style={{background:"#0A1628",border:"1px solid #1E3A5F",borderRadius:"10px",overflow:"hidden"}}>
        <div style={{padding:"10px 14px",borderBottom:"1px solid #1E293B"}}>
          <p style={{color:"#60AAFF",fontSize:"9px",fontWeight:"700",letterSpacing:"2px",margin:0}}>SCAN HISTORY ({history.length}/{MAX_HISTORY})</p>
        </div>
        {history.map((scan,i)=>{
          const isLatest = i===0;
          const sc = scoreColor(scan.overall_risk_score);
          return (
            <div key={scan.id} style={{borderBottom:"1px solid #1E293B"}}>
              <div onClick={()=>setExpanded(expanded===scan.id?null:scan.id)}
                style={{display:"grid",gridTemplateColumns:"26px 1fr 65px 65px 65px 28px",alignItems:"center",gap:"8px",padding:"10px 14px",cursor:"pointer"}}
                onMouseEnter={e=>e.currentTarget.style.background="#0F1A2E"}
                onMouseLeave={e=>e.currentTarget.style.background=expanded===scan.id?"#0F1A2E":"transparent"}>
                <div style={{textAlign:"center"}}>
                  {isLatest
                    ? <span style={{background:"#10B98122",color:"#10B981",border:"1px solid #10B98144",borderRadius:"8px",padding:"1px 5px",fontSize:"7px",fontWeight:"700"}}>NEW</span>
                    : <span style={{color:"#475569",fontSize:"10px",fontFamily:"monospace"}}>{"#"+(i+1)}</span>
                  }
                </div>
                <div>
                  <p style={{color:"#E2E8F0",fontSize:"10px",fontWeight:"600",margin:0}}>{scan.label}</p>
                  <p style={{color:"#475569",fontSize:"8px",margin:"1px 0 0"}}>{fmtDate(scan.timestamp)}</p>
                </div>
                <div style={{textAlign:"center"}}>
                  <p style={{color:sc,fontSize:"14px",fontWeight:"800",margin:0,fontFamily:"monospace"}}>{scan.overall_risk_score}</p>
                  <p style={{color:"#475569",fontSize:"7px",margin:0}}>SCORE</p>
                </div>
                <div style={{textAlign:"center"}}>
                  <p style={{color:"#E2E8F0",fontSize:"14px",fontWeight:"800",margin:0,fontFamily:"monospace"}}>{scan.total_findings}</p>
                  <p style={{color:"#475569",fontSize:"7px",margin:0}}>FINDINGS</p>
                </div>
                <div style={{textAlign:"center"}}>
                  <p style={{color:scan.critical===0?"#10B981":"#FF5C5C",fontSize:"14px",fontWeight:"800",margin:0,fontFamily:"monospace"}}>{scan.critical}</p>
                  <p style={{color:"#475569",fontSize:"7px",margin:0}}>CRITICAL</p>
                </div>
                <span style={{color:"#475569",fontSize:"12px",transition:"transform 0.2s",transform:expanded===scan.id?"rotate(90deg)":"none"}}>{">"}</span>
              </div>
              {expanded===scan.id && (
                <div style={{background:"#070F1A",padding:"12px 14px",borderTop:"1px solid #1E293B"}}>
                  {scan.domains?.length>0 && (
                    <div style={{marginBottom:"8px"}}>
                      <p style={{color:"#475569",fontSize:"7px",letterSpacing:"1px",margin:"0 0 5px"}}>DOMAIN SCORES</p>
                      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:"4px"}}>
                        {scan.domains.map(d=>{
                          const dc=d.score>=75?"#10B981":d.score>=50?"#F59E0B":"#EF4444";
                          return (
                            <div key={d.name} style={{background:"#0A1628",borderRadius:"4px",padding:"5px 7px"}}>
                              <div style={{display:"flex",justifyContent:"space-between"}}>
                                <span style={{color:"#94A3B8",fontSize:"8px"}}>{d.name}</span>
                                <span style={{color:dc,fontSize:"8px",fontWeight:"700",fontFamily:"monospace"}}>{d.score}%</span>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                  {scan.executive_summary && (
                    <p style={{color:"#94A3B8",fontSize:"10px",lineHeight:"1.6",margin:"0 0 8px",fontStyle:"italic"}}>"{scan.executive_summary}"</p>
                  )}
                  <button onClick={()=>onDelete(scan.id)} disabled={deletingId===scan.id}
                    style={{background:"transparent",color:"#475569",border:"1px solid #1E293B",borderRadius:"3px",padding:"3px 8px",fontSize:"9px",cursor:"pointer",fontFamily:"inherit"}}>
                    {deletingId===scan.id?"Deleting...":"Delete this scan"}
                  </button>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default function App() {
  const [screen,        setScreen]        = useState("input");
  const [apiKey,        setApiKey]        = useState("");
  const [showKey,       setShowKey]       = useState(false);
  const [inputMode,     setInputMode]     = useState("config");
  const [provider,      setProvider]      = useState("AWS");
  const [selectedIaC,   setSelectedIaC]   = useState([]);
  const [framework,     setFramework]     = useState("General Best Practices");
  const [configTabs,    setConfigTabs]    = useState([{id:"1",label:"Config 1",content:"",type:"",iac:"",color:"",provider:"AWS"}]);
  const [activeConfig,  setActiveConfig]  = useState("1");
  const [loading,       setLoading]       = useState(false);
  const [loadingMsg,    setLoadingMsg]    = useState("");
  const [results,       setResults]       = useState(null);
  const [error,         setError]         = useState("");
  const [sevFilter,     setSevFilter]     = useState("all");
  const [search,        setSearch]        = useState("");
  const [demoIdx,       setDemoIdx]       = useState(0);
  const [demoMsg,       setDemoMsg]       = useState("");
  const [providerLockMsg,setProviderLockMsg]= useState("");
  const [copiedSum,     setCopiedSum]     = useState(false);
  const [showLive,      setShowLive]      = useState(false);
  const [pdfLoading,    setPdfLoading]    = useState(false);
  const [activeTab,     setActiveTab]     = useState("findings");
  const [scanHistory,   setScanHistory]   = useState([]);
  const [deletingId,    setDeletingId]    = useState(null);
  const [showJiraSetup, setShowJiraSetup] = useState(false);
  const [jiraConfig,    setJiraConfig]    = useState({host:"",email:"",token:"",project:""});
  const [jiraCreating,  setJiraCreating]  = useState(null);
  const [jiraCreated,   setJiraCreated]   = useState({});
  const [jiraError,     setJiraError]     = useState("");

  useEffect(()=>{
    try {
      const saved = localStorage.getItem("sophos-jira-config");
      if(saved) setJiraConfig(JSON.parse(saved));
    } catch(e){}
  },[]);

  const saveJiraConfig = cfg => {
    setJiraConfig(cfg);
    try { localStorage.setItem("sophos-jira-config", JSON.stringify(cfg)); } catch(e){}
  };

  const createJiraTicket = async (finding) => {
    if(!jiraConfig.host||!jiraConfig.email||!jiraConfig.token||!jiraConfig.project){
      setShowJiraSetup(true); return;
    }
    setJiraCreating(finding.id); setJiraError("");
    const sevMap = {critical:"Highest",high:"High",medium:"Medium",low:"Low",info:"Low"};
    const body = {
      fields: {
        project:     { key: jiraConfig.project.toUpperCase() },
        summary:     "[Cloud Radar] "+finding.severity.toUpperCase()+" - "+finding.title,
        description: {
          type:"doc", version:1,
          content:[
            {type:"heading",attrs:{level:3},content:[{type:"text",text:"Finding Details"}]},
            {type:"paragraph",content:[{type:"text",text:"Control: "+finding.control_id+" | Domain: "+finding.domain+" | Resource: "+finding.affected_resource}]},
            {type:"heading",attrs:{level:3},content:[{type:"text",text:"What This Means"}]},
            {type:"paragraph",content:[{type:"text",text:finding.what_it_means}]},
            {type:"heading",attrs:{level:3},content:[{type:"text",text:"Business Impact"}]},
            {type:"paragraph",content:[{type:"text",text:finding.business_impact}]},
            {type:"heading",attrs:{level:3},content:[{type:"text",text:"Remediation Steps"}]},
            {type:"paragraph",content:[{type:"text",text:finding.remediation_steps}]},
            ...(finding.cli_command&&finding.cli_command!=="N/A"?[
              {type:"heading",attrs:{level:3},content:[{type:"text",text:"CLI Command"}]},
              {type:"codeBlock",content:[{type:"text",text:finding.cli_command}]}
            ]:[]),
            ...(finding.mitre_technique_id?[
              {type:"paragraph",content:[{type:"text",text:"MITRE ATT&CK: "+finding.mitre_technique_id+" - "+finding.mitre_tactic}]}
            ]:[]),
            {type:"paragraph",content:[{type:"text",text:"Source: Sophos Cloud Radar | Framework: "+framework+" | Provider: "+provider}]},
          ]
        },
        issuetype: { name:"Bug" },
        priority:  { name: sevMap[finding.severity]||"Medium" },
        labels:    ["cloud-security","sophos-cloud-radar",finding.severity,provider.toLowerCase()],
      }
    };
    try {
      const res = await fetch("https://"+jiraConfig.host+"/rest/api/3/issue",{
        method:"POST",
        headers:{
          "Content-Type":"application/json",
          "Authorization":"Basic "+btoa(jiraConfig.email+":"+jiraConfig.token),
        },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      if(res.ok && data.key){
        setJiraCreated(prev=>({...prev,[finding.id]:data.key}));
      } else {
        setJiraError("Jira error: "+(data.errorMessages?.[0]||data.errors?.project||JSON.stringify(data)));
      }
    } catch(e){
      setJiraError("Failed to create ticket: "+e.message+". Check your Jira host and credentials.");
    }
    setJiraCreating(null);
  };

  useEffect(()=>{
    loadHistory().then(h=>setScanHistory(h));
  },[]);

  const mc = MODE_COLOR[inputMode];

  const loadDemo = () => {
    const pool = DEMO_CONFIGS.filter(d=>d.mode===inputMode&&d.provider===provider);
    if(pool.length===0){
      setDemoMsg("Demo not available for "+provider+" "+inputMode);
      setTimeout(()=>setDemoMsg(""),3000);
      return;
    }
    const demo = pool[demoIdx%pool.length];
    setConfigTabs(prev=>prev.map(t=>t.id===activeConfig?{...t,content:demo.config,label:demo.label,type:demo.type,iac:"",provider:provider}:t));
    setDemoMsg("Loaded: "+demo.label);
    setTimeout(()=>setDemoMsg(""),2500);
    setDemoIdx(i=>i+1);
  };

  const analyze = async () => {
    // Sanitise API key - strip ALL non-ISO-8859-1 chars, zero-width spaces,
    // smart quotes, invisible unicode that creep in from copy-paste
    const cleanKey = apiKey
      .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g,"") // control chars
      .replace(/[\u007F-\u009F]/g,"")                               // DEL + C1 controls
      .replace(/[\u00A0\u200B\u200C\u200D\u2060\uFEFF]/g,"")    // invisible spaces
      .replace(/[\u2018\u2019\u201C\u201D]/g,"")                  // smart quotes
      .replace(/[^\x20-\x7E]/g,"")                                  // keep only printable ASCII
      .trim();
    if(!cleanKey){setError("Please enter your Anthropic API key.");return;}
    if(!cleanKey.startsWith("sk-")){setError("API key should start with sk-  - check your key is correct.");return;}
    const filledTabs = configTabs.filter(t=>t.content.trim());
    if(filledTabs.length===0){setError("Please paste at least one config to analyze.");return;}
    const combinedConfig = filledTabs.map(t=>"["+( t.type||"config")+"]\n"+(t.content.length>2000?t.content.slice(0,2000):t.content)).join("\n---\n");
    setLoading(true); setError("");
    const msgs = LOAD_MSGS[inputMode]; let idx=0;
    setLoadingMsg(msgs[0]);
    const tick = setInterval(()=>{ idx=(idx+1)%msgs.length; setLoadingMsg(msgs[idx]); },2200);
    try {
      const res = await fetch("https://api.anthropic.com/v1/messages",{
        method:"POST",
        headers:{
          "Content-Type":"application/json",
          "x-api-key":cleanKey,
          "anthropic-version":"2023-06-01",
          "anthropic-dangerous-direct-browser-access":"true"
        },
        body:JSON.stringify({
          model:"claude-haiku-4-5-20251001",
          max_tokens:1000,
          system:buildPrompt(inputMode,provider),
          messages:[{role:"user",content:"Return ONLY this JSON (filled with real values):\n"+RESPONSE_SCHEMA+"\nRules: max 5 findings, fields under 100 chars, map to "+framework+".\n\n"+combinedConfig}]
        })
      });
      clearInterval(tick);
      const data = await res.json();
      if(!res.ok){setError("API Error: "+(data?.error?.message||"HTTP "+res.status));setLoading(false);return;}
      const text = data.content?.map(i=>i.text||"").join("")||"";
      const clean = text.replace(/```json|```/g,"").trim();
      let parsed;
      try { parsed=JSON.parse(clean); }
      catch { try{parsed=JSON.parse(repairJSON(clean));}catch{throw new Error("Response too large. Try a shorter config.");} }
      setResults(parsed);
      setActiveTab("findings");
      setScreen("results");
      const record = buildScanRecord(parsed,provider,framework,inputMode);
      const updated = [record,...scanHistory].slice(0,MAX_HISTORY);
      setScanHistory(updated);
      saveHistory(updated);
    } catch(e) {
      clearInterval(tick);
      setError("Analysis failed: "+e.message);
    }
    setLoading(false);
  };

  const exportPDF = () => {
    setPdfLoading(true);
    // Small timeout so React re-renders the loading state before the heavy work
    setTimeout(()=>{
      try {
        generatePDF(results,framework,provider);
      } catch(e) {
        setError("PDF export failed: "+e.message);
      }
      setPdfLoading(false);
    }, 50);
  };

  const deleteScan = async id => {
    setDeletingId(id);
    const updated = scanHistory.filter(s=>s.id!==id);
    setScanHistory(updated);
    await saveHistory(updated);
    setDeletingId(null);
  };

  const clearHistory = async () => { setScanHistory([]); await saveHistory([]); };

  const filtered = (results?.findings||[]).filter(f=>
    (sevFilter==="all"||f.severity===sevFilter)&&
    (!search||[f.title,f.control_id,f.affected_resource].some(s=>s?.toLowerCase().includes(search.toLowerCase())))
  );
  const counts = (results?.findings||[]).reduce((a,f)=>({...a,[f.severity]:(a[f.severity]||0)+1}),{});
  const mitreCount = extractMitreTechniques(results?.findings||[]).length;

  const activeTabObj = configTabs.find(t=>t.id===activeConfig)||configTabs[0];

  return (
    <div style={{minHeight:"100vh",background:"#F0F4FF",fontFamily:"Aptos,Nunito,'Segoe UI',Arial,sans-serif",color:"#1E293B"}}>

      {/* Header */}
      <div style={{background:"linear-gradient(135deg,#0D1B3E,#091628)",borderBottom:"1px solid #1E293B",padding:"0 22px",display:"flex",alignItems:"center",justifyContent:"space-between",height:"56px"}}>
        <div style={{display:"flex",alignItems:"center",gap:"10px"}}>
          {/* Radar logo */}
          <div style={{width:"32px",height:"32px",borderRadius:"50%",background:"#0A1628",border:"2px solid #005CB9",display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0}}>
            <svg width="20" height="20" viewBox="0 0 28 28">
              <circle cx="14" cy="14" r="10" fill="none" stroke="#005CB9" strokeWidth="0.8" opacity="0.3"/>
              <circle cx="14" cy="14" r="6"  fill="none" stroke="#005CB9" strokeWidth="0.8" opacity="0.4"/>
              <line x1="14" y1="14" x2="14" y2="4" stroke="#0085CA" strokeWidth="1.5" strokeLinecap="round">
                <animateTransform attributeName="transform" type="rotate" from="0 14 14" to="360 14 14" dur="3s" repeatCount="indefinite"/>
              </line>
              <circle cx="14" cy="4" r="2" fill="#10B981">
                <animateTransform attributeName="transform" type="rotate" from="0 14 14" to="360 14 14" dur="3s" repeatCount="indefinite"/>
              </circle>
              <circle cx="14" cy="14" r="2" fill="white"/>
            </svg>
          </div>
          <div>
            <div style={{fontWeight:"900",fontSize:"13px",letterSpacing:"2px",color:"white",lineHeight:1}}>SOPHOS</div>
            <div style={{fontSize:"7px",letterSpacing:"2px",color:"#0085CA",fontWeight:"600",lineHeight:1.2}}>CLOUD RADAR</div>
            <div style={{fontSize:"6px",letterSpacing:"1px",color:"#475569",lineHeight:1}}>AI SECURITY CLOUD ANALYZER</div>
          </div>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:"8px"}}>
          <div style={{display:"flex",alignItems:"center",gap:"5px",background:"#0A1628",border:"1px solid #1E3A5F",borderRadius:"6px",padding:"4px 8px"}}>
            <span style={{fontSize:"8px",color:"#475569",whiteSpace:"nowrap"}}>API KEY</span>
            <input type={showKey?"text":"password"} value={apiKey} onChange={e=>setApiKey(e.target.value.replace(/[^\x20-\x7E]/g,"").trim())} placeholder="sk-ant-..."
              style={{background:"transparent",border:"none",outline:"none",color:apiKey?"#10B981":"#64748B",fontSize:"9px",fontFamily:"monospace",width:"135px"}}/>
            <button onClick={()=>setShowKey(!showKey)} style={{background:"transparent",border:"none",cursor:"pointer",color:"#475569",fontSize:"8px",padding:0}}>{showKey?"hide":"show"}</button>
          </div>
          <div style={{display:"flex",alignItems:"center",gap:"4px"}}>
            <div style={{width:"5px",height:"5px",borderRadius:"50%",background:apiKey?"#10B981":"#475569",boxShadow:apiKey?"0 0 6px #10B981":"none"}}/>
            <span style={{color:"#64748B",fontSize:"8px"}}>{apiKey?"Claude AI Ready":"Enter API Key"}</span>
          </div>
        </div>
      </div>

      <div style={{maxWidth:"1080px",margin:"0 auto",padding:"18px 14px"}}>

        {/* INPUT SCREEN */}
        {screen==="input" && (
          <div>
            <div style={{textAlign:"center",marginBottom:"20px"}}>
              <h1 style={{fontSize:"20px",fontWeight:"800",color:"#0F172A",margin:"0 0 4px",letterSpacing:"-0.5px"}}>Sophos Cloud Radar</h1>
              <p style={{color:"#475569",fontSize:"13px",margin:0}}>Analyze cloud configs, flow logs and activity logs across AWS, Azure, GCP and IaC with MITRE ATT&CK mapping</p>
            </div>

            <div style={{background:"#FFFFFF",border:"1px solid #BFDBFE",borderRadius:"12px",padding:"20px",boxShadow:"0 4px 24px rgba(59,130,246,0.08)"}}>

              {/* Step 1 */}
              <div style={{marginBottom:"14px"}}>
                <p style={{color:"#1E40AF",fontSize:"12px",fontWeight:"700",letterSpacing:"1px",marginBottom:"8px"}}>STEP 1 - WHAT DO YOU WANT TO ANALYZE?</p>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:"6px"}}>
                  {INPUT_MODES.map(m=>(
                    <button key={m.id} onClick={()=>{setInputMode(m.id);setShowLive(false);setConfigTabs(prev=>prev.map(t=>({...t,type:""})));}}
                      style={{padding:"9px 10px",borderRadius:"7px",cursor:"pointer",fontFamily:"inherit",textAlign:"left",
                        background:inputMode===m.id?"#0F2040":"#060E1A",
                        border:inputMode===m.id?"1.5px solid "+MODE_COLOR[m.id]:"1px solid #1E293B"}}>
                      <p style={{margin:"0 0 2px",fontSize:"13px",fontWeight:"700",color:inputMode===m.id?MODE_COLOR[m.id]:"#334155"}}>{m.label}</p>
                      <p style={{margin:0,fontSize:"11px",color:"#64748B"}}>{m.desc}</p>
                    </button>
                  ))}
                </div>
              </div>

              {/* Step 2 - Environment */}
              <div style={{marginBottom:"14px"}}>
                <p style={{color:"#1E40AF",fontSize:"12px",fontWeight:"700",letterSpacing:"1px",marginBottom:"8px"}}>STEP 2 - ENVIRONMENT</p>
                <div style={{display:"flex",alignItems:"center",gap:"5px",flexWrap:"wrap",marginBottom:"6px"}}>
                  {PROVIDERS.map(p=>{
                    const pc = PROVIDER_COLORS[p]||"#60AAFF";
                    const isActive = provider===p;
                    return (
                      <button key={p}
                        onClick={()=>{if(configTabs.some(t=>t.content.trim())&&p!==provider){setProviderLockMsg("Clear all tabs before switching environment");setTimeout(()=>setProviderLockMsg(""),3000);return;}setProvider(p);setShowLive(false);setSelectedIaC([]);setConfigTabs(prev=>prev.map(t=>({...t,type:"",iac:"",provider:p})));}}
                        style={{padding:"8px 20px",borderRadius:"8px",fontSize:"13px",fontWeight:"700",fontFamily:"inherit",
                          background:isActive?pc:"#F8FAFF",
                          color:isActive?"white":configTabs.some(t=>t.content.trim())&&!isActive?"#CBD5E1":"#334155",
                          border:isActive?"2px solid "+pc:"2px solid #BFDBFE",
                          cursor:configTabs.some(t=>t.content.trim())&&!isActive?"not-allowed":"pointer",
                          opacity:configTabs.some(t=>t.content.trim())&&!isActive?0.45:1}}>
                        {PROVIDER_LABELS[p]}
                      </button>
                    );
                  })}

                </div>
                {/* Environment lock indicator */}
                {configTabs.some(t=>t.content.trim()) && (
                  <div style={{display:"flex",alignItems:"center",gap:"8px",marginTop:"6px"}}>
                    <div style={{display:"flex",alignItems:"center",gap:"6px",background:"#EFF6FF",border:"1px solid #BFDBFE",borderRadius:"6px",padding:"5px 10px"}}>
                      <div style={{width:"6px",height:"6px",borderRadius:"50%",background:PROVIDER_COLORS[provider]||"#3B82F6",boxShadow:"0 0 6px "+(PROVIDER_COLORS[provider]||"#3B82F6")}}/>
                      <span style={{color:"#1E40AF",fontSize:"11px",fontWeight:"700"}}>Environment locked: {provider}</span>
                      <span style={{color:"#64748B",fontSize:"10px"}}>- Clear all tabs to switch</span>
                    </div>
                    {providerLockMsg && (
                      <span style={{background:"#FEF2F2",border:"1px solid #FECACA",color:"#DC2626",borderRadius:"5px",padding:"4px 10px",fontSize:"11px",fontWeight:"600"}}>
                        {providerLockMsg}
                      </span>
                    )}
                  </div>
                )}
              </div>

              {/* Step 3 - Config Type (only for config mode) */}
              {inputMode==="config" && (
                <div style={{marginBottom:"14px"}}>
                  <p style={{color:"#1E40AF",fontSize:"12px",fontWeight:"700",letterSpacing:"1px",marginBottom:"8px"}}>
                    STEP 3 - CONFIG TYPE
                    <span style={{color:provider==="IaC"?"#A855F7":"#475569",fontWeight:"600",marginLeft:"6px"}}>({provider==="IaC"?"Infrastructure as Code":provider})</span>
                  </p>
                  <div style={{display:"flex",gap:"4px",flexWrap:"wrap"}}>
                    {(CONFIG_TYPES["config"][provider]||[]).map(t=>{
                      const isSelected = activeTabObj.type===t;
                      return (
                        <button key={t}
                          onClick={()=>setConfigTabs(prev=>prev.map(tab=>tab.id===activeConfig?{...tab,type:tab.type===t?"":t}:tab))}
                          style={{padding:"6px 12px",borderRadius:"6px",fontSize:"12px",fontWeight:"600",cursor:"pointer",fontFamily:"inherit",
                            background:isSelected?"#ECFDF5":"#F8FAFF",
                            color:isSelected?"#059669":"#334155",
                            border:isSelected?"2px solid #10B981":"1.5px solid #BFDBFE"}}>
                          {t}
                        </button>
                      );
                    })}
                  </div>
                  {activeTabObj.type && (
                    <p style={{color:"#475569",fontSize:"7px",margin:"4px 0 0"}}>
                      Active tab: <span style={{color:"#10B981"}}>{activeTabObj.type}</span>
                    </p>
                  )}
                </div>
              )}

              {/* Step 4 - Framework */}
              <div style={{marginBottom:"14px"}}>
                <p style={{color:"#1E40AF",fontSize:"12px",fontWeight:"700",letterSpacing:"1px",marginBottom:"8px"}}>STEP 3 - COMPLIANCE FRAMEWORK</p>
                <select value={framework} onChange={e=>setFramework(e.target.value)}
                  style={{background:"#F8FAFF",color:"#1E293B",border:"2px solid #BFDBFE",borderRadius:"7px",padding:"9px 13px",fontSize:"13px",fontFamily:"inherit",cursor:"pointer",minWidth:"240px"}}>
                  {FRAMEWORKS.map(f=><option key={f} value={f}>{f}</option>)}
                </select>
              </div>

              {/* Step 5 - Editor */}
              <div style={{marginBottom:"12px"}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"7px"}}>
                  <p style={{color:"#1E40AF",fontSize:"12px",fontWeight:"700",letterSpacing:"1px",marginBottom:"8px"}}>STEP 4 - {showLive?"FETCH LIVE CONFIG":"PASTE YOUR DATA"}</p>
                  <div style={{display:"flex",gap:"3px"}}>
                    <button onClick={()=>setShowLive(false)} style={{padding:"7px 16px",borderRadius:"6px",fontSize:"12px",cursor:"pointer",fontFamily:"inherit",fontWeight:"700",background:!showLive?"#DBEAFE":"#F8FAFF",color:!showLive?"#1E40AF":"#64748B",border:!showLive?"2px solid #3B82F6":"2px solid #BFDBFE"}}>Paste</button>
                    <button onClick={()=>setShowLive(true)} style={{padding:"7px 16px",borderRadius:"6px",fontSize:"12px",cursor:"pointer",fontFamily:"inherit",fontWeight:"700",background:showLive?"#EFF6FF":"#F8FAFF",color:showLive?"#0085CA":"#64748B",border:showLive?"2px solid #0085CA":"2px solid #BFDBFE"}}>Fetch Live</button>
                  </div>
                </div>
                {showLive
                  ? <LiveConfigPanel provider={provider} mode={inputMode}/>
                  : <MultiConfigEditor tabs={configTabs} activeId={activeConfig} mc={mc} inputMode={inputMode} provider={provider}
                      onTabChange={id=>setActiveConfig(id)}
                      onTabUpdate={(id,field,val)=>setConfigTabs(prev=>prev.map(t=>t.id===id?{...t,[field]:val}:t))}
                      onTabAdd={()=>{const newId=Date.now().toString();const newNum=configTabs.length+1;setConfigTabs(prev=>[...prev,{id:newId,label:"Config "+newNum,content:"",type:"",iac:"",color:"",provider:provider}]);setActiveConfig(newId);}}
                      onTabRemove={id=>{if(configTabs.length===1)return;const remaining=configTabs.filter(t=>t.id!==id);setConfigTabs(remaining);if(activeConfig===id)setActiveConfig(remaining[remaining.length-1].id);}}
                      onTabClear={id=>setConfigTabs(prev=>prev.map(t=>t.id===id?{...t,content:""}:t))}
                      onTabDuplicate={id=>{const src=configTabs.find(t=>t.id===id);if(!src||configTabs.length>=8)return;const newId=Date.now().toString();const copy={...src,id:newId,label:src.label+" (copy)",provider:provider};setConfigTabs(prev=>{const idx=prev.findIndex(t=>t.id===id);const next=[...prev];next.splice(idx+1,0,copy);return next;});setActiveConfig(newId);}}
                      onTabReorder={(dragId,targetId)=>{setConfigTabs(prev=>{const from=prev.findIndex(t=>t.id===dragId);const to=prev.findIndex(t=>t.id===targetId);if(from<0||to<0)return prev;const next=[...prev];const[moved]=next.splice(from,1);next.splice(to,0,moved);return next;});}}/>
                }
              </div>

              {!apiKey && <div style={{background:"#EFF6FF",border:"1px solid #BFDBFE",borderRadius:"7px",padding:"10px 13px",marginBottom:"12px"}}><p style={{color:"#1D4ED8",fontSize:"12px",margin:0}}>Enter your Anthropic API key above. <a href="https://console.anthropic.com/keys" target="_blank" rel="noreferrer" style={{color:"#3B82F6"}}>Get a free key</a></p></div>}
              {error && <div style={{background:"#FEF2F2",border:"1px solid #FECACA",borderRadius:"7px",padding:"10px 13px",marginBottom:"12px"}}><p style={{color:"#DC2626",fontSize:"12px",margin:0}}>Error: {error}</p></div>}

              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                <div style={{display:"flex",gap:"7px"}}>
                  <div style={{display:"flex",alignItems:"center",gap:"8px"}}>
                    <button onClick={loadDemo} style={{background:"#EFF6FF",color:"#1D4ED8",border:"2px solid #BFDBFE",borderRadius:"7px",padding:"10px 18px",fontSize:"13px",cursor:"pointer",fontFamily:"inherit",fontWeight:"700"}}>Load Demo</button>
                    {demoMsg&&(
                      <span style={{fontSize:"11px",fontWeight:"600",color:demoMsg.startsWith("Demo not")?"#DC2626":"#059669",background:demoMsg.startsWith("Demo not")?"#FEF2F2":"#ECFDF5",border:"1px solid "+(demoMsg.startsWith("Demo not")?"#FECACA":"#A7F3D0"),borderRadius:"5px",padding:"4px 10px",transition:"opacity 0.3s"}}>
                        {demoMsg}
                      </span>
                    )}
                  </div>
                  {configTabs.some(t=>t.content) && <button onClick={()=>setConfigTabs([{id:"1",label:"Config 1",content:"",type:"",iac:""}])} style={{background:"#F8FAFF",color:"#64748B",border:"1.5px solid #BFDBFE",borderRadius:"7px",padding:"10px 18px",fontSize:"13px",cursor:"pointer",fontFamily:"inherit"}}>Clear All</button>}
                </div>
                <button onClick={analyze} disabled={loading}
                  style={{background:loading?"#1E3A5F":"linear-gradient(135deg,"+mc+","+mc+"bb)",color:"white",border:"none",borderRadius:"7px",padding:"12px 28px",fontSize:"14px",fontWeight:"700",cursor:loading?"not-allowed":"pointer",fontFamily:"inherit",letterSpacing:"1px",display:"flex",alignItems:"center",gap:"6px",minWidth:"180px"}}>
                  {loading
                    ? <><span style={{display:"inline-block",animation:"spin 1s linear infinite"}}>o</span><span style={{fontSize:"9px"}}>{loadingMsg}</span></>
                    : inputMode==="config"?"ANALYZE CONFIG":inputMode==="flowlog"?"ANALYZE FLOW LOGS":"ANALYZE ACTIVITY LOGS"
                  }
                </button>
              </div>
            </div>
          </div>
        )}

        {/* RESULTS SCREEN */}
        {screen==="results" && results && (
          <div>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"18px"}}>
              <div style={{display:"flex",alignItems:"center",gap:"8px"}}>
                <button onClick={()=>setScreen("input")} style={{background:"transparent",color:"#60AAFF",border:"1px solid #1E3A5F",borderRadius:"5px",padding:"5px 11px",fontSize:"10px",cursor:"pointer",fontFamily:"inherit"}}>Back</button>
                <span style={{background:mc+"22",color:mc,border:"1px solid "+mc+"44",borderRadius:"4px",padding:"2px 8px",fontSize:"8px",fontWeight:"700",letterSpacing:"1px"}}>{results.analysis_type||"Analysis"}</span>
              </div>
              <div style={{display:"flex",gap:"7px"}}>
                <button onClick={()=>setShowJiraSetup(true)}
                  style={{background:"#0052CC",color:"white",border:"none",borderRadius:"5px",padding:"5px 13px",fontSize:"10px",cursor:"pointer",fontFamily:"inherit",fontWeight:"600",display:"flex",alignItems:"center",gap:"5px"}}>
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="white"><path d="M11.571 11.513H0a5.218 5.218 0 0 0 5.232 5.215h2.13v2.057A5.215 5.215 0 0 0 12.575 24V12.518a1.005 1.005 0 0 0-1.004-1.005zm5.723-5.756H5.736a5.215 5.215 0 0 0 5.215 5.214h2.129v2.058a5.218 5.218 0 0 0 5.215 5.214V6.762a1.005 1.005 0 0 0-1.001-1.005zM23.013 0H11.455a5.215 5.215 0 0 0 5.215 5.215h2.129v2.057A5.215 5.215 0 0 0 24 12.485V1.005A1.005 1.005 0 0 0 23.013 0z"/></svg>
                  Jira {jiraConfig.host?"Connected":"Setup"}
                </button>
                <button onClick={exportPDF} disabled={pdfLoading}
                  style={{background:pdfLoading?"#1E3A5F":"linear-gradient(135deg,#10B981,#059669)",color:"white",border:"none",borderRadius:"5px",padding:"5px 13px",fontSize:"10px",cursor:pdfLoading?"not-allowed":"pointer",fontFamily:"inherit",fontWeight:"600"}}>
                  {pdfLoading?"Generating...":"Export PDF"}
                </button>
                <button onClick={async()=>{
                    const criticals=(results?.findings||[]).filter(f=>f.severity==="critical"&&!jiraCreated[f.id]);
                    if(criticals.length===0){alert("No new critical findings to create tickets for.");return;}
                    if(!jiraConfig.host){setShowJiraSetup(true);return;}
                    for(const f of criticals){ await createJiraTicket(f); }
                  }}
                  style={{background:"#7C3AED",color:"white",border:"none",borderRadius:"5px",padding:"5px 13px",fontSize:"10px",cursor:"pointer",fontFamily:"inherit",fontWeight:"600",display:"flex",alignItems:"center",gap:"4px"}}>
                  All Critical
                </button>
                <button onClick={()=>{setScreen("input");setResults(null);}}
                  style={{background:"#3B82F6",color:"white",border:"none",borderRadius:"5px",padding:"5px 12px",fontSize:"10px",cursor:"pointer",fontFamily:"inherit",fontWeight:"600"}}>New Scan</button>
              </div>
            </div>

            {/* Score cards */}
            <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:"10px",marginBottom:"16px"}}>
              <div style={{background:"#0A1628",border:"1px solid #1E3A5F",borderRadius:"9px",padding:"14px",textAlign:"center"}}>
                <ScoreGauge score={results.overall_risk_score}/>
                <p style={{color:"#64748B",fontSize:"8px",margin:"4px 0 0",letterSpacing:"1px"}}>RISK SCORE</p>
              </div>
              <div style={{background:"#0A1628",border:"1px solid #1E3A5F",borderRadius:"9px",padding:"14px"}}>
                <p style={{color:"#64748B",fontSize:"8px",letterSpacing:"1px",margin:"0 0 6px"}}>ISSUES FOUND</p>
                <p style={{color:"white",fontSize:"28px",fontWeight:"800",margin:"0 0 6px",fontFamily:"monospace"}}>{results.findings?.length||0}</p>
                <div style={{display:"flex",flexDirection:"column",gap:"2px"}}>
                  {["critical","high","medium","low"].map(s=>counts[s]?(
                    <div key={s} style={{display:"flex",justifyContent:"space-between"}}>
                      <span style={{color:SEV[s].text,fontSize:"8px",textTransform:"uppercase"}}>{s}</span>
                      <span style={{color:"white",fontSize:"8px",fontFamily:"monospace"}}>{counts[s]}</span>
                    </div>
                  ):null)}
                </div>
              </div>
              <div style={{background:"#0A1628",border:"1px solid #1E3A5F",borderRadius:"9px",padding:"14px"}}>
                <p style={{color:"#64748B",fontSize:"8px",letterSpacing:"1px",margin:"0 0 6px"}}>COMPLIANCE</p>
                <p style={{color:results.compliance_score>=70?"#10B981":"#EF4444",fontSize:"28px",fontWeight:"800",margin:"0 0 3px",fontFamily:"monospace"}}>{results.compliance_score}%</p>
                <p style={{color:"#475569",fontSize:"8px",margin:0}}>{framework}</p>
              </div>
              <div style={{background:"#0A1628",border:"1px solid #1E3A5F",borderRadius:"9px",padding:"14px"}}>
                <p style={{color:"#64748B",fontSize:"8px",letterSpacing:"1px",margin:"0 0 6px"}}>MITRE TECHNIQUES</p>
                <p style={{color:"#A855F7",fontSize:"28px",fontWeight:"800",margin:"0 0 3px",fontFamily:"monospace"}}>{mitreCount}</p>
                <p style={{color:"#475569",fontSize:"8px",margin:0}}>{results.estimated_fix_hours}h fix | {results.quick_wins_count} quick wins</p>
              </div>
            </div>

            {/* Domain bars */}
            <div style={{marginBottom:"16px"}}>
              <p style={{color:"#60AAFF",fontSize:"8px",fontWeight:"700",letterSpacing:"2px",marginBottom:"8px"}}>DOMAIN RISK BREAKDOWN</p>
              <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:"8px"}}>
                {results.domains?.map(d=><DomainBar key={d.name} d={d}/>)}
              </div>
            </div>

            {/* Tab switcher */}
            <div style={{display:"flex",gap:"5px",marginBottom:"12px"}}>
              <button onClick={()=>setActiveTab("findings")} style={{padding:"6px 14px",borderRadius:"6px",fontSize:"10px",fontWeight:"600",cursor:"pointer",fontFamily:"inherit",background:activeTab==="findings"?"#1E3A5F":"transparent",color:activeTab==="findings"?"#60AAFF":"#475569",border:activeTab==="findings"?"1px solid #3B82F6":"1px solid #1E293B"}}>
                Findings ({results.findings?.length||0})
              </button>
              <button onClick={()=>setActiveTab("mitre")} style={{padding:"6px 14px",borderRadius:"6px",fontSize:"10px",fontWeight:"600",cursor:"pointer",fontFamily:"inherit",background:activeTab==="mitre"?"#1E1030":"transparent",color:activeTab==="mitre"?"#A855F7":"#475569",border:activeTab==="mitre"?"1px solid #A855F7":"1px solid #1E293B",display:"flex",alignItems:"center",gap:"4px"}}>
                MITRE ATT&CK {mitreCount>0&&<span style={{background:"#A855F722",color:"#A855F7",border:"1px solid #A855F744",borderRadius:"8px",padding:"0 6px",fontSize:"9px"}}>{mitreCount}</span>}
              </button>
              <button onClick={()=>setActiveTab("history")} style={{padding:"6px 14px",borderRadius:"6px",fontSize:"10px",fontWeight:"600",cursor:"pointer",fontFamily:"inherit",background:activeTab==="history"?"#0F2A1A":"transparent",color:activeTab==="history"?"#10B981":"#475569",border:activeTab==="history"?"1px solid #10B981":"1px solid #1E293B",display:"flex",alignItems:"center",gap:"4px"}}>
                Scan History {scanHistory.length>0&&<span style={{background:"#10B98122",color:"#10B981",border:"1px solid #10B98144",borderRadius:"8px",padding:"0 6px",fontSize:"9px"}}>{scanHistory.length}</span>}
              </button>
            </div>

            {/* Findings tab */}
            {activeTab==="findings" && (
              <div style={{background:"#0A1628",border:"1px solid #1E3A5F",borderRadius:"9px",marginBottom:"16px",overflow:"hidden"}}>
                <div style={{padding:"10px 14px",borderBottom:"1px solid #1E293B",display:"flex",gap:"8px",alignItems:"center",flexWrap:"wrap"}}>
                  <p style={{color:"#60AAFF",fontSize:"8px",fontWeight:"700",letterSpacing:"2px",margin:0}}>FINDINGS</p>
                  <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search findings..."
                    style={{background:"#060E1A",border:"1px solid #1E293B",color:"#E2E8F0",borderRadius:"4px",padding:"4px 8px",fontSize:"9px",fontFamily:"inherit",flex:1,minWidth:"120px",outline:"none"}}/>
                  <div style={{display:"flex",gap:"4px"}}>
                    {["all","critical","high","medium","low"].map(s=>(
                      <button key={s} onClick={()=>setSevFilter(s)}
                        style={{padding:"3px 7px",borderRadius:"4px",fontSize:"8px",fontWeight:"600",cursor:"pointer",fontFamily:"inherit",textTransform:"uppercase",
                          background:sevFilter===s?(SEV[s]?.bg||"#1E3A5F"):"transparent",
                          color:sevFilter===s?(SEV[s]?.text||"#60AAFF"):"#475569",
                          border:sevFilter===s?"1px solid "+(SEV[s]?.border||"#3B82F6"):"1px solid #1E293B"}}>
                        {s}
                      </button>
                    ))}
                  </div>
                </div>
                <div style={{overflowX:"auto"}}>
                  <div style={{minWidth:"560px"}}>
                    <div style={{display:"grid",gridTemplateColumns:"90px 95px 1fr 145px 20px",gap:"10px",padding:"7px 14px",borderBottom:"1px solid #1E293B",background:"#060E1A"}}>
                      {["SEVERITY","CONTROL","FINDING","DOMAIN",""].map(h=><span key={h} style={{color:"#475569",fontSize:"7px",fontWeight:"700",letterSpacing:"1px"}}>{h}</span>)}
                    </div>
                    {filtered.length===0
                      ? <div style={{padding:"28px",textAlign:"center",color:"#475569"}}>No findings match filter</div>
                      : filtered.map(f=><FindingRow key={f.id} f={f} onCreateJira={createJiraTicket} jiraKey={jiraCreated[f.id]} jiraCreating={jiraCreating}/>)
                    }
                  </div>
                </div>
              </div>
            )}

            {jiraError && (
              <div style={{background:"#3D1515",border:"1px solid #FF5C5C",borderRadius:"6px",padding:"8px 12px",marginBottom:"10px",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                <p style={{color:"#FF5C5C",fontSize:"11px",margin:0}}>{jiraError}</p>
                <button onClick={()=>setJiraError("")} style={{background:"transparent",border:"none",color:"#FF5C5C",cursor:"pointer",fontSize:"14px"}}>x</button>
              </div>
            )}
            {activeTab==="mitre" && <MitreVisualizer findings={results.findings||[]}/>}
            {activeTab==="history" && <ScanHistoryPanel history={scanHistory} onDelete={deleteScan} onClear={clearHistory} deletingId={deletingId}/>}

            {/* Executive Summary */}
            <div style={{background:"#0A1628",border:"1px solid #1E3A5F",borderRadius:"9px",padding:"16px"}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"10px"}}>
                <p style={{color:"#60AAFF",fontSize:"8px",fontWeight:"700",letterSpacing:"2px",margin:0}}>EXECUTIVE SUMMARY</p>
                <button onClick={()=>{navigator.clipboard.writeText(results.executive_summary);setCopiedSum(true);setTimeout(()=>setCopiedSum(false),1500);}}
                  style={{background:copiedSum?"#10B981":"#1E3A5F",color:"white",border:"none",borderRadius:"4px",padding:"4px 10px",fontSize:"9px",cursor:"pointer",fontFamily:"inherit"}}>
                  {copiedSum?"Copied":"Copy"}
                </button>
              </div>
              {results.top_critical_finding && (
                <div style={{background:"#3D1515",border:"1px solid #FF5C5C",borderRadius:"5px",padding:"8px 12px",marginBottom:"10px"}}>
                  <p style={{color:"#FF5C5C",fontSize:"9px",fontWeight:"700",margin:"0 0 2px",letterSpacing:"1px"}}>TOP CRITICAL FINDING</p>
                  <p style={{color:"#FFB3B3",fontSize:"10px",margin:0}}>{results.top_critical_finding}</p>
                </div>
              )}
              <p style={{color:"#CBD5E1",fontSize:"11px",lineHeight:"1.8",margin:"0 0 8px"}}>{results.executive_summary}</p>
              <p style={{color:"#334155",fontSize:"8px",margin:0}}>Sophos Cloud Radar - Powered by Claude AI - {new Date().toLocaleDateString()}</p>
            </div>
          </div>
        )}
      </div>

        {/* Jira Setup Modal */}
        {showJiraSetup && (
          <div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.7)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:1000}}>
            <div style={{background:"#0A1628",border:"1px solid #1E4A8F",borderRadius:"12px",padding:"24px",width:"480px",maxWidth:"90vw"}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"20px"}}>
                <div style={{display:"flex",alignItems:"center",gap:"10px"}}>
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="#4C9AFF"><path d="M11.571 11.513H0a5.218 5.218 0 0 0 5.232 5.215h2.13v2.057A5.215 5.215 0 0 0 12.575 24V12.518a1.005 1.005 0 0 0-1.004-1.005zm5.723-5.756H5.736a5.215 5.215 0 0 0 5.215 5.214h2.129v2.058a5.218 5.218 0 0 0 5.215 5.214V6.762a1.005 1.005 0 0 0-1.001-1.005zM23.013 0H11.455a5.215 5.215 0 0 0 5.215 5.215h2.129v2.057A5.215 5.215 0 0 0 24 12.485V1.005A1.005 1.005 0 0 0 23.013 0z"/></svg>
                  <h2 style={{color:"white",fontSize:"16px",fontWeight:"700",margin:0}}>Jira Integration Setup</h2>
                </div>
                <button onClick={()=>{setShowJiraSetup(false);setJiraError("");}} style={{background:"transparent",border:"none",color:"#475569",cursor:"pointer",fontSize:"18px"}}>x</button>
              </div>

              <div style={{display:"flex",flexDirection:"column",gap:"12px",marginBottom:"16px"}}>
                <div>
                  <label style={{color:"#94A3B8",fontSize:"11px",fontWeight:"600",display:"block",marginBottom:"4px",letterSpacing:"1px"}}>JIRA HOST</label>
                  <input value={jiraConfig.host} onChange={e=>setJiraConfig(c=>({...c,host:e.target.value}))}
                    placeholder="yourcompany.atlassian.net"
                    style={{width:"100%",background:"#060E1A",border:"1px solid #1E3A5F",borderRadius:"6px",padding:"9px 12px",fontSize:"12px",color:"#E2E8F0",fontFamily:"inherit",outline:"none",boxSizing:"border-box"}}/>
                  <p style={{color:"#475569",fontSize:"10px",margin:"3px 0 0"}}>Do not include https:// - just the domain</p>
                </div>
                <div>
                  <label style={{color:"#94A3B8",fontSize:"11px",fontWeight:"600",display:"block",marginBottom:"4px",letterSpacing:"1px"}}>JIRA EMAIL</label>
                  <input value={jiraConfig.email} onChange={e=>setJiraConfig(c=>({...c,email:e.target.value}))}
                    placeholder="you@yourcompany.com"
                    style={{width:"100%",background:"#060E1A",border:"1px solid #1E3A5F",borderRadius:"6px",padding:"9px 12px",fontSize:"12px",color:"#E2E8F0",fontFamily:"inherit",outline:"none",boxSizing:"border-box"}}/>
                </div>
                <div>
                  <label style={{color:"#94A3B8",fontSize:"11px",fontWeight:"600",display:"block",marginBottom:"4px",letterSpacing:"1px"}}>API TOKEN</label>
                  <input type="password" value={jiraConfig.token} onChange={e=>setJiraConfig(c=>({...c,token:e.target.value}))}
                    placeholder="Your Jira API token"
                    style={{width:"100%",background:"#060E1A",border:"1px solid #1E3A5F",borderRadius:"6px",padding:"9px 12px",fontSize:"12px",color:"#E2E8F0",fontFamily:"inherit",outline:"none",boxSizing:"border-box"}}/>
                  <p style={{color:"#475569",fontSize:"10px",margin:"3px 0 0"}}>
                    Generate at: id.atlassian.com/manage-profile/security/api-tokens
                  </p>
                </div>
                <div>
                  <label style={{color:"#94A3B8",fontSize:"11px",fontWeight:"600",display:"block",marginBottom:"4px",letterSpacing:"1px"}}>PROJECT KEY</label>
                  <input value={jiraConfig.project} onChange={e=>setJiraConfig(c=>({...c,project:e.target.value.toUpperCase()}))}
                    placeholder="SEC"
                    style={{width:"100%",background:"#060E1A",border:"1px solid #1E3A5F",borderRadius:"6px",padding:"9px 12px",fontSize:"12px",color:"#E2E8F0",fontFamily:"inherit",outline:"none",boxSizing:"border-box"}}/>
                  <p style={{color:"#475569",fontSize:"10px",margin:"3px 0 0"}}>The short project key shown in Jira issue IDs (e.g. SEC-123)</p>
                </div>
              </div>

              {jiraError && (
                <div style={{background:"#3D1515",border:"1px solid #FF5C5C",borderRadius:"6px",padding:"8px 12px",marginBottom:"12px"}}>
                  <p style={{color:"#FF5C5C",fontSize:"11px",margin:0}}>{jiraError}</p>
                </div>
              )}

              <div style={{background:"#060E1A",border:"1px solid #1E293B",borderRadius:"6px",padding:"10px 12px",marginBottom:"16px"}}>
                <p style={{color:"#64748B",fontSize:"10px",margin:"0 0 4px",fontWeight:"600"}}>HOW TICKETS ARE CREATED</p>
                <p style={{color:"#475569",fontSize:"10px",margin:0,lineHeight:"1.6"}}>
                  Each finding creates a Jira Bug with severity mapped to priority (Critical=Highest), 
                  pre-filled with the finding title, affected resource, business impact, remediation steps, 
                  CLI command, and MITRE ATT&CK reference. Labels include cloud-security, sophos-cloud-radar, 
                  severity, and provider.
                </p>
              </div>

              <div style={{display:"flex",gap:"8px",justifyContent:"flex-end"}}>
                <button onClick={()=>{setShowJiraSetup(false);setJiraError("");}}
                  style={{background:"transparent",color:"#64748B",border:"1px solid #1E293B",borderRadius:"6px",padding:"8px 16px",fontSize:"12px",cursor:"pointer",fontFamily:"inherit"}}>
                  Cancel
                </button>
                <button onClick={()=>{saveJiraConfig(jiraConfig);setShowJiraSetup(false);setJiraError("");}}
                  style={{background:"#0052CC",color:"white",border:"none",borderRadius:"6px",padding:"8px 20px",fontSize:"12px",fontWeight:"700",cursor:"pointer",fontFamily:"inherit"}}>
                  Save Configuration
                </button>
              </div>
            </div>
          </div>
        )}
      <style>{"@import url('https://fonts.googleapis.com/css2?family=Nunito:wght@400;500;600;700;800;900&display=swap'); @keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}"}</style>
    </div>
  );
}
