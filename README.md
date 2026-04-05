![BitSight](docs/images/BitSight_logo.jpg)

# BitSight Security Ratings for Splunk

## Overview

Full Splunk App for BitSight Security Ratings.

Monitor and visualize:

- security ratings
- portfolio companies
- alerts
- findings
- exposed credentials
- users
- threat intelligence
- risk vectors
- remediation activity
- operational health

This app provides prebuilt dashboards, modular input collection, lookup-backed enrichment, workflow actions, setup pages, alert actions, and documentation views for BitSight data in Splunk.

## ⚠️ Disclaimer

This tool is **not an official BitSight product**.

Use of this software is **not covered** by any license, warranty, or support agreement you may have with BitSight.

All functionality is implemented independently using publicly available BitSight documentation, including:

- BitSight API Documentation Overview  
  https://help.bitsighttech.com/hc/en-us/articles/231872628-API-Documentation-Overview
- What is a BitSight Security Rating  
  https://help.bitsighttech.com/hc/en-us/articles/231352528-What-is-a-Bitsight-Security-Rating
- Vulnerability Severity / BitSight Severity / CVSS  
  https://help.bitsighttech.com/hc/en-us/articles/4418994292887-Vulnerability-Severity-Bitsight-Severity-CVSS
- How to Get Help  
  https://help.bitsighttech.com/hc/en-us/articles/115000807367-How-to-Get-Help

## Features

### 🛡️ Core Capabilities

| Feature | Description |
|---------|-------------|
| 📊 Security Ratings Monitoring | Track your organization's security rating over time |
| 🏢 Portfolio Management | Monitor third-party vendor security posture with sparklines |
| 🔔 Alert Management | Real-time visibility into BitSight alert activity |
| 🔍 Findings Analysis | Detailed security finding tracking and investigation workflows |
| 🔐 Exposed Credentials | Data breach and credential exposure monitoring |
| ⚠️ Threat Intelligence | CVE and threat tracking from BitSight threat data |
| 👥 User Management | Track user activity, quota usage, and access review |
| 📈 Risk Vector Coverage | Coverage for BitSight risk vectors used by the app |

### 📈 Advanced Analytics

| Feature | Description |
|---------|-------------|
| 📉 Ratings Trending | Company-level ratings trending over time |
| 📊 Findings Trending | WoW, MoM, QoQ, and YoY findings trend analysis |
| 🔄 Comparative Trending | WoW, MoM, QoQ, and YoY rating comparisons |
| 🏆 Peer Benchmarking | Industry and peer group comparisons |
| ⏱️ MTTR Executive | Mean Time to Remediate executive metrics |
| 🎯 Asset Risk Matrix | Asset importance versus severity heat mapping |
| 🌳 Ratings Tree | Company hierarchy and subsidiary ratings visualization |

### ✅ Compliance & Governance

| Feature | Description |
|---------|-------------|
| 🏛️ NIST CSF Mapping | Risk vectors mapped to NIST Cybersecurity Framework |
| ⏰ SLA Tracking | Remediation SLA monitoring and overdue tracking |
| 👤 User Access Review | Periodic access review and audit support |

### ⚙️ Operational Excellence

| Feature | Description |
|---------|-------------|
| 📊 Operational Metrics | Records processed, API calls, and ingestion metrics |
| 💓 Health Monitoring | Data freshness and collection status |
| ✅ Configuration Validation | Setup validation and health verification |
| 🕐 Scheduled Health Checks | Daily validation and recurring operational checks |
| 📋 Log Viewer | API activity and error monitoring |
| 📚 Documentation Views | In-app help, glossary, documentation hub, and API documentation hub |

### 🚨 Alert Actions

| Feature | Description |
|---------|-------------|
| 📧 Email Alert Action | Sends email notifications for BitSight alerts |
| 🌐 Webhook Alert Action | Sends webhook notifications to external systems |
| 🧩 Script Alert Action | Executes local custom scripts for downstream workflows |
| 📟 PagerDuty Alert Action | Triggers PagerDuty incidents for urgent alerts |
| 🎫 ServiceNow Alert Action | Creates ServiceNow incidents for operational response |

### 🚀 Deployment

| Feature | Description |
|---------|-------------|
| 🖥️ Web UI Setup | Configure the app through Splunk Web |
| ☁️ Splunk Cloud Ready | App structure prepared for Splunk packaging and validation workflows |
| 🧾 Example Configurations | Includes example local configuration files |
| 🔍 Workflow Actions | Search, pivot, and external enrichment shortcuts |
| 📦 Modular Input Collection | Collect BitSight data directly into Splunk indexes |

## BitSight Rating Categories

| Category | Rating Range | Description |
|----------|--------------|-------------|
| Advanced | 740-900 | Strong security performance and lower risk |
| Intermediate | 640-730 | Fair security performance and moderate risk |
| Basic | 250-630 | Poor security performance and higher risk |

## BitSight Severity Levels

| Severity | Display Name | Priority | Color |
|----------|--------------|----------|-------|
| severe | Severe | 1 | `#dc4e41` |
| material | Material | 2 | `#f1813f` |
| moderate | Moderate | 3 | `#f8be34` |
| minor | Minor | 4 | `#53a051` |

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **Overview** | Executive summary with KPIs, rating trends, and alerts |
| **Search** | Company search and lookup |
| **Portfolio** | Third-party vendor portfolio management with sparklines |
| **Ratings Tree** | Company hierarchy and subsidiary ratings |
| **Benchmarking** | Peer and industry benchmarking comparisons |
| **Ratings** | Detailed security rating analysis with risk vectors |
| **Ratings Trending** | Company ratings trending over time |
| **Trending** | WoW, MoM, QoQ, YoY comparative trending analysis |
| **Findings** | Security findings summary by severity and risk vector |
| **Findings Detailed** | Detailed findings with assets and remediation context |
| **Findings Trending** | Findings WoW, MoM, QoQ, YoY trending analysis |
| **Remediation** | Remediation tracking and SLA monitoring |
| **MTTR Executive** | Mean Time to Remediate executive dashboard |
| **Asset Risk Matrix** | Asset importance versus severity risk matrix |
| **NIST CSF** | NIST Cybersecurity Framework compliance mapping |
| **Threats** | CVE and threat intelligence dashboard |
| **Exposed Credentials** | Data breach and credential exposure tracking |
| **Users** | User management, activity, and quota tracking |
| **Users Access Review** | User access review and audit dashboard |
| **Alerts** | Alert management and tracking |
| **Health** | Data health and ingestion monitoring |
| **Health Check** | Configuration validation and scheduled health checks |
| **Operations** | Records processed and ingestion metrics |
| **Logs** | Log viewer and API activity monitoring |
| **Reports** | Board-ready report generation |
| **Help** | Executive help, glossary, support, and troubleshooting |
| **Documentation Hub** | General BitSight documentation landing view |
| **API Documentation Hub** | BitSight API documentation landing view |

## Risk Vectors Supported

### Compromised Systems (5)

- `botnet_infections`
- `spam_propagation`
- `malware_servers`
- `unsolicited_comm`
- `potentially_exploited`

### Diligence (15)

- `spf`
- `dkim`
- `ssl_certificates`
- `ssl_configurations`
- `open_ports`
- `web_appsec`
- `patching_cadence`
- `insecure_systems`
- `server_software`
- `desktop_software`
- `mobile_software`
- `dnssec`
- `mobile_application_security`
- `application_security`
- `dmarc`

### User Behavior (1)

- `file_sharing`

## Installation

### Step 1: Deploy the App

1. Download the packaged app archive.
2. In Splunk Web, navigate to **Apps → Manage Apps**.
3. Click **Install app from file**.
4. Upload the app package.
5. Restart Splunk when prompted.

### Step 2: Configure the App

1. In Splunk Web, navigate to **Apps → BitSight → Setup**.
2. Configure the required settings.

#### API Configuration

- **BitSight API Token**  
  Enter your BitSight API token.
- **API Base URL**  
  Default is `https://api.bitsighttech.com`
- **Verify SSL**  
  Enable SSL certificate verification unless your environment requires otherwise.
- **Request Timeout**  
  Set timeout in seconds.

#### Proxy Configuration

- **Use Proxy**  
  Enable if your network requires a proxy.
- **Proxy URL**  
  Example: `http://proxy.example.com:8080`
- **Proxy Username**  
  Optional.
- **Proxy Password**  
  Optional.

#### Data Inputs

Enable the data inputs you want to collect.

Examples include:

- Portfolio
- Ratings
- Ratings History
- Findings
- Findings Summary
- Alerts
- Exposed Credentials
- Threats
- Users
- User Quota
- User Company Views
- Tiers
- Industries
- Ratings Tree
- Risk Vectors
- Asset and infrastructure collection inputs
- Reporting and statistics inputs

#### Collection Settings

Configure collection timing and history values.

Examples include:

- Portfolio Interval
- Ratings Interval
- Ratings History Interval
- Findings Interval
- Alerts Interval
- Threats Interval
- Exposed Credentials Interval
- Users Interval
- Days Back

3. Click **Save**.

### Step 3: Validate Configuration

1. Click **Test API Connection** to validate your BitSight API token.
2. If using a proxy, click **Test Proxy Connection**.
3. Review setup validation and health results.

### Step 4: Verify Data Collection

In Splunk Web, run:

```spl
index=security_bitsight sourcetype=bitsight_*
| stats count by sourcetype
