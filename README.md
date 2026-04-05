![BitSight](docs/images/%20BitSight_logo.jpg)

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
| severe | Severe | 1 | 🟥 |
| material | Material | 2 | 🟧 |
| moderate | Moderate | 3 | 🟨 |
| minor | Minor | 4 | 🟩 |


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
```

## Directory Structure

```text
BitSight_For_Splunk_App/
├── app.manifest
├── LICENSE
├── README.md
├── default/
│   ├── alert_actions.conf
│   ├── app.conf
│   ├── indexes.conf
│   ├── inputs.conf
│   ├── macros.conf
│   ├── props.conf
│   ├── restmap.conf
│   ├── savedsearches.conf
│   ├── transforms.conf
│   ├── web.conf
│   ├── workflow_actions.conf
│   ├── data/ui/
│   │   ├── nav/
│   │   │   └── default.xml
│   │   └── views/
│   │       ├── setup.xml
│   │       ├── bitsight_overview.xml
│   │       ├── bitsight_search.xml
│   │       ├── bitsight_portfolio.xml
│   │       ├── bitsight_ratings.xml
│   │       ├── bitsight_ratings_tree.xml
│   │       ├── bitsight_ratings_trending.xml
│   │       ├── bitsight_trending.xml
│   │       ├── bitsight_benchmarking.xml
│   │       ├── bitsight_findings.xml
│   │       ├── bitsight_findings_detailed.xml
│   │       ├── bitsight_findings_trending.xml
│   │       ├── bitsight_remediation.xml
│   │       ├── bitsight_mttr_executive.xml
│   │       ├── bitsight_asset_risk_matrix.xml
│   │       ├── bitsight_nist_csf.xml
│   │       ├── bitsight_threats.xml
│   │       ├── bitsight_exposed_credentials.xml
│   │       ├── bitsight_users.xml
│   │       ├── bitsight_users_access_review.xml
│   │       ├── bitsight_alerts.xml
│   │       ├── bitsight_health.xml
│   │       ├── bitsight_health_check.xml
│   │       ├── bitsight_operations.xml
│   │       ├── bitsight_logs.xml
│   │       ├── bitsight_reports.xml
│   │       ├── bitsight_help.xml
│   │       ├── bitsight_documentation_hub.xml
│   │       └── bitsight_api_documentation.xml
├── bin/
│   ├── bitsight_input.py
│   ├── bitsight_setup_handler.py
│   ├── bitsight_validation.py
│   ├── bitsight_email_alert.py
│   ├── bitsight_webhook_alert.py
│   ├── bitsight_script_alert.py
│   ├── bitsight_pagerduty_alert.py
│   └── bitsight_snow_alert.py
├── docs/
│   └── images/
│       └── BitSight_logo.jpg
├── local/
│   ├── alert_actions.conf.example
│   ├── bitsight_settings.conf.example
│   └── inputs.conf.example
├── lookups/
│   ├── bitsight_rating_categories.csv
│   ├── bitsight_risk_vectors.csv
│   └── bitsight_severity_levels.csv
├── metadata/
│   ├── default.meta
│   └── local.meta
├── README/
│   ├── alert_actions.conf.spec
│   └── bitsight_settings.conf.spec
└── static/
    ├── appIcon.png
    ├── appIcon_2x.png
    ├── appIconAlt.png
    └── appIconAlt_2x.png
```

## Sourcetypes

| Sourcetype | Description |
|------------|-------------|
| `bitsight_portfolio` | Portfolio company data |
| `bitsight_company` | Company detail and company search data |
| `bitsight_country` | Country detail data |
| `bitsight_rating_distribution` | Rating distribution data |
| `bitsight_ratings_tree` | Company hierarchy and ratings tree data |
| `bitsight_company_requests` | Company request summary data |
| `bitsight_ratings` | Current security ratings |
| `bitsight_ratings_history` | Historical ratings and grade history |
| `bitsight_ratings_history_csv` | Ratings history CSV export data |
| `bitsight_findings` | Security findings |
| `bitsight_findings_summary` | Findings summary data |
| `bitsight_findings_summaries` | Findings summaries data |
| `bitsight_findings_statistics` | Findings statistics |
| `bitsight_findings_comments` | Finding comment data |
| `bitsight_observations` | Observation data |
| `bitsight_risk_vectors` | Risk vector data |
| `bitsight_risk_vectors_summary` | Risk vector summary data |
| `bitsight_diligence_statistics` | Diligence statistics |
| `bitsight_industry_statistics` | Industry statistics |
| `bitsight_user_behavior_statistics` | User behavior statistics |
| `bitsight_observations_statistics` | Observation statistics |
| `bitsight_assets` | Asset data |
| `bitsight_assets_statistics` | Asset statistics and asset risk matrix data |
| `bitsight_infrastructure` | Infrastructure data |
| `bitsight_infrastructure_changes` | Infrastructure change data |
| `bitsight_ip_by_country` | IP by country data |
| `bitsight_providers` | Service provider and dependency data |
| `bitsight_products` | Product usage data |
| `bitsight_users` | User records |
| `bitsight_users_quota` | User quota information |
| `bitsight_users_views` | User company view activity |
| `bitsight_alerts` | BitSight alert notifications |
| `bitsight_credentials` | Exposed credentials data |
| `bitsight_threats` | Threat intelligence data |
| `bitsight_folders` | Folder data |
| `bitsight_tiers` | Tier data |
| `bitsight_subscriptions` | Subscription data |
| `bitsight_industries` | Industry reference data |
| `bitsight_peer_analytics` | Peer analytics data |
| `bitsight_nist_csf` | NIST CSF reporting data |
| `bitsight_preview_report` | Preview report data |

## Workflow Actions

| Workflow Action Area | Description |
|----------------------|-------------|
| Company Links | Open company pages directly in the BitSight portal |
| Company Searches | Search BitSight data for a selected company |
| Findings Searches | Pivot from company, risk vector, severity, or asset into findings |
| Credential Searches | Pivot from email to credential and breach data |
| Risk Vector Searches | Pivot from a risk vector to affected companies |
| Alert Searches | Pivot into historical alert activity |
| Industry and Tier Searches | Pivot by industry or tier |
| External Enrichment | Shodan, VirusTotal, Censys, WHOIS, DNS, and related lookups |

## Requirements

- Splunk Enterprise 8.0+ or compatible Splunk deployment
- Python 3.x runtime as provided by Splunk
- BitSight API token
- Network connectivity to BitSight APIs
- Optional proxy access if required by your environment

## AppInspect Compliance

This app is structured for Splunk app packaging and validation workflows, including:

- proper app directory structure
- no hardcoded credentials in shipped defaults
- metadata files
- setup handler support
- modular input support
- alert action scripts
- README documentation
- example local configuration files

## Troubleshooting

### No Data Appearing

1. Go to **Apps → BitSight → Setup**.
2. Verify the BitSight API token.
3. Run **Test API Connection**.
4. Confirm at least one input is enabled.
5. Search Splunk internal logs:

```spl
index=_internal source=*bitsight*
```

### API Errors

- Verify API token permissions in BitSight.
- Confirm connectivity to `api.bitsighttech.com`.
- Confirm base URL configuration.
- Check timeout values.
- Check proxy configuration if applicable.

### Proxy Issues

1. Verify proxy URL format includes protocol.
2. Verify proxy credentials if required.
3. Run **Test Proxy Connection**.
4. Check Splunk internal logs for proxy errors.

### Configuration Validation

- Save the setup page after changes.
- Review validation results.
- Review health and operations dashboards.
- Review app logs.

### Sourcetype Verification

Run:

```spl
index=security_bitsight
| stats count by sourcetype
| sort sourcetype
```

## Support

### BitSight Resources

- BitSight Knowledge Base  
  https://help.bitsighttech.com/hc/en-us
- How to Get Help  
  https://help.bitsighttech.com/hc/en-us/articles/115000807367-How-to-Get-Help
- BitSight Academy  
  https://academy.bitsight.com/
- BitSight API Documentation Overview  
  https://help.bitsighttech.com/hc/en-us/articles/231872628-API-Documentation-Overview

### Splunk Resources

- Splunk Documentation  
  https://docs.splunk.com

## License

Apache License 2.0

Copyright (c) 2025 Mark Teicher

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and-or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
