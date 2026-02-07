# Bitsight Security Ratings for Splunk

## Overview
Full Splunk App for Bitsight Security Ratings. Monitor and visualize security ratings, portfolio companies, alerts, findings, exposed credentials, users, and threat intelligence from the Bitsight API.


## ⚠️ Disclaimer

This tool is **not an official BitSight product**.

Use of this software is **not covered** by any license, warranty, or support agreement you may have with BitSight.
All functionality is implemented independently using publicly available Bitsight API Documentation: https://help.bitsighttech.com/hc/en-us/articles/231872628-API-Documentation-Overview


## Features

### 🛡️ Core Capabilities
| Feature | Description |
|---------|-------------|
| 📊 Security Ratings Monitoring | Track your organization's security rating over time |
| 🏢 Portfolio Management | Monitor third-party vendor security posture with sparklines |
| 🔔 Alert Management | Real-time notifications for security rating changes |
| 🔍 Findings Analysis | Detailed vulnerability and security finding tracking with CVSS scores |
| 🔐 Exposed Credentials | Data breach and credential exposure monitoring |
| ⚠️ Threat Intelligence | CVE and vulnerability threat tracking |
| 👥 User Management | Track user activity, quota usage, and access review |
| 📈 21 Risk Vectors | Complete coverage of all Bitsight risk vectors |

### 📈 Advanced Analytics
| Feature | Description |
|---------|-------------|
| 📉 Ratings Trending | Company-level ratings trending over time |
| 📊 Findings Trending | WoW, MoM, QoQ, YoY findings trend analysis |
| 🔄 Comparative Trending | WoW, MoM, QoQ, YoY rating comparisons |
| 🏆 Peer Benchmarking | Industry and peer group comparisons |
| ⏱️ MTTR Executive | Mean Time to Remediate executive metrics |
| 🎯 Asset Risk Matrix | Asset importance vs severity heat mapping |
| 🌳 Ratings Tree | Company hierarchy and subsidiary ratings visualization |

### ✅ Compliance & Governance
| Feature | Description |
|---------|-------------|
| 🏛️ NIST CSF Mapping | Risk vectors mapped to NIST Cybersecurity Framework |
| ⏰ SLA Tracking | Remediation SLA monitoring and breach alerts |
| 👤 User Access Review | Periodic access review and audit support |

### ⚙️ Operational Excellence
| Feature | Description |
|---------|-------------|
| 📊 Operational Metrics | Records processed, API calls, ingestion rates |
| 💓 Health Monitoring | Data freshness and collection status |
| ✅ Configuration Validation | Automatic setup validation on first launch |
| 🕐 Scheduled Health Checks | Daily validation and hourly API health checks |
| 📋 Log Viewer | API activity and error monitoring |

### 🚀 Deployment
| Feature | Description |
|---------|-------------|
| 📊 26 Pre-built Dashboards | Immediate insights out of the box |
| 🖥️ Web UI Setup | No CLI required - configure via Splunk Web |
| ☁️ Splunk Cloud Ready | AppInspect compliant for cloud deployment |
| 📧 Alert Actions | Email, Webhook, Script, and PagerDuty integrations |

## Installation

### Step 1: Deploy the App
1. Download the `BitSight_For_Splunk_App-1.0.0.tar.gz` file
2. In Splunk Web, navigate to **Apps → Manage Apps**
3. Click **Install app from file**
4. Upload the `.tar.gz` file and click **Upload**
5. Restart Splunk when prompted

### Step 2: Configure the App
1. In Splunk Web, navigate to **Apps → Bitsight → Setup**
2. Configure the following settings:

#### API Configuration
- **Bitsight API Token**: Enter your API token (obtain from the Bitsight portal)
- **API Base URL**: Default is `https://api.bitsighttech.com`
- **Verify SSL**: Enable SSL certificate verification (recommended)
- **Request Timeout**: Set timeout in seconds (default: 60)

#### Proxy Configuration (Optional)
- **Use Proxy**: Enable if your network requires a proxy
- **Proxy URL**: Enter proxy URL (e.g., `http://proxy.example.com:8080`)
- **Proxy Username**: Enter username if proxy requires authentication
- **Proxy Password**: Enter password if proxy requires authentication

#### Data Inputs
Select which data to collect:
- Portfolio Companies
- Security Ratings
- Ratings History (Trending)
- Security Findings
- Findings Summary
- Alerts
- Exposed Credentials
- Threat Intelligence
- Users & Quota

#### Collection Settings
- **Portfolio Interval**: How often to collect portfolio data (seconds)
- **Findings Interval**: How often to collect findings data (seconds)
- **Alerts Interval**: How often to check for new alerts (seconds)
- **Historical Data**: Number of days of historical data to collect

3. Click **Save** to apply the configuration

### Step 3: Validate Configuration
1. After saving, click **Test API Connection** to verify your API token
2. If using a proxy, click **Test Proxy Connection** to verify connectivity
3. The app will automatically validate your configuration on first launch

### Step 4: Verify Data Collection
In Splunk Web, run this search to verify data is being collected:
```spl
index=security_bitsight sourcetype=bitsight:*
| stats count by sourcetype
```

## Directory Structure
```
BitSight_For_Splunk_App/
├── app.manifest                    # App manifest for Splunk Cloud
├── LICENSE                         # Apache 2.0 License
├── README.md                       # This file
├── default/
│   ├── app.conf                    # App configuration
│   ├── alert_actions.conf          # Alert action definitions
│   ├── bitsight.conf               # Default settings
│   ├── indexes.conf                # Index definitions
│   ├── inputs.conf                 # Input definitions
│   ├── macros.conf                 # Search macros
│   ├── props.conf                  # Field extraction rules
│   ├── restmap.conf                # REST API configuration
│   ├── savedsearches.conf          # Saved searches & alerts
│   ├── server.conf                 # Server configuration
│   ├── transforms.conf             # Field transformations
│   ├── web.conf                    # Web settings
│   ├── workflow_actions.conf       # Workflow actions
│   └── data/ui/
│       ├── nav/default.xml         # Navigation menu
│       └── views/                  # Dashboard XML files (26 dashboards)
│           ├── setup.xml           # Setup wizard
│           ├── bitsight_overview.xml
│           ├── bitsight_search.xml
│           ├── bitsight_portfolio.xml
│           ├── bitsight_ratings.xml
│           ├── bitsight_ratings_tree.xml
│           ├── bitsight_ratings_trending.xml
│           ├── bitsight_trending.xml
│           ├── bitsight_benchmarking.xml
│           ├── bitsight_findings.xml
│           ├── bitsight_findings_detailed.xml
│           ├── bitsight_findings_trending.xml
│           ├── bitsight_remediation.xml
│           ├── bitsight_mttr_executive.xml
│           ├── bitsight_asset_risk_matrix.xml
│           ├── bitsight_nist_csf.xml
│           ├── bitsight_threats.xml
│           ├── bitsight_exposed_credentials.xml
│           ├── bitsight_users.xml
│           ├── bitsight_users_access_review.xml
│           ├── bitsight_alerts.xml
│           ├── bitsight_health.xml
│           ├── bitsight_health_check.xml
│           ├── bitsight_operations.xml
│           ├── bitsight_logs.xml
│           ├── bitsight_reports.xml
│           └── bitsight_help.xml
├── bin/
│   ├── bitsight_input.py           # Modular input script
│   ├── bitsight_setup_handler.py   # Setup REST handler
│   ├── bitsight_validation.py      # Configuration validation
│   ├── bitsight_email_alert.py     # Email alert action
│   ├── bitsight_webhook_alert.py   # Webhook alert action
│   ├── bitsight_script_alert.py    # Script alert action
│   └── bitsight_pagerduty_alert.py # PagerDuty alert action
├── lookups/
│   ├── bitsight_rating_categories.csv
│   ├── bitsight_risk_vectors.csv
│   └── bitsight_severity_levels.csv
├── local/
│   └── inputs.conf.example         # Example configuration
├── metadata/
│   ├── default.meta                # Default permissions
│   └── local.meta                  # Local permissions
├── README/
│   ├── bitsight.conf.spec          # Config specification
│   └── alert_actions.conf.spec     # Alert actions spec
└── static/
    ├── appIcon.png                 # App icon (36x36)
    ├── appIcon_2x.png              # Retina app icon (72x72)
    ├── appIconAlt.png              # Alternative icon (36x36)
    └── appIconAlt_2x.png           # Retina alt icon (72x72)
```

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
| **Findings Detailed** | Detailed findings with CVSS scores, assets, remediation |
| **Findings Trending** | Findings WoW, MoM, QoQ, YoY trending analysis |
| **Remediation** | Remediation tracking and SLA monitoring |
| **MTTR Executive** | Mean Time to Remediate executive dashboard |
| **Asset Risk Matrix** | Asset importance vs severity risk matrix |
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
| **Help** | Executive help and glossary |

## Risk Vectors Supported

### Compromised Systems (5)
- botnet_infections, spam_propagation, malware_servers, unsolicited_comm, potentially_exploited

### Diligence (15)
- spf, dkim, ssl_certificates, ssl_configurations, open_ports, web_appsec
- patching_cadence, insecure_systems, server_software, desktop_software
- mobile_software, dnssec, mobile_application_security, application_security, dmarc

### User Behavior (1)
- file_sharing

## Sourcetypes

| Sourcetype | Description |
|------------|-------------|
| `bitsight:portfolio` | Portfolio company data |
| `bitsight:current_ratings` | Current security ratings |
| `bitsight:ratings_history` | Historical ratings for trending |
| `bitsight:findings` | Security findings |
| `bitsight:findings_summary` | Findings summary statistics |
| `bitsight:alerts` | Alert notifications |
| `bitsight:threats` | Threat intelligence |
| `bitsight:exposed_credentials` | Exposed credentials |
| `bitsight:users` | User accounts |
| `bitsight:user_quota` | User quota information |
| `bitsight:user_company_views` | User activity |

## Requirements

- Splunk Enterprise 8.0+ or Splunk Cloud
- Python 3.x (included with Splunk)
- Bitsight API Token (obtain from Bitsight portal)

## AppInspect Compliance

This app is designed to pass Splunk AppInspect validation:
- ✅ Proper directory structure
- ✅ app.manifest for Splunk Cloud
- ✅ No hardcoded credentials in default/
- ✅ All inputs disabled by default
- ✅ Proper metadata permissions
- ✅ Apache 2.0 License included
- ✅ README documentation
- ✅ Setup validation script

## Troubleshooting

### No data appearing
1. Navigate to **Apps → Bitsight → Setup** and verify your API token
2. Click **Test API Connection** to validate connectivity
3. Check that at least one data input is enabled
4. In Splunk Web, search `index=_internal source=*bitsight*` for errors

### API errors
- Verify your API token has the correct permissions in the Bitsight portal
- Check Bitsight API rate limits
- Ensure network connectivity to `api.bitsighttech.com`
- If using a proxy, verify proxy settings and test connection

### Proxy issues
1. Navigate to **Apps → Bitsight → Setup**
2. Verify proxy URL format includes protocol (http:// or https://)
3. Click **Test Proxy Connection** to validate
4. Check proxy authentication credentials if required

### Configuration validation
The app automatically validates configuration on first launch. To re-run validation:
1. Navigate to **Apps → Bitsight → Setup**
2. Make any change and click **Save**
3. Check the validation results in the app logs

## Support
- Bitsight API Documentation: https://help.bitsighttech.com/hc/en-us/articles/231872628-API-Documentation-Overview
- Splunk Documentation: https://docs.splunk.com

## License
Apache License 2.0

#Copyright (c) 2025 Mark Teicher

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
