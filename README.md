# Bitsight Security Ratings for Splunk

## Overview
Full Splunk App for Bitsight Security Ratings. Monitor and visualize security ratings, portfolio companies, alerts, findings, exposed credentials, users, and threat intelligence from the Bitsight API.

## Features
- **Security Ratings Monitoring**: Track your organization's security rating over time
- **Portfolio Management**: Monitor third-party vendor security posture
- **Alert Management**: Real-time notifications for security rating changes
- **Findings Analysis**: Detailed vulnerability and security finding tracking with CVSS scores
- **Exposed Credentials**: Data breach and credential exposure monitoring
- **Threat Intelligence**: CVE and vulnerability threat tracking
- **User Management**: Track user activity and quota usage
- **Trending Analysis**: WoW, MoM, QoQ, YoY rating and findings trends
- **21 Risk Vectors**: Complete coverage of all Bitsight risk vectors
- **10 Pre-built Dashboards**: Immediate insights out of the box
- **Setup Validation**: Automatic configuration validation on first launch

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
├── app.manifest              # App manifest for Splunk Cloud
├── LICENSE                   # Apache 2.0 License
├── README.md                 # This file
├── default/
│   ├── app.conf              # App configuration
│   ├── bitsight.conf         # Default settings
│   ├── inputs.conf           # Input definitions
│   ├── props.conf            # Field extraction rules
│   ├── transforms.conf       # Field transformations
│   └── data/ui/
│       ├── nav/default.xml   # Navigation menu
│       └── views/            # Dashboard XML files
├── bin/
│   ├── bitsight_input.py     # Modular input script
│   ├── bitsight_setup_handler.py  # Setup REST handler
│   └── bitsight_validation.py     # Configuration validation
├── lookups/
│   ├── bitsight_rating_categories.csv
│   ├── bitsight_risk_vectors.csv
│   └── bitsight_severity_levels.csv
├── local/
│   └── inputs.conf.example   # Example configuration
├── metadata/
│   ├── default.meta          # Default permissions
│   └── local.meta            # Local permissions
└── static/
    ├── appIcon.png           # App icon (36x36)
    ├── appIcon_2x.png        # Retina app icon (72x72)
    └── appIconAlt.png        # Alternative icon
```

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **Overview** | Executive summary with KPIs, rating trends, and alerts |
| **Ratings Analysis** | Detailed security rating analysis with risk vectors |
| **Trending** | Week/Month/Quarter/Year over period trending analysis |
| **Portfolio** | Third-party vendor portfolio management |
| **Findings** | Security findings summary |
| **Findings Detailed** | Detailed findings with CVSS, risk vectors, remediation |
| **Users** | User management, activity, and quota tracking |
| **Alerts** | Alert management and tracking |
| **Exposed Credentials** | Data breach and credential exposure tracking |
| **Threats** | CVE and threat intelligence dashboard |

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
