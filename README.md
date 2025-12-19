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

## Installation

### Step 1: Deploy the App
1. Download the `BitSight_For_Splunk_App-1.0.0.tar.gz` file
2. In Splunk Web, navigate to **Apps → Manage Apps**
3. Click **Install app from file**
4. Upload the `.tar.gz` file and click **Upload**
5. Restart Splunk when prompted

### Step 2: Configure API Token
1. Copy the example configuration:
```bash
cp $SPLUNK_HOME/etc/apps/BitSight_For_Splunk_App/local/inputs.conf.example $SPLUNK_HOME/etc/apps/BitSight_For_Splunk_App/local/inputs.conf
```

2. Edit `local/inputs.conf` and replace `YOUR_BITSIGHT_API_TOKEN_HERE` with your actual API token

3. Set `disabled = 0` for the inputs you want to enable

### Step 3: Verify Data Collection
Run this search to verify data is being collected:
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
│   ├── inputs.conf           # Input definitions (disabled by default)
│   ├── props.conf            # Field extraction rules
│   ├── transforms.conf       # Field transformations
│   └── data/ui/
│       ├── nav/default.xml   # Navigation menu
│       └── views/            # Dashboard XML files
├── bin/
│   └── bitsight_input.py     # Modular input script
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

## Troubleshooting

### No data appearing
1. Verify `local/inputs.conf` exists with your API token
2. Check inputs are enabled (`disabled = 0`)
3. Check `$SPLUNK_HOME/var/log/splunk/splunkd.log` for errors

### API errors
- Verify your API token has the correct permissions
- Check Bitsight API rate limits
- Ensure network connectivity to `api.bitsighttech.com`

## Support
- Bitsight API Documentation: https://help.bitsighttech.com/hc/en-us/articles/231872628-API-Documentation-Overview
- Splunk Documentation: https://docs.splunk.com

## License
Apache License 2.0
