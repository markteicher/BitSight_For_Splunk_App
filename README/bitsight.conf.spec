# Bitsight configuration file specification

[settings]
api_token = <value>
* Bitsight API authentication token
* Required for API access

base_url = <value>
* Base URL for Bitsight API
* Default: https://api.bitsighttech.com/ratings/v1

verify_ssl = <bool>
* Whether to verify SSL certificates
* Default: true

timeout = <integer>
* Request timeout in seconds
* Default: 60

proxy_enabled = <bool>
* Enable proxy for API requests
* Default: false

proxy_url = <value>
* Proxy server URL (e.g., http://proxy:8080)
* Required if proxy_enabled is true

[collection]
portfolio_interval = <integer>
* Collection interval for portfolio data in seconds
* Default: 3600

findings_interval = <integer>
* Collection interval for findings data in seconds
* Default: 3600

alerts_interval = <integer>
* Collection interval for alerts data in seconds
* Default: 900

days_back = <integer>
* Number of days of historical data to collect
* Default: 365

[logging]
log_level = DEBUG|INFO|WARNING|ERROR
* Logging level for the app
* Default: INFO
