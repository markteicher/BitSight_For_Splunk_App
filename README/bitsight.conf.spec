#
# =============================================================================
# FILE
# =============================================================================
# README/bitsight_settings.conf.spec
#
# =============================================================================
# PURPOSE
# =============================================================================
# BitSight configuration file specification
# setup configuration reference
# proxy configuration reference
# input toggle configuration reference
# collection interval configuration reference
# logging configuration reference
# validation state configuration reference
#
# =============================================================================
# FILE FORMAT
# =============================================================================
# Splunk .conf.spec
#
# =============================================================================
# GRANULAR DOCUMENTATION SPECIFICATION
# =============================================================================
# STANZAS
# settings
# proxy
# inputs
# collection
# logging
# validation
#

[settings]

api_token = <string>
# BitSight API authentication token
# Required for API access

base_url = <string>
# Base URL for the BitSight API
# Default: https://api.bitsighttech.com/ratings/v1

verify_ssl = <bool>
# Whether to verify SSL certificates
# Valid values: true | false
# Default: true

timeout = <integer>
# Request timeout in seconds
# Default: 60


[proxy]

proxy_enabled = <bool>
# Enable proxy for API requests
# Valid values: true | false
# Default: false

proxy_url = <string>
# Proxy server URL
# Example: http://proxy.example.com:8080
# Required if proxy_enabled is true

proxy_username = <string>
# Proxy authentication username
# Optional

proxy_password = <string>
# Proxy authentication password
# Optional


[inputs]

input_portfolio = <bool>
# Enable portfolio collection
# Default: true

input_ratings = <bool>
# Enable current ratings collection
# Default: true

input_ratings_history = <bool>
# Enable ratings history collection
# Default: true

input_ratings_history_csv = <bool>
# Enable ratings history CSV collection
# Default: false

input_company_details = <bool>
# Enable company details collection
# Default: false

input_country_details = <bool>
# Enable country details collection
# Default: false

input_company_requests_summary = <bool>
# Enable company requests summary collection
# Default: false

input_findings = <bool>
# Enable findings collection
# Default: true

input_findings_compromised = <bool>
# Enable compromised findings collection
# Default: false

input_findings_diligence = <bool>
# Enable diligence findings collection
# Default: false

input_findings_summary = <bool>
# Enable findings summary collection
# Default: true

input_finding_comments = <bool>
# Enable finding comments collection
# Default: false

input_risk_vectors = <bool>
# Enable risk vector collection
# Default: true

input_alerts = <bool>
# Enable alert collection
# Default: true

input_exposed_credentials = <bool>
# Enable exposed credentials collection
# Default: true

input_threats = <bool>
# Enable threat collection
# Default: true

input_users = <bool>
# Enable user collection
# Default: true

input_user_quota = <bool>
# Enable user quota collection
# Default: true

input_user_company_views = <bool>
# Enable user company views collection
# Default: false

input_folders = <bool>
# Enable folder collection
# Default: false

input_tiers = <bool>
# Enable tier collection
# Default: false

input_industries = <bool>
# Enable industry collection
# Default: false

input_assets = <bool>
# Enable asset collection
# Default: false

input_asset_risk_matrix = <bool>
# Enable asset risk matrix collection
# Default: false

input_infrastructure = <bool>
# Enable infrastructure collection
# Default: false

input_infrastructure_changes = <bool>
# Enable infrastructure changes collection
# Default: false

input_ip_by_country = <bool>
# Enable IP by country collection
# Default: false

input_diligence_statistics = <bool>
# Enable diligence statistics collection
# Default: false

input_observations_statistics = <bool>
# Enable observations statistics collection
# Default: false

input_industry_statistics = <bool>
# Enable industry statistics collection
# Default: false

input_user_behavior_statistics = <bool>
# Enable user behavior statistics collection
# Default: false

input_service_providers = <bool>
# Enable service providers collection
# Default: false

input_products = <bool>
# Enable products collection
# Default: false

input_ratings_tree = <bool>
# Enable ratings tree collection
# Default: false

input_observations = <bool>
# Enable observations collection
# Default: false

input_findings_summaries = <bool>
# Enable findings summaries collection
# Default: false

input_findings_statistics = <bool>
# Enable findings statistics collection
# Default: false

input_peer_analytics = <bool>
# Enable peer analytics collection
# Default: false

input_rating_distribution = <bool>
# Enable rating distribution collection
# Default: false

input_nist_csf_report = <bool>
# Enable NIST CSF report collection
# Default: false

input_preview_report = <bool>
# Enable preview report collection
# Default: false

input_risk_vectors_summary = <bool>
# Enable risk vectors summary collection
# Default: false


[collection]

portfolio_interval = <integer>
# Collection interval for portfolio data in seconds
# Default: 3600

ratings_interval = <integer>
# Collection interval for current ratings data in seconds
# Default: 3600

ratings_history_interval = <integer>
# Collection interval for ratings history data in seconds
# Default: 86400

ratings_history_csv_interval = <integer>
# Collection interval for ratings history CSV data in seconds
# Default: 86400

company_details_interval = <integer>
# Collection interval for company details data in seconds
# Default: 86400

country_details_interval = <integer>
# Collection interval for country details data in seconds
# Default: 86400

company_requests_summary_interval = <integer>
# Collection interval for company requests summary data in seconds
# Default: 86400

findings_interval = <integer>
# Collection interval for findings data in seconds
# Default: 3600

findings_compromised_interval = <integer>
# Collection interval for compromised findings data in seconds
# Default: 3600

findings_diligence_interval = <integer>
# Collection interval for diligence findings data in seconds
# Default: 3600

findings_summary_interval = <integer>
# Collection interval for findings summary data in seconds
# Default: 3600

finding_comments_interval = <integer>
# Collection interval for finding comments data in seconds
# Default: 3600

risk_vectors_interval = <integer>
# Collection interval for risk vector data in seconds
# Default: 3600

alerts_interval = <integer>
# Collection interval for alerts data in seconds
# Default: 900

threats_interval = <integer>
# Collection interval for threat data in seconds
# Default: 3600

exposed_credentials_interval = <integer>
# Collection interval for exposed credentials data in seconds
# Default: 3600

users_interval = <integer>
# Collection interval for user data in seconds
# Default: 3600

user_quota_interval = <integer>
# Collection interval for user quota data in seconds
# Default: 3600

user_company_views_interval = <integer>
# Collection interval for user company views data in seconds
# Default: 3600

folders_interval = <integer>
# Collection interval for folder data in seconds
# Default: 86400

tiers_interval = <integer>
# Collection interval for tier data in seconds
# Default: 86400

industries_interval = <integer>
# Collection interval for industry data in seconds
# Default: 86400

assets_interval = <integer>
# Collection interval for asset data in seconds
# Default: 3600

asset_risk_matrix_interval = <integer>
# Collection interval for asset risk matrix data in seconds
# Default: 3600

infrastructure_interval = <integer>
# Collection interval for infrastructure data in seconds
# Default: 3600

infrastructure_changes_interval = <integer>
# Collection interval for infrastructure changes data in seconds
# Default: 3600

ip_by_country_interval = <integer>
# Collection interval for IP by country data in seconds
# Default: 86400

diligence_statistics_interval = <integer>
# Collection interval for diligence statistics data in seconds
# Default: 86400

observations_statistics_interval = <integer>
# Collection interval for observations statistics data in seconds
# Default: 86400

industry_statistics_interval = <integer>
# Collection interval for industry statistics data in seconds
# Default: 86400

user_behavior_statistics_interval = <integer>
# Collection interval for user behavior statistics data in seconds
# Default: 86400

service_providers_interval = <integer>
# Collection interval for service providers data in seconds
# Default: 86400

products_interval = <integer>
# Collection interval for products data in seconds
# Default: 86400

ratings_tree_interval = <integer>
# Collection interval for ratings tree data in seconds
# Default: 86400

observations_interval = <integer>
# Collection interval for observations data in seconds
# Default: 3600

findings_summaries_interval = <integer>
# Collection interval for findings summaries data in seconds
# Default: 3600

findings_statistics_interval = <integer>
# Collection interval for findings statistics data in seconds
# Default: 3600

peer_analytics_interval = <integer>
# Collection interval for peer analytics data in seconds
# Default: 86400

rating_distribution_interval = <integer>
# Collection interval for rating distribution data in seconds
# Default: 86400

nist_csf_report_interval = <integer>
# Collection interval for NIST CSF report data in seconds
# Default: 86400

preview_report_interval = <integer>
# Collection interval for preview report data in seconds
# Default: 86400

risk_vectors_summary_interval = <integer>
# Collection interval for risk vectors summary data in seconds
# Default: 86400

days_back = <integer>
# Number of days of historical data to collect
# Default: 365


[logging]

log_level = DEBUG|INFO|WARNING|ERROR
# Logging level for the app
# Default: INFO


[validation]

first_run = <bool>
# Whether the app is in first-run state
# Valid values: true | false

validated = <bool>
# Whether configuration validation has completed successfully
# Valid values: true | false

last_validation = <string>
# Timestamp of the last validation run
# Example: 2025-01-15T12:00:00Z
