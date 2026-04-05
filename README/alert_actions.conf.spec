#
# =============================================================================
# FILE
# =============================================================================
# README/alert_actions.conf.spec
#
# =============================================================================
# PURPOSE
# =============================================================================
# BitSight alert actions configuration specification
# reference for configuring BitSight alert actions
# parameter reference for supported alert actions
# variable substitution reference
#
# =============================================================================
# FILE FORMAT
# =============================================================================
# Splunk .conf.spec
#
# =============================================================================
# GRANULAR DOCUMENTATION SPECIFICATION
# =============================================================================
# ALERT ACTIONS
# bitsight_email_alert
# bitsight_webhook_alert
# bitsight_script_alert
# bitsight_snow_alert
# bitsight_pagerduty_alert
#
# VARIABLE SUBSTITUTION
# supported in selected string parameters
#

# ============================================================================
# EMAIL ALERT ACTION
# ============================================================================
[bitsight_email_alert]

param.to = <string>
# Required
# Comma-separated list of email addresses to send alerts to

param.cc = <string>
# Optional
# Comma-separated list of CC email addresses

param.subject = <string>
# Email subject line
# Supports variable substitution
# Default: BitSight Alert

param.message = <string>
# Email body message
# Supports variable substitution

param.include_results = <bool>
# Whether to include search results in the email
# Valid values: 0 | 1
# Default: 1

param.include_link = <bool>
# Whether to include a link to results in Splunk
# Valid values: 0 | 1
# Default: 1

param.priority = <string>
# Email priority
# Valid values: low | normal | high
# Default: normal

param.smtp_server = <string>
# SMTP server hostname
# Default: localhost

param.smtp_port = <integer>
# SMTP server port
# Default: 25

param.smtp_use_tls = <bool>
# Whether to enable SMTP TLS
# Valid values: 0 | 1
# Default: 0

param.smtp_user = <string>
# Optional SMTP authentication username

param.smtp_password = <string>
# Optional SMTP authentication password

param.from_address = <string>
# Sender email address
# Default: splunk@localhost

param.smtp_timeout = <integer>
# SMTP timeout in seconds
# Default: 30


# ============================================================================
# WEBHOOK ALERT ACTION
# ============================================================================
[bitsight_webhook_alert]

param.webhook_url = <string>
# Required
# Webhook URL to send notifications to
# Examples:
# Slack: https://hooks.slack.com/services/xxx/yyy/zzz
# Teams: https://outlook.office.com/webhook/xxx
# Custom: https://your-api.example.com/webhook

param.method = <string>
# HTTP method to use
# Valid values: POST | PUT | PATCH
# Default: POST

param.content_type = <string>
# Content-Type header value
# Default: application/json

param.payload_template = <string>
# JSON template for the webhook payload
# Supports variable substitution
# Default: {"alert_name":"$name$","trigger_time":"$trigger_time$"}

param.custom_headers = <string>
# Custom HTTP headers
# One header per line
# Format: Header-Name: value

param.verify_ssl = <bool>
# Whether to verify SSL certificates
# Valid values: 0 | 1
# Default: 1

param.timeout = <integer>
# Request timeout in seconds
# Default: 30


# ============================================================================
# SCRIPT ALERT ACTION
# ============================================================================
[bitsight_script_alert]

param.script_name = <string>
# Required
# Name of the script to execute
# Script must exist in the bin/ directory

param.script_args = <string>
# Optional
# Additional arguments to pass to the script

param.pass_payload = <bool>
# Whether to pass the alert payload to the script as a JSON file
# Valid values: 0 | 1
# Default: 1

param.timeout = <integer>
# Script execution timeout in seconds
# Default: 300


# ============================================================================
# SERVICENOW ALERT ACTION
# ============================================================================
[bitsight_snow_alert]

param.snow_url = <string>
# Required
# ServiceNow instance URL
# Example: https://instance.service-now.com

param.snow_user = <string>
# Required
# ServiceNow username for API access

param.snow_password = <string>
# Required
# ServiceNow password for API access

param.incident_category = <string>
# Incident category
# Supports variable substitution
# Default: Security

param.incident_subcategory = <string>
# Incident subcategory
# Supports variable substitution
# Default: Vendor Risk

param.incident_priority = <string>
# Incident priority
# Supports variable substitution
# Default: 3

param.incident_short_description = <string>
# Short description for the incident
# Supports variable substitution
# Default: [BitSight] Alert

param.incident_description = <string>
# Full description for the incident
# Supports variable substitution
# Default: BitSight alert triggered.

param.timeout = <integer>
# Request timeout in seconds
# Default: 30


# ============================================================================
# PAGERDUTY ALERT ACTION
# ============================================================================
[bitsight_pagerduty_alert]

param.routing_key = <string>
# Required
# PagerDuty Events API v2 routing key

param.severity = <string>
# Event severity
# Valid values: critical | error | warning | info
# Default: error

param.dedup_key = <string>
# Deduplication key for grouping related events
# Supports variable substitution

param.event_action = <string>
# Event action
# Valid values: trigger | acknowledge | resolve
# Default: trigger

param.summary = <string>
# Event summary
# Supports variable substitution
# Default: BitSight Alert

param.source = <string>
# Event source identifier
# Supports variable substitution
# Default: Splunk BitSight App

param.component = <string>
# Affected component
# Supports variable substitution

param.group = <string>
# Logical grouping
# Supports variable substitution
# Default: vendor-risk

param.class = <string>
# Event class
# Supports variable substitution
# Default: security-rating

param.timeout = <integer>
# Request timeout in seconds
# Default: 30


# ============================================================================
# VARIABLE SUBSTITUTION
# ============================================================================
# The following variables can be used in supported alert action parameters
#
# TOP-LEVEL VARIABLES
#
# $name$
# Alert or saved search name
#
# $search_name$
# Saved search name
#
# $trigger_time$
# Time the alert was triggered
#
# $app$
# App context
#
# $owner$
# Alert owner
#
# $results_link$
# Link to view results in Splunk
#
# $result.count$
# Number of matching results
#
# RESULT VARIABLES
#
# $result.field_name$
# Any field from the alert result
#
# Common examples:
# $result.company_name$
# $result.company_guid$
# $result.rating$
# $result.rating_change$
# $result.severity$
# $result.risk_vector$
#
