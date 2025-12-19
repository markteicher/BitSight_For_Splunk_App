#
# Bitsight Alert Actions Configuration Specification
# Use this file as a reference for configuring alert actions
#

# ============================================================================
# EMAIL ALERT ACTION
# ============================================================================
[bitsight_email_alert]
param.to = <string>
* Required. Comma-separated list of email addresses to send alerts to.

param.cc = <string>
* Optional. Comma-separated list of CC email addresses.

param.subject = <string>
* Email subject line. Supports variable substitution.
* Default: [Bitsight Alert] $name$

param.message = <string>
* Email body message. Supports variable substitution.

param.include_results = <bool>
* Whether to include search results in the email.
* Default: 1

param.include_link = <bool>
* Whether to include a link to results in Splunk.
* Default: 1

param.priority = <string>
* Email priority: low, normal, high
* Default: normal

# ============================================================================
# WEBHOOK ALERT ACTION
# ============================================================================
[bitsight_webhook_alert]
param.webhook_url = <string>
* Required. The webhook URL to send notifications to.
* Examples:
*   Slack: https://hooks.slack.com/services/xxx/yyy/zzz
*   Teams: https://outlook.office.com/webhook/xxx
*   Custom: https://your-api.example.com/webhook

param.method = <string>
* HTTP method to use: POST, PUT
* Default: POST

param.content_type = <string>
* Content-Type header value.
* Default: application/json

param.payload_template = <string>
* JSON template for the webhook payload. Supports variable substitution.
* Variables: $name$, $trigger_time$, $result.count$, $result.field_name$
* Default: {"alert_name": "$name$", "trigger_time": "$trigger_time$"}

param.custom_headers = <string>
* Custom HTTP headers, one per line in format: Header-Name: value

param.verify_ssl = <bool>
* Whether to verify SSL certificates.
* Default: 1

param.timeout = <integer>
* Request timeout in seconds.
* Default: 30

# ============================================================================
# SCRIPT ALERT ACTION
# ============================================================================
[bitsight_script_alert]
param.script_name = <string>
* Required. Name of the script to execute (must be in bin/ directory).
* Default: bitsight_alert_script.py

param.script_args = <string>
* Optional. Additional arguments to pass to the script.

param.pass_payload = <bool>
* Whether to pass the alert payload to the script as a JSON file.
* Default: 1

# ============================================================================
# SERVICENOW ALERT ACTION
# ============================================================================
[bitsight_snow_alert]
param.snow_url = <string>
* Required. ServiceNow instance URL (e.g., https://instance.service-now.com)

param.snow_user = <string>
* Required. ServiceNow username for API access.

param.snow_password = <string>
* Required. ServiceNow password for API access.

param.incident_category = <string>
* Incident category.
* Default: Security

param.incident_subcategory = <string>
* Incident subcategory.
* Default: Vendor Risk

param.incident_priority = <integer>
* Incident priority (1-5).
* Default: 3

param.incident_short_description = <string>
* Short description for the incident. Supports variable substitution.

param.incident_description = <string>
* Full description for the incident. Supports variable substitution.

# ============================================================================
# PAGERDUTY ALERT ACTION
# ============================================================================
[bitsight_pagerduty_alert]
param.routing_key = <string>
* Required. PagerDuty Events API v2 routing key (integration key).

param.severity = <string>
* Event severity: critical, error, warning, info
* Default: error

param.dedup_key = <string>
* Deduplication key for grouping related events. Supports variable substitution.
* Default: bitsight-$result.company_guid$-$result.risk_vector$

param.event_action = <string>
* Event action: trigger, acknowledge, resolve
* Default: trigger

param.summary = <string>
* Event summary. Supports variable substitution.
* Default: Bitsight Alert: $result.company_name$ - $name$

param.source = <string>
* Event source identifier.
* Default: Splunk Bitsight App

param.component = <string>
* Affected component. Supports variable substitution.

param.group = <string>
* Logical grouping.
* Default: vendor-risk

param.class = <string>
* Event class.
* Default: security-rating

# ============================================================================
# VARIABLE SUBSTITUTION
# ============================================================================
# The following variables can be used in alert action parameters:
#
# Alert Variables:
#   $name$           - Alert/saved search name
#   $search_name$    - Saved search name
#   $trigger_time$   - Time the alert was triggered
#   $app$            - App context (bitsight)
#   $owner$          - Alert owner
#   $results_link$   - Link to view results in Splunk
#   $result.count$   - Number of matching results
#
# Result Variables (from search results):
#   $result.field_name$  - Any field from the search results
#   $result.company_name$ - Company name
#   $result.company_guid$ - Company GUID
#   $result.rating$       - Security rating
#   $result.rating_change$ - Rating change
#   $result.severity$     - Alert severity
#   $result.risk_vector$  - Risk vector name
