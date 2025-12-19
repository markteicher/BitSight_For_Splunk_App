#!/usr/bin/env python
# encoding: utf-8
"""
Bitsight Webhook Alert Action
Sends webhook notifications to external systems (Slack, Teams, PagerDuty, etc.)
"""

import sys
import os
import json
import re

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

try:
    import requests
except ImportError:
    # Fallback to urllib for environments without requests
    import urllib.request
    import urllib.error
    import ssl
    requests = None


def substitute_variables(template, payload):
    """Substitute $variable$ patterns with actual values from payload"""
    
    result = payload.get('result', {})
    
    substitutions = {
        'name': payload.get('search_name', ''),
        'search_name': payload.get('search_name', ''),
        'trigger_time': payload.get('trigger_time', ''),
        'app': payload.get('app', 'bitsight'),
        'owner': payload.get('owner', ''),
        'results_link': payload.get('results_link', ''),
        'result.count': str(len(payload.get('results', []))),
    }
    
    # Add all result fields
    for key, value in result.items():
        substitutions[f'result.{key}'] = str(value) if value else ''
    
    # Perform substitution
    def replace_var(match):
        var_name = match.group(1)
        return substitutions.get(var_name, '')
    
    return re.sub(r'\$([^$]+)\$', replace_var, template)


def send_webhook(config, payload):
    """Send webhook notification"""
    
    webhook_url = config.get('webhook_url', '')
    method = config.get('method', 'POST').upper()
    content_type = config.get('content_type', 'application/json')
    custom_headers = config.get('custom_headers', '')
    verify_ssl = config.get('verify_ssl', '1') == '1'
    timeout = int(config.get('timeout', 30))
    payload_template = config.get('payload_template', '{}')
    
    if not webhook_url:
        return False, "No webhook URL configured"
    
    # Build payload from template
    try:
        payload_str = substitute_variables(payload_template, payload)
        webhook_payload = json.loads(payload_str)
    except json.JSONDecodeError as e:
        return False, f"Invalid payload template JSON: {e}"
    
    # Parse custom headers
    headers = {'Content-Type': content_type}
    if custom_headers:
        for header in custom_headers.split('\n'):
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
    
    # Send request
    try:
        if requests:
            # Use requests library if available
            if method == 'POST':
                response = requests.post(
                    webhook_url,
                    json=webhook_payload,
                    headers=headers,
                    verify=verify_ssl,
                    timeout=timeout
                )
            elif method == 'PUT':
                response = requests.put(
                    webhook_url,
                    json=webhook_payload,
                    headers=headers,
                    verify=verify_ssl,
                    timeout=timeout
                )
            else:
                return False, f"Unsupported HTTP method: {method}"
            
            if response.status_code >= 400:
                return False, f"Webhook returned status {response.status_code}: {response.text}"
            
            return True, f"Webhook sent successfully (status {response.status_code})"
        else:
            # Fallback to urllib
            data = json.dumps(webhook_payload).encode('utf-8')
            req = urllib.request.Request(webhook_url, data=data, headers=headers, method=method)
            
            context = None
            if not verify_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
                status = response.getcode()
                if status >= 400:
                    return False, f"Webhook returned status {status}"
                return True, f"Webhook sent successfully (status {status})"
    
    except Exception as e:
        return False, f"Webhook request failed: {str(e)}"


def main():
    """Main entry point for alert action"""
    
    if len(sys.argv) < 2:
        print("ERROR: No payload file provided", file=sys.stderr)
        sys.exit(1)
    
    payload_file = sys.argv[1]
    
    try:
        with open(payload_file, 'r') as f:
            payload = json.load(f)
    except Exception as e:
        print(f"ERROR: Failed to read payload: {e}", file=sys.stderr)
        sys.exit(1)
    
    config = payload.get('configuration', {})
    
    success, message = send_webhook(config, payload)
    
    if success:
        print(f"INFO: {message}")
        sys.exit(0)
    else:
        print(f"ERROR: {message}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
