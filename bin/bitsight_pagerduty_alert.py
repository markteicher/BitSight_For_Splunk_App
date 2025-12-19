#!/usr/bin/env python
# encoding: utf-8
"""
Bitsight PagerDuty Alert Action
Triggers PagerDuty incidents for critical Bitsight alerts
"""

import sys
import os
import json
import re

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

try:
    import requests
except ImportError:
    import urllib.request
    import urllib.error
    requests = None

PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"


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
    }
    
    # Add all result fields
    for key, value in result.items():
        substitutions[f'result.{key}'] = str(value) if value else ''
    
    def replace_var(match):
        var_name = match.group(1)
        return substitutions.get(var_name, match.group(0))
    
    return re.sub(r'\$([^$]+)\$', replace_var, template)


def send_pagerduty_event(config, payload):
    """Send PagerDuty event"""
    
    routing_key = config.get('routing_key', '')
    severity = config.get('severity', 'error')
    dedup_key = config.get('dedup_key', '')
    event_action = config.get('event_action', 'trigger')
    summary = config.get('summary', 'Bitsight Alert')
    source = config.get('source', 'Splunk Bitsight App')
    component = config.get('component', '')
    group = config.get('group', 'vendor-risk')
    event_class = config.get('class', 'security-rating')
    
    if not routing_key:
        return False, "No PagerDuty routing key configured"
    
    # Substitute variables
    summary = substitute_variables(summary, payload)
    dedup_key = substitute_variables(dedup_key, payload)
    component = substitute_variables(component, payload)
    
    # Build PagerDuty event payload
    pd_payload = {
        "routing_key": routing_key,
        "event_action": event_action,
        "dedup_key": dedup_key if dedup_key else None,
        "payload": {
            "summary": summary,
            "severity": severity,
            "source": source,
            "component": component if component else None,
            "group": group,
            "class": event_class,
            "custom_details": {
                "search_name": payload.get('search_name', ''),
                "trigger_time": payload.get('trigger_time', ''),
                "results_link": payload.get('results_link', ''),
                "result": payload.get('result', {})
            }
        }
    }
    
    # Remove None values
    pd_payload = {k: v for k, v in pd_payload.items() if v is not None}
    pd_payload['payload'] = {k: v for k, v in pd_payload['payload'].items() if v is not None}
    
    # Send to PagerDuty
    headers = {'Content-Type': 'application/json'}
    
    try:
        if requests:
            response = requests.post(
                PAGERDUTY_EVENTS_URL,
                json=pd_payload,
                headers=headers,
                timeout=30
            )
            
            if response.status_code >= 400:
                return False, f"PagerDuty returned status {response.status_code}: {response.text}"
            
            result = response.json()
            return True, f"PagerDuty event created: {result.get('dedup_key', 'unknown')}"
        else:
            data = json.dumps(pd_payload).encode('utf-8')
            req = urllib.request.Request(PAGERDUTY_EVENTS_URL, data=data, headers=headers)
            
            with urllib.request.urlopen(req, timeout=30) as response:
                status = response.getcode()
                if status >= 400:
                    return False, f"PagerDuty returned status {status}"
                result = json.loads(response.read().decode('utf-8'))
                return True, f"PagerDuty event created: {result.get('dedup_key', 'unknown')}"
    
    except Exception as e:
        return False, f"PagerDuty request failed: {str(e)}"


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
    
    success, message = send_pagerduty_event(config, payload)
    
    if success:
        print(f"INFO: {message}")
        sys.exit(0)
    else:
        print(f"ERROR: {message}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
