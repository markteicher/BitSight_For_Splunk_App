#!/usr/bin/env python
# encoding: utf-8
"""
Bitsight Email Alert Action
Sends email notifications for Bitsight security rating alerts
"""

import sys
import os
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

def send_email(config, payload):
    """Send email notification"""
    
    # Get configuration
    to_addresses = config.get('to', '').split(',')
    cc_addresses = config.get('cc', '').split(',') if config.get('cc') else []
    subject = config.get('subject', 'Bitsight Alert')
    message_body = config.get('message', '')
    priority = config.get('priority', 'normal')
    include_results = config.get('include_results', '1') == '1'
    include_link = config.get('include_link', '1') == '1'
    
    # Get SMTP settings from Splunk
    smtp_server = config.get('smtp_server', 'localhost')
    smtp_port = int(config.get('smtp_port', 25))
    smtp_use_tls = config.get('smtp_use_tls', '0') == '1'
    smtp_user = config.get('smtp_user', '')
    smtp_password = config.get('smtp_password', '')
    from_address = config.get('from_address', 'splunk@localhost')
    
    # Build email
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = from_address
    msg['To'] = ', '.join(to_addresses)
    if cc_addresses:
        msg['Cc'] = ', '.join(cc_addresses)
    
    # Set priority header
    if priority == 'high':
        msg['X-Priority'] = '1'
        msg['Importance'] = 'high'
    elif priority == 'low':
        msg['X-Priority'] = '5'
        msg['Importance'] = 'low'
    
    # Build message body
    html_body = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; }}
            .alert-header {{ background-color: #d9534f; color: white; padding: 15px; }}
            .alert-body {{ padding: 15px; background-color: #f5f5f5; }}
            .results-table {{ border-collapse: collapse; width: 100%; }}
            .results-table th, .results-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            .results-table th {{ background-color: #4a4a4a; color: white; }}
            .rating-good {{ color: #5cb85c; }}
            .rating-fair {{ color: #f0ad4e; }}
            .rating-poor {{ color: #d9534f; }}
        </style>
    </head>
    <body>
        <div class="alert-header">
            <h2>🔒 Bitsight Security Alert</h2>
        </div>
        <div class="alert-body">
            <p>{message_body.replace(chr(10), '<br>')}</p>
    """
    
    # Add results if configured
    if include_results and payload.get('result'):
        result = payload['result']
        html_body += """
            <h3>Alert Details</h3>
            <table class="results-table">
        """
        for key, value in result.items():
            if not key.startswith('_'):
                html_body += f"<tr><th>{key}</th><td>{value}</td></tr>"
        html_body += "</table>"
    
    # Add results link if configured
    if include_link and payload.get('results_link'):
        html_body += f"""
            <p><a href="{payload['results_link']}">View Results in Splunk</a></p>
        """
    
    html_body += """
        </div>
    </body>
    </html>
    """
    
    # Attach HTML body
    msg.attach(MIMEText(message_body, 'plain'))
    msg.attach(MIMEText(html_body, 'html'))
    
    # Send email
    try:
        if smtp_use_tls:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
        else:
            server = smtplib.SMTP(smtp_server, smtp_port)
        
        if smtp_user and smtp_password:
            server.login(smtp_user, smtp_password)
        
        all_recipients = to_addresses + cc_addresses
        server.sendmail(from_address, all_recipients, msg.as_string())
        server.quit()
        
        return True, "Email sent successfully"
    except Exception as e:
        return False, str(e)


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
    
    success, message = send_email(config, payload)
    
    if success:
        print(f"INFO: {message}")
        sys.exit(0)
    else:
        print(f"ERROR: {message}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
