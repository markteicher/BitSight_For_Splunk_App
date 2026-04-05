#!/usr/bin/env python3
# encoding: utf-8

"""
=============================================================================
 bin/bitsight_script_alert.py
 BitSight for Splunk App
 Script Alert Action
=============================================================================

PURPOSE

Executes a custom script for BitSight alerts.

Builds a command line from the Splunk alert action payload and
configuration.

Supports:

- configured script execution
- optional script arguments
- optional payload file passing
- temporary payload file creation
- script timeout handling
- stdout and stderr capture
- execution status reporting

FILE LOCATION

App-relative path
bin/bitsight_script_alert.py

SCRIPT TYPE

Custom Splunk alert action script

EXECUTION MODEL

Invoked by Splunk alert actions
expects payload file path as argv[1]

GRANULAR DOCUMENTATION SPECIFICATION

INPUT SOURCE

Splunk alert action payload JSON file

PAYLOAD REQUIREMENT

argv[1]
payload file path

PAYLOAD SECTIONS USED

configuration

CONFIGURATION FIELDS

script_name
script_args
pass_payload
timeout

SCRIPT RESOLUTION MODEL

script_name
resolved relative to the app bin directory

PAYLOAD PASSING MODEL

If pass_payload is enabled
writes payload JSON to a temporary file
appends temporary payload file path to the command line

OUTPUT BEHAVIOR

stdout
INFO message on success

stderr
ERROR message on failure

EXIT CODES

0
success

1
failure

EXECUTION TIMEOUT

default
300 seconds

DEPENDENCIES

json
os
shlex
subprocess
sys
tempfile

=============================================================================
"""

import json
import os
import shlex
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

DEFAULT_TIMEOUT = 300


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _clean_string(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _build_command(script_path: str, script_args: str) -> List[str]:
    command: List[str] = [sys.executable, script_path]

    if script_args:
        command.extend(shlex.split(script_args))

    return command


def execute_script(config: Dict[str, Any], payload: Dict[str, Any]) -> Tuple[bool, str]:
    """Execute custom script with alert payload."""

    script_name = _clean_string(config.get("script_name"))
    script_args = _clean_string(config.get("script_args"))
    pass_payload = _as_bool(config.get("pass_payload"), True)
    timeout = int(config.get("timeout", DEFAULT_TIMEOUT) or DEFAULT_TIMEOUT)

    if not script_name:
        return False, "No script name configured"

    bin_dir = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(bin_dir, script_name)

    if not os.path.isfile(script_path):
        return False, f"Script not found: {script_path}"

    cmd = _build_command(script_path, script_args)
    payload_file: Optional[str] = None

    try:
        if pass_payload:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".json",
                delete=False,
                encoding="utf-8",
            ) as f:
                json.dump(payload, f, ensure_ascii=False)
                payload_file = f.name
            cmd.append(payload_file)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        stdout_text = (result.stdout or "").strip()
        stderr_text = (result.stderr or "").strip()

        if result.returncode != 0:
            if stderr_text:
                return False, f"Script exited with code {result.returncode}: {stderr_text}"
            return False, f"Script exited with code {result.returncode}"

        if stdout_text:
            return True, f"Script executed successfully: {stdout_text}"

        return True, "Script executed successfully"

    except subprocess.TimeoutExpired:
        return False, "Script execution timed out"
    except Exception as e:
        return False, f"Script execution failed: {str(e)}"
    finally:
        if payload_file and os.path.exists(payload_file):
            try:
                os.remove(payload_file)
            except OSError:
                pass


def main() -> None:
    """Main entry point for alert action."""

    if len(sys.argv) < 2:
        print("ERROR: No payload file provided", file=sys.stderr)
        sys.exit(1)

    payload_file = sys.argv[1]

    try:
        with open(payload_file, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception as e:
        print(f"ERROR: Failed to read payload: {e}", file=sys.stderr)
        sys.exit(1)

    config = payload.get("configuration", {})
    if not isinstance(config, dict):
        print("ERROR: Invalid configuration payload", file=sys.stderr)
        sys.exit(1)

    success, message = execute_script(config, payload)

    if success:
        print(f"INFO: {message}")
        sys.exit(0)

    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
