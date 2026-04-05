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
- BitSight app file logging

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

APP LOG PATH MODEL

creates app-relative directory
var/log

creates app-relative file
var/log/bitsight.log

DEPENDENCIES

datetime
json
os
shlex
subprocess
sys
tempfile

=============================================================================
"""

import datetime
import json
import os
import shlex
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

DEFAULT_TIMEOUT = 300
APP_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
APP_LOG_DIR = os.path.join(APP_ROOT, "var", "log")
APP_LOG_FILE = os.path.join(APP_LOG_DIR, "bitsight.log")
COMPONENT_NAME = "bitsight_script_alert.py"


def ensure_bitsight_log_file() -> str:
    os.makedirs(APP_LOG_DIR, exist_ok=True)

    if not os.path.exists(APP_LOG_FILE):
        with open(APP_LOG_FILE, "a", encoding="utf-8"):
            pass

    return APP_LOG_FILE


def write_app_log(level: str, message: str) -> None:
    try:
        ensure_bitsight_log_file()
        timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        safe_message = str(message).replace("\n", " ").replace("\r", " ").strip()

        with open(APP_LOG_FILE, "a", encoding="utf-8") as handle:
            handle.write(
                f"{timestamp} level={str(level).upper()} component={COMPONENT_NAME} message={safe_message}\n"
            )
    except Exception:
        pass


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
        write_app_log("ERROR", "Script alert action failed: no script name configured")
        return False, "No script name configured"

    bin_dir = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(bin_dir, script_name)

    if not os.path.isfile(script_path):
        write_app_log("ERROR", f"Script alert action failed: script not found path={script_path}")
        return False, f"Script not found: {script_path}"

    cmd = _build_command(script_path, script_args)
    payload_file: Optional[str] = None

    write_app_log(
        "INFO",
        (
            "Script alert action starting "
            f"script_name={script_name} "
            f"pass_payload={pass_payload} "
            f"timeout={timeout}"
        ),
    )

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
            write_app_log(
                "INFO",
                f"Script alert action created temporary payload file path={payload_file}",
            )

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
                write_app_log(
                    "ERROR",
                    (
                        "Script alert action failed "
                        f"script_name={script_name} "
                        f"returncode={result.returncode} "
                        f"stderr={stderr_text}"
                    ),
                )
                return False, f"Script exited with code {result.returncode}: {stderr_text}"

            write_app_log(
                "ERROR",
                (
                    "Script alert action failed "
                    f"script_name={script_name} "
                    f"returncode={result.returncode}"
                ),
            )
            return False, f"Script exited with code {result.returncode}"

        if stdout_text:
            write_app_log(
                "INFO",
                (
                    "Script alert action completed successfully "
                    f"script_name={script_name} "
                    f"stdout={stdout_text}"
                ),
            )
            return True, f"Script executed successfully: {stdout_text}"

        write_app_log(
            "INFO",
            f"Script alert action completed successfully script_name={script_name}",
        )
        return True, "Script executed successfully"

    except subprocess.TimeoutExpired:
        write_app_log(
            "ERROR",
            f"Script alert action timed out script_name={script_name} timeout={timeout}",
        )
        return False, "Script execution timed out"
    except Exception as e:
        write_app_log(
            "ERROR",
            f"Script alert action failed script_name={script_name} error={str(e)}",
        )
        return False, f"Script execution failed: {str(e)}"
    finally:
        if payload_file and os.path.exists(payload_file):
            try:
                os.remove(payload_file)
                write_app_log(
                    "INFO",
                    f"Script alert action removed temporary payload file path={payload_file}",
                )
            except OSError:
                write_app_log(
                    "WARNING",
                    f"Script alert action could not remove temporary payload file path={payload_file}",
                )


def main() -> None:
    """Main entry point for alert action."""

    ensure_bitsight_log_file()

    if len(sys.argv) < 2:
        write_app_log("ERROR", "Script alert action failed: no payload file provided")
        print("ERROR: No payload file provided", file=sys.stderr)
        sys.exit(1)

    payload_file = sys.argv[1]
    write_app_log("INFO", f"Script alert action invoked payload_file={payload_file}")

    try:
        with open(payload_file, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception as e:
        write_app_log("ERROR", f"Failed to read script alert payload error={e}")
        print(f"ERROR: Failed to read payload: {e}", file=sys.stderr)
        sys.exit(1)

    config = payload.get("configuration", {})
    if not isinstance(config, dict):
        write_app_log("ERROR", "Script alert action failed: invalid configuration payload")
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
