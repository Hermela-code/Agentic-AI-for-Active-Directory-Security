"""
NetExec Wrapper
Component: Tool Integration


Shells out to the real `nxc` (NetExec) CLI binary. Two distinct approval
levels per scenarios.md's Human Approval & Safety table:

  - smb_enum() is passive banner-grab enumeration (no creds) -> Observation,
    runs autonomously.
  - check_admin_access() validates supplied credentials against a target
    and reports admin status -> this is a Controlled Validation action and
    MUST be gated behind human approval upstream (Hermela's agent /
    Wintana's backend's /approvals flow) before this function is ever
    called. This wrapper does not enforce that gate itself - it trusts the
    caller already has sign-off, exactly like finding_rules.py's
    `requires_approval` flag on a SecurityFinding is meant to be checked
    by the agent before the corresponding validation_action runs.
"""

import logging
import re
import shutil
import subprocess
from typing import List, Optional

from tools.models import AdminCheckResult, ToolExecutionResult
from tools.scope_guard import OutOfScopeError, assert_in_scope

logger = logging.getLogger("ad_tools.netexec")

DEFAULT_TIMEOUT_SECONDS = 30
PWN3D_MARKER = "(Pwn3d!)"


def _nxc_binary_available() -> bool:
    return shutil.which("nxc") is not None


def _run_nxc(args: List[str], timeout_seconds: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["nxc", *args], capture_output=True, text=True, timeout=timeout_seconds, check=False
    )


def smb_enum(target: str, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> ToolExecutionResult:
    """
    Unauthenticated `nxc smb <target>` banner grab: OS version, hostname,
    domain name, signing status. No credentials involved - read-only
    Observation level.
    """
    command_str = f"nxc smb {target}"

    try:
        resolved_ip = assert_in_scope(target)
    except OutOfScopeError as exc:
        return ToolExecutionResult(
            tool_name="netexec", command=command_str, output="", status="error", error=str(exc)
        )

    if not _nxc_binary_available():
        return ToolExecutionResult(
            tool_name="netexec", command=command_str, output="", status="error",
            error="nxc binary not found on PATH. Install with: pipx install netexec",
        )

    try:
        proc = _run_nxc(["smb", resolved_ip], timeout_seconds)
    except subprocess.TimeoutExpired:
        return ToolExecutionResult(
            tool_name="netexec", command=command_str, output="", status="timeout",
            error=f"nxc smb exceeded {timeout_seconds}s timeout",
        )
    except OSError as exc:
        return ToolExecutionResult(
            tool_name="netexec", command=command_str, output="", status="error", error=str(exc)
        )

    if proc.returncode != 0 and not proc.stdout.strip():
        return ToolExecutionResult(
            tool_name="netexec", command=command_str, output=proc.stdout, status="error",
            error=proc.stderr.strip() or f"nxc exited with code {proc.returncode}",
        )

    return ToolExecutionResult(
        tool_name="netexec", command=command_str, output=proc.stdout.strip(), status="success",
    )


def check_admin_access(
    target: str,
    username: str,
    password: str,
    domain: Optional[str] = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> AdminCheckResult:
    """
    Controlled Validation action: tests whether the given credentials have
    local admin rights on `target` via `nxc smb`. The "(Pwn3d!)" marker in
    NetExec's output means SMB admin access was confirmed - this is the
    exact raw signal the project overview's example ("Pwn3d!") describes
    translating into a plain-language explanation.

    IMPORTANT: Callers (the agent) must only invoke this after the
    corresponding approval has been granted via POST
    /approvals/{id}/approve. This function does not check approval state
    itself.
    """
    command_str = f"nxc smb {target} -u {username} -p '***' " + (f"-d {domain} " if domain else "") + "--shares"

    try:
        resolved_ip = assert_in_scope(target)
    except OutOfScopeError as exc:
        return AdminCheckResult(
            tool_name="netexec", command=command_str, output="", status="error", error=str(exc),
            target=target, username=username,
        )

    if not _nxc_binary_available():
        return AdminCheckResult(
            tool_name="netexec", command=command_str, output="", status="error",
            error="nxc binary not found on PATH. Install with: pipx install netexec",
            target=target, username=username,
        )

    args = ["smb", resolved_ip, "-u", username, "-p", password, "--shares"]
    if domain:
        args.extend(["-d", domain])

    try:
        proc = _run_nxc(args, timeout_seconds)
    except subprocess.TimeoutExpired:
        return AdminCheckResult(
            tool_name="netexec", command=command_str, output="", status="timeout",
            error=f"nxc smb exceeded {timeout_seconds}s timeout",
            target=target, username=username,
        )
    except OSError as exc:
        return AdminCheckResult(
            tool_name="netexec", command=command_str, output="", status="error", error=str(exc),
            target=target, username=username,
        )

    # Redact the raw output of any accidental credential echo before storing/logging it,
    # consistent with SETUP.md rule #7 ("never expose credentials... in findings or logs").
    sanitized_output = proc.stdout.replace(password, "***")

    is_admin = PWN3D_MARKER in proc.stdout
    shares = _parse_shares(proc.stdout)

    return AdminCheckResult(
        tool_name="netexec",
        command=command_str,
        output=sanitized_output.strip(),
        status="success" if proc.returncode == 0 or proc.stdout.strip() else "error",
        error=None if proc.returncode == 0 else (proc.stderr.strip() or None),
        target=target,
        username=username,
        is_admin=is_admin,
        shares=shares,
    )


def _parse_shares(output: str) -> List[str]:
    """Pulls share names out of nxc's --shares table output, e.g. 'SYSVOL   READ' -> 'SYSVOL'."""
    shares = []
    for line in output.splitlines():
        match = re.search(r"^\S+\s+\S+\s+(\S+)\s+(READ|WRITE|READ,WRITE)", line)
        if match:
            shares.append(match.group(1))
    return shares
