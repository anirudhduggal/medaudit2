# Medaudit HL7 Fuzzer - Safety Guardrails
# Bounds the "blast radius" of fuzzing campaigns against medical devices.

"""
Fuzzer safety guardrails.

The fuzzer deliberately sends malformed and malicious HL7 traffic at high
volume. Pointed at the wrong host (a typo, or a production device instead of a
lab unit) or turned up too high, it can crash or DoS fragile medical equipment
-- a patient-safety event, not just downtime. These guards make the dangerous
action require deliberate intent and cap the throughput:

  * Loopback targets (localhost / 127.0.0.1 / ::1) are treated as safe lab
    targets and run with no confirmation and no extra rate limiting.
  * Any non-loopback target must be explicitly authorized by the operator
    ("I am authorized to test <host>"), otherwise the campaign is refused.
  * Regardless of target, the total message count is capped, and remote targets
    get a minimum inter-message delay so a config can't accidentally flood a
    device.

All thresholds are overridable via environment variables for authorized lab
work that genuinely needs higher volume.
"""

import ipaddress
import logging
import os

logger = logging.getLogger(__name__)

# Hard ceiling on messages per campaign (protects memory and the target).
MAX_REQUESTS_CEILING = int(os.environ.get("MEDAUDIT_FUZZ_MAX_REQUESTS", "5000"))

# Minimum delay (ms) between messages for NON-loopback targets, i.e. an upper
# bound on send rate. Loopback keeps whatever the config asks for.
MIN_REMOTE_DELAY_MS = int(os.environ.get("MEDAUDIT_FUZZ_MIN_DELAY_MS", "20"))

# Hostnames we treat as loopback without a DNS lookup.
_LOOPBACK_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}


class TargetNotAuthorized(Exception):
    """Raised when a non-loopback target is fuzzed without explicit authorization."""


def is_loopback_target(host: str) -> bool:
    """
    True only if `host` is unambiguously loopback.

    We deliberately do NOT resolve hostnames via DNS: an unknown hostname is
    treated as non-loopback (the safer default), so it requires authorization.
    """
    if not host:
        return False
    h = host.strip().lower()
    if h in _LOOPBACK_HOSTNAMES:
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        # Not an IP literal (a hostname) -- treat as remote / needs auth.
        return False


def check_authorization(host: str, authorized: bool) -> None:
    """
    Raise TargetNotAuthorized unless the target is loopback or explicitly
    authorized by the operator.
    """
    if is_loopback_target(host):
        return
    if not authorized:
        raise TargetNotAuthorized(
            f"Refusing to fuzz non-loopback target '{host}' without explicit "
            f"authorization. This tool sends malformed traffic that can crash or "
            f"disrupt live medical devices. Confirm you are authorized to test "
            f"this host before proceeding."
        )


def apply_limits(max_requests: int, delay_ms: int, host: str):
    """
    Clamp campaign volume and send rate to safe bounds.

    Returns (effective_max_requests, effective_delay_ms, notes) where `notes` is
    a list of human-readable strings describing any clamping that occurred (for
    logging / surfacing to the operator).
    """
    notes = []

    effective_max = max_requests
    if effective_max > MAX_REQUESTS_CEILING:
        notes.append(
            f"max_requests reduced {max_requests} -> {MAX_REQUESTS_CEILING} "
            f"(safety ceiling; override with MEDAUDIT_FUZZ_MAX_REQUESTS)"
        )
        effective_max = MAX_REQUESTS_CEILING

    effective_delay = delay_ms
    if not is_loopback_target(host) and effective_delay < MIN_REMOTE_DELAY_MS:
        notes.append(
            f"delay_ms raised {delay_ms} -> {MIN_REMOTE_DELAY_MS} for remote "
            f"target (rate cap; override with MEDAUDIT_FUZZ_MIN_DELAY_MS)"
        )
        effective_delay = MIN_REMOTE_DELAY_MS

    for note in notes:
        logger.warning("Fuzzer safety: %s", note)

    return effective_max, effective_delay, notes
