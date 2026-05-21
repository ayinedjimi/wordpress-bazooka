"""User enumeration via timing attack on wp-login.php."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class UserEnumTimingModule(BazookaModule):
    name = "vuln.user_enum_timing"
    phase = "vuln"
    description = "User enumeration via timing attack on wp-login.php"
    profiles = ["aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        login_url = f"{base}/wp-login.php"

        # Determine a valid username to test against
        valid_username = "admin"
        if ctx.target.users:
            valid_username = ctx.target.users[0].username or ctx.target.users[0].slug or "admin"

        invalid_username = "bz_nonexistent_user_9999"
        fake_password = "bz_wrong_password_timing_test_12345"

        iterations = 3
        valid_times: list[float] = []
        invalid_times: list[float] = []

        for _ in range(iterations):
            # Time request with valid username
            t0 = time.monotonic()
            try:
                await session.post(
                    login_url,
                    data={
                        "log": valid_username,
                        "pwd": fake_password,
                        "wp-submit": "Log In",
                        "redirect_to": f"{base}/wp-admin/",
                        "testcookie": "1",
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    follow_redirects=False,
                )
            except Exception:
                pass
            valid_times.append(time.monotonic() - t0)

            # Time request with invalid username
            t0 = time.monotonic()
            try:
                await session.post(
                    login_url,
                    data={
                        "log": invalid_username,
                        "pwd": fake_password,
                        "wp-submit": "Log In",
                        "redirect_to": f"{base}/wp-admin/",
                        "testcookie": "1",
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    follow_redirects=False,
                )
            except Exception:
                pass
            invalid_times.append(time.monotonic() - t0)

        if not valid_times or not invalid_times:
            return result

        avg_valid = sum(valid_times) / len(valid_times)
        avg_invalid = sum(invalid_times) / len(invalid_times)
        time_diff = avg_valid - avg_invalid

        # Store timing data for other modules
        result.add_data("user_enum_timing", {
            "valid_username": valid_username,
            "avg_valid_time": round(avg_valid, 4),
            "avg_invalid_time": round(avg_invalid, 4),
            "time_diff": round(time_diff, 4),
            "valid_times": [round(t, 4) for t in valid_times],
            "invalid_times": [round(t, 4) for t in invalid_times],
        })

        # If valid user consistently takes >0.3s longer, timing-based enumeration is confirmed
        # Also check that each individual pair shows the pattern (consistency check)
        consistent = all(
            valid_times[i] > invalid_times[i] + 0.15
            for i in range(min(len(valid_times), len(invalid_times)))
        )

        if time_diff > 0.3 and consistent:
            result.add_finding(Finding(
                id="VULN-TIMING-ENUM-001",
                title=f"User enumeration via timing attack on {ctx.target.domain}",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.DESIGN_FLAW,
                description=(
                    f"wp-login.php reveals valid usernames through response time differences. "
                    f"Login attempts with the valid username '{valid_username}' take an average of "
                    f"{avg_valid:.3f}s, while the non-existent user '{invalid_username}' averages "
                    f"{avg_invalid:.3f}s (delta: {time_diff:.3f}s over {iterations} iterations). "
                    f"WordPress performs password hashing (phpass/bcrypt) only when the username "
                    f"exists, creating a measurable timing side-channel."
                ),
                evidence=Evidence(
                    request=f"POST {login_url}\nlog={valid_username}&pwd=<redacted>",
                    response_status=200,
                    response_headers={},
                    response_body_excerpt=(
                        f"Valid user avg: {avg_valid:.4f}s ({valid_times})\n"
                        f"Invalid user avg: {avg_invalid:.4f}s ({invalid_times})\n"
                        f"Consistent delta: {time_diff:.4f}s"
                    ),
                ),
                impact=(
                    "Attackers can enumerate valid usernames without rate limiting detection. "
                    "Combined with password spraying or credential stuffing, this enables "
                    "targeted brute-force attacks against confirmed accounts."
                ),
                remediation=(
                    "Implement constant-time comparison for login failures regardless of username "
                    "validity. Perform a dummy password hash when the user does not exist. "
                    "Consider plugins like WP Cerber or Limit Login Attempts Reloaded that add "
                    "uniform delays to all login responses."
                ),
                compliance=Compliance(
                    owasp_2021="A07:2021 - Identification and Authentication Failures",
                    cwe="CWE-208",
                    mitre_attack="T1110.001 - Brute Force: Password Guessing",
                ),
                references=[
                    "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
                    "https://cwe.mitre.org/data/definitions/208.html",
                ],
                phase="vuln",
                module=self.name,
                tags=["timing", "user-enumeration", "brute-force", "login"],
            ))

        return result
