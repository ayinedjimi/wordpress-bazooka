"""Password policy audit via registration form analysis."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class PasswordPolicyModule(BazookaModule):
    name = "vuln.password_policy"
    phase = "vuln"
    description = "Password policy audit via registration form analysis"
    profiles = ["standard", "aggressive"]

    def should_run(self, ctx: ScanContext) -> bool:
        """Only run if registration is detected as open."""
        return bool(ctx.data.get("registration_open"))

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        register_url = f"{base}/wp-login.php?action=register"

        has_strength_meter = False
        has_js_validation = False
        has_policy_indicators = False
        evidence_details: list[str] = []

        # ── Check 1: Fetch registration page and analyze HTML ────────────────
        try:
            resp = await session.get(register_url, use_cache=False)
            body = resp.text

            if resp.status_code != 200:
                # Registration page not accessible — might be redirected or blocked
                result.add_data("password_policy_status", "registration_page_inaccessible")
                return result

            body_lower = body.lower()

            # Check for WordPress password strength meter
            strength_meter_indicators = [
                "wp-admin/js/password-strength-meter",
                "password-strength-meter",
                "pw_weak",
                "pw_medium",
                "pw_strong",
                "pw_mismatch",
                "zxcvbn",  # WordPress uses zxcvbn library
                "wp.passwordStrength",
                "passwordStrength",
            ]
            for indicator in strength_meter_indicators:
                if indicator.lower() in body_lower:
                    has_strength_meter = True
                    evidence_details.append(f"Found strength meter indicator: '{indicator}'")
                    break

            # Check for JavaScript-based password validation
            js_validation_patterns = [
                r"password.*(?:min|minimum).*(?:length|len|char)",
                r"(?:min|minimum).*(?:length|len).*password",
                r"password.*\.length\s*[<>=!]+\s*\d+",
                r"validatePassword",
                r"checkPassword",
                r"password_policy",
                r"passwordPolicy",
                r"password.*requirement",
                r"(?:must|should).*contain.*(?:upper|lower|digit|special|number)",
            ]
            for pattern in js_validation_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    has_js_validation = True
                    evidence_details.append(f"Found JS validation pattern: '{pattern}'")
                    break

            # Check for inline password policy messages in HTML
            policy_html_patterns = [
                r"password.*must.*(?:be|contain|have|include)",
                r"(?:minimum|at least)\s+\d+\s*(?:character|char|letter|digit)",
                r"password.*(?:policy|requirements?|rules?|criteria)",
                r"(?:strong|complex)\s+password\s+(?:required|needed)",
                r"(?:uppercase|lowercase|number|special\s+character).*required",
            ]
            for pattern in policy_html_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    has_policy_indicators = True
                    evidence_details.append(f"Found policy HTML pattern: '{pattern}'")
                    break

        except Exception as e:
            evidence_details.append(f"Registration page fetch error: {e}")

        # ── Check 2: Look for password-related JS files in page ──────────────
        try:
            # Extract script sources from the registration page
            script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body)
            password_scripts_found = False
            for src in script_srcs:
                src_lower = src.lower()
                if any(kw in src_lower for kw in [
                    "password", "strength", "zxcvbn", "validate", "policy"
                ]):
                    password_scripts_found = True
                    evidence_details.append(f"Password-related script: {src}")
                    break

            if password_scripts_found:
                has_js_validation = True
        except Exception:
            pass

        # ── Check 3: Check response headers for security policy hints ────────
        try:
            csp = resp.headers.get("Content-Security-Policy", "")
            if csp:
                evidence_details.append(f"CSP header present (indirect security indicator)")
        except Exception:
            pass

        # ── Check 4: Test the registration endpoint behavior ─────────────────
        # Instead of actually registering, check if the form has any
        # client-side enforcement by examining the form structure
        try:
            # Look for password field attributes that indicate policy
            password_field_patterns = [
                r'<input[^>]*type=["\']password["\'][^>]*pattern=["\']([^"\']+)["\']',
                r'<input[^>]*type=["\']password["\'][^>]*minlength=["\'](\d+)["\']',
                r'<input[^>]*type=["\']password["\'][^>]*data-(?:min|policy|strength)[^>]*',
            ]
            for pattern in password_field_patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    has_policy_indicators = True
                    evidence_details.append(
                        f"Password field has enforcement attribute: {match.group(0)[:100]}"
                    )
                    break
        except Exception:
            pass

        # ── Aggregate results ────────────────────────────────────────────────
        has_any_policy = has_strength_meter or has_js_validation or has_policy_indicators

        result.add_data("password_policy", {
            "has_strength_meter": has_strength_meter,
            "has_js_validation": has_js_validation,
            "has_policy_indicators": has_policy_indicators,
            "evidence": evidence_details,
        })

        if not has_any_policy:
            result.add_finding(Finding(
                id="VULN-PASSWD-POLICY-001",
                title=f"No client-side password policy on registration for {ctx.target.domain}",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                confidence=Confidence.LIKELY,
                finding_type=FindingType.MISCONFIGURATION,
                description=(
                    "The WordPress registration page does not appear to enforce any "
                    "client-side password policy. No password strength meter (zxcvbn), "
                    "JavaScript validation, HTML5 pattern/minlength attributes, or "
                    "password requirement messages were detected. "
                    "While WordPress 4.3+ includes a password strength indicator on "
                    "the reset-password page, the registration page may not enforce "
                    "minimum strength."
                ),
                evidence=Evidence(
                    request=f"GET {register_url}",
                    response_status=resp.status_code if resp else 0,
                    response_headers={},
                    response_body_excerpt=(
                        "No password policy indicators found.\n"
                        f"Details: {'; '.join(evidence_details) or 'None'}"
                    ),
                ),
                impact=(
                    "Users can register with weak passwords (e.g., '123456', 'password'), "
                    "making accounts vulnerable to brute-force and credential stuffing attacks. "
                    "Without server-side enforcement, the site relies entirely on user behavior."
                ),
                remediation=(
                    "Implement server-side password policy enforcement using a plugin like "
                    "WPassword, Force Strong Passwords, or iThemes Security. Require minimum "
                    "12 characters with mixed case, digits, and special characters. WordPress "
                    "core's password strength meter alone is advisory and can be bypassed."
                ),
                compliance=Compliance(
                    owasp_2021="A07:2021 - Identification and Authentication Failures",
                    cwe="CWE-521",
                    pci_dss_v4="8.3.6 - Minimum password complexity",
                ),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                    "https://cwe.mitre.org/data/definitions/521.html",
                    "https://wordpress.org/plugins/wpassword/",
                ],
                phase="vuln",
                module=self.name,
                tags=["password-policy", "registration", "brute-force"],
            ))

        return result
