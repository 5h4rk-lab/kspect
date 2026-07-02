# Security policy

## Reporting a vulnerability

Report vulnerabilities in kspect privately via GitHub Security Advisories
("Report a vulnerability" on the Security tab) rather than public issues.
You will receive an acknowledgment within 72 hours and a remediation plan
or assessment within 14 days. Coordinated disclosure is appreciated;
reporters are credited in release notes unless they prefer otherwise.

## Scope

In scope: anything that makes kspect misreport posture (false pass),
execute unintended actions (it must be strictly read-only), mishandle
hostile kernel-interface content, or escalate privilege.

Out of scope: findings on hosts kspect audits (that's the tool working),
and attacks requiring a kernel-level compromise of the audited host —
a kernel-resident attacker can lie to any on-host auditor (see
docs/THREAT_MODEL.md).

## Supported versions

The latest minor release receives security fixes.
