# Technical Assessment Report — BodgeIt Web Application Penetration Test

---

## 1. Engagement Overview and Security Architecture

In an era defined by increasingly sophisticated persistent threats, maintaining the security integrity of the BodgeIt store is a strategic necessity rather than a mere technical requirement. This assessment was conducted as a proactive security measure to identify exploitable weaknesses before they can be leveraged for financial loss, operational disruption, or reputational damage.

By simulating realistic adversary behavior, this penetration test provides a practical remediation roadmap that supports business continuity, customer trust, and secure application operations. The engagement focused on identifying weaknesses across the exposed application surface and validating real exploitation paths.

The assessment followed structured security testing practices aligned with:

* NIST SP 800-115 Technical Guide to Information Security Testing and Assessment
* OWASP Testing Guide methodology

This ensured a repeatable, evidence-driven, and systematic approach across planning, discovery, attack, and reporting phases.

### Assessment Parameters

| Parameter         | Details                                                          |
| ----------------- | ---------------------------------------------------------------- |
| Primary Target IP | 192.168.242.128                                                  |
| Target URLs       | [http://192.168.242.128/bodgeit](http://192.168.242.128/bodgeit) |
| Permitted Ports   | 80, 443                                                          |
| Assessment Scope  | Web Application Penetration Testing (VM)                         |
| Scope Exclusions  | XSS, CSRF, Offline VHD attacks, GRUB interaction                 |
| Client Allowances | External access via Virtual Machine                              |

---

## 2. Technical Reconnaissance and Attack Surface Mapping

Structured reconnaissance was performed to identify exposed services, misconfigurations, and outdated components that could serve as entry points for deeper exploitation.

A TCP SYN scan across the subnet identified multiple exposed services on the target host.

### Open Ports and Services Identified

| Port     | Service                  |
| -------- | ------------------------ |
| 22/tcp   | SSH                      |
| 80/tcp   | HTTP (Apache httpd)      |
| 139/tcp  | NetBIOS-SSN              |
| 143/tcp  | IMAP                     |
| 443/tcp  | HTTPS (Apache httpd/SSL) |
| 445/tcp  | Microsoft-DS             |
| 5001/tcp | Commplex-link            |
| 8080/tcp | HTTP-Proxy               |
| 8081/tcp | Blackice-icecap          |

Service enumeration and vulnerability scanning revealed widespread use of deprecated and End-of-Life software.

### Deprecated / EOL Components Detected

| Component         | Version |
| ----------------- | ------- |
| Apache            | 2.2.14  |
| PHP               | 5.3.2   |
| OpenSSL           | 0.9.8k  |
| Python            | 2.6.5   |
| mod_ssl           | 2.2.14  |
| mod_mono          | 2.4.3   |
| mod_perl          | 2.0.4   |
| mod_python        | 3.3.1   |
| Perl              | v5.10.1 |
| Phusion Passenger | 4.0.38  |
| proxy_html        | 3.0.1   |

### Security Impact

Operating EOL software introduces systemic risk because these versions no longer receive security patches. This leaves the environment continuously exposed to publicly available exploits, including Remote Code Execution. From an attacker’s perspective, this dramatically lowers exploitation effort and increases compromise likelihood.

---

## 3. Exploitation Logic and MITRE ATT&CK Integration

To standardize attack mapping and improve stakeholder understanding, observed attack behaviors were aligned with the MITRE ATT&CK framework. This enables visibility into how individual weaknesses can be chained into full compromise scenarios.

### ATT&CK Mapping Summary

| Tactic            | Technique                     | ID        | Execution Method    |
| ----------------- | ----------------------------- | --------- | ------------------- |
| Reconnaissance    | Network Scanning              | T1595.001 | Nmap                |
| Reconnaissance    | Vulnerability Scanning        | T1595.002 | Nikto               |
| Discovery         | Website Crawling              | T1594     | Spidering           |
| Initial Access    | Exploit Public-Facing App     | T1190     | Direct path access  |
| Collection        | Adversary-in-the-Middle       | T1114     | Data harvesting     |
| Credential Access | OS Credential Dumping         | T1003     | SQL Injection logic |
| Persistence       | Modify Authentication Process | T1556     | Password tampering  |
| Impact            | Data Manipulation             | T1195     | Basket logic abuse  |

### Attack Path Narrative

The attack chain began with discovery of an exposed administrative endpoint. This allowed collection of sensitive internal details, which were used to craft SQL Injection payloads for authentication bypass. Administrative persistence was then achieved through password manipulation, followed by transaction logic abuse to impact application integrity.

---

## 4. Critical and High-Severity Vulnerability Analysis

The following findings present direct risk to Confidentiality, Integrity, and Availability.

### WPT-003 — SQL Injection (Critical)

| Field         | Details                                      |
| ------------- | -------------------------------------------- |
| Description   | Authentication bypass via SQL Injection      |
| Evidence      | Injection of crafted SQL condition in login  |
| Impact        | Full account takeover without password       |
| Business Risk | Complete loss of confidentiality             |
| Remediation   | Parameterized queries and input sanitization |

---

### WPT-006 — Parameter Tampering (Critical)

| Field         | Details                                    |
| ------------- | ------------------------------------------ |
| Description   | Price manipulation via parameter tampering |
| Evidence      | Negative quantity value accepted           |
| Impact        | Financial fraud scenario                   |
| Business Risk | Direct revenue loss                        |
| Remediation   | Strict server-side validation              |

---

### WPT-001 — Broken Access Control (High)

| Field         | Details                                      |
| ------------- | -------------------------------------------- |
| Description   | Admin page accessible without authentication |
| Evidence      | Direct admin.jsp access                      |
| Impact        | Database structure exposure                  |
| Business Risk | Enables targeted follow-on attacks           |
| Remediation   | Role-Based Access Control and session checks |

---

### WPT-004 — Password Method Manipulation (High)

| Field         | Details                          |
| ------------- | -------------------------------- |
| Description   | Password change allowed via GET  |
| Evidence      | Method switched from POST to GET |
| Impact        | Account persistence by attacker  |
| Business Risk | Administrative lockout           |
| Remediation   | Enforce POST and validate tokens |

---

### WPT-009 — Apache Byte Range DoS (High)

| Field         | Details                                |
| ------------- | -------------------------------------- |
| Description   | Byte Range DoS vulnerability           |
| Evidence      | CVE detection via scan                 |
| Impact        | Server crash risk                      |
| Business Risk | Service unavailability                 |
| Remediation   | Upgrade Apache and apply rate limiting |

---

## 5. Moderate and Informational Findings

Lower-severity findings still contribute to attack chaining and reconnaissance refinement.

### Additional Findings Summary

| ID      | Finding                 | Severity | Impact                             |
| ------- | ----------------------- | -------- | ---------------------------------- |
| WPT-002 | Debug Parameter Enabled | Moderate | Internal data disclosure           |
| WPT-008 | TRACE Method Enabled    | Low      | Configuration intelligence leakage |

### Security Impact

Diagnostic and protocol-level exposures provide attackers with internal structure and behavioral clues that increase exploit precision and reduce trial-and-error effort.

### Remediation Actions

* Disable TRACE method at server level
* Remove debug modes in production
* Restrict diagnostic outputs

---

## 6. Strategic Recommendations and Incident Response Roadmap

Security maturity requires organizational capability, not just technical patching.

### Recommended Internal Capability

Establish an internal CSIRT or SOC capability to provide:

* Context-aware monitoring
* Faster incident triage
* Reduced third-party dependency
* Improved response SLAs

### Incident Handling Lifecycle

| Phase                  | Objective                       |
| ---------------------- | ------------------------------- |
| Triage                 | Classify and register incidents |
| Analysis               | Correlate and validate alerts   |
| Containment            | Block and isolate threats       |
| Eradication & Recovery | Remove root cause and restore   |
| Lessons Learned        | Improve defensive posture       |

---

## Long-Term Mitigation Strategy

| Initiative             | Value                          |
| ---------------------- | ------------------------------ |
| Replace EOL Systems    | Removes systemic exposure      |
| Annual Security Drills | Improves readiness             |
| Purple Team Exercises  | Tests real response capability |
| SIEM with ELK          | Centralized visibility         |
| 24/7 Alerting          | Faster detection               |

---

## Conclusion

Security resilience is achieved through continuous improvement, proactive validation, and operational readiness. Addressing the identified vulnerabilities and implementing the strategic recommendations will significantly strengthen the BodgeIt application’s defensive posture and reduce business risk exposure.
