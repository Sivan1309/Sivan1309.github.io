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

<img width="1862" height="1166" alt="Image" src="https://github.com/user-attachments/assets/5cf765ee-7c99-480c-84c3-3905122b4e2a" />

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

<img width="1884" height="1102" alt="Image" src="https://github.com/user-attachments/assets/d4ba8573-7bbc-45e9-8723-5eebff48400a" />

---

### WPT-006 — Parameter Tampering (Critical)

| Field         | Details                                    |
| ------------- | ------------------------------------------ |
| Description   | Price manipulation via parameter tampering |
| Evidence      | Negative quantity value accepted           |
| Impact        | Financial fraud scenario                   |
| Business Risk | Direct revenue loss                        |
| Remediation   | Strict server-side validation              |

**Attack Flow**

<img width="1624" height="1034" alt="Image" src="https://github.com/user-attachments/assets/a111ab81-8853-4f6b-a332-c6eb6d21b7b3" />

<img width="1634" height="948" alt="Image" src="https://github.com/user-attachments/assets/4addb6ed-a557-4bb8-b896-6a6bbbec727d" />

<img width="1638" height="814" alt="Image" src="https://github.com/user-attachments/assets/b3948b18-4778-4263-98a8-908e5da24eba" />

---

### WPT-001 — Broken Access Control (High)

| Field         | Details                                      |
| ------------- | -------------------------------------------- |
| Description   | Admin page accessible without authentication |
| Evidence      | Direct admin.jsp access                      |
| Impact        | Database structure exposure                  |
| Business Risk | Enables targeted follow-on attacks           |
| Remediation   | Role-Based Access Control and session checks |


**Attack Flow**

<img width="1440" height="978" alt="Image" src="https://github.com/user-attachments/assets/fbe02565-1586-4415-9665-6f38690e71fd" />

<img width="1590" height="1294" alt="Image" src="https://github.com/user-attachments/assets/5f8648ae-3719-42a3-855e-a69e9b560c62" />

<img width="1604" height="732" alt="Image" src="https://github.com/user-attachments/assets/86275154-c10a-4dae-92c3-349441b5186b" />
---

### WPT-004 — Password Method Manipulation (High)

| Field         | Details                          |
| ------------- | -------------------------------- |
| Description   | Password change allowed via GET  |
| Evidence      | Method switched from POST to GET |
| Impact        | Account persistence by attacker  |
| Business Risk | Administrative lockout           |
| Remediation   | Enforce POST and validate tokens |

**Attack Flow**

<img width="1730" height="1048" alt="Image" src="https://github.com/user-attachments/assets/592f0827-6a41-441b-8031-b25c5be4bf2d" />

<img width="1766" height="1024" alt="Image" src="https://github.com/user-attachments/assets/236bd3ad-e835-4de0-baaa-d63b5c805ad0" />

<img width="1600" height="702" alt="Image" src="https://github.com/user-attachments/assets/3683f9d9-e111-42c3-942e-bf3018a44fd6" />
---

### WPT-009 — Apache Byte Range DoS (High)

| Field         | Details                                |
| ------------- | -------------------------------------- |
| Description   | Byte Range DoS vulnerability           |
| Evidence      | CVE detection via scan                 |
| Impact        | Server crash risk                      |
| Business Risk | Service unavailability                 |
| Remediation   | Upgrade Apache and apply rate limiting |

<img width="1836" height="374" alt="Image" src="https://github.com/user-attachments/assets/967eed51-c0d0-4ab4-aef2-7db1d41a2f19" />

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

As a security professional, my role extends beyond finding bugs to ensuring organizational resilience. 

### Immediate Technical Remediation

* **Input Validation**: Implement strict server-side allow-listing for all user inputs to neutralize SQL Injection and XSS vectors.

* **Logic Enforcement**: Move all pricing and logic calculations to the server-side. Never trust the client.

* **Patch Management**: Upgrade the web server (Apache), PHP, and OpenSSL to current stable versions immediately to mitigate RCE risks

Security maturity requires organizational capability, not just technical patching.

### Strategic Recommendation: Internal CSIRT & SOC Implementation

To move beyond reactive patching and establish long-term resilience, the organization must transition into a proactive security posture. I recommend the formation of a dedicated Internal Computer Security Incident Response Team (CSIRT) supported by a Security Operations Center (SOC) capability.

<img width="1042" height="918" alt="Image" src="https://github.com/user-attachments/assets/a82b61b0-02f7-4bcd-a0fd-b66338bda95e" />
---

### 1. The Value Proposition: Why Go Internal?

While outsourcing is an option, establishing an internal team offers distinct strategic advantages that directly impact security outcomes:

* **Tailored Security Operations**: An internal team creates monitoring protocols and processes specifically aligned with the organization's unique business needs and risk profile, rather than a generic "one-size-fits-all" approach.

* **Contextual Intelligence**: Internal staff possess a deep, comprehensive understanding of the organization's specific network topology, data flows, and system dependencies. This allows for faster threat detection and more accurate risk assessment compared to external vendors.

* **Data Sovereignty & Control**: Keeping security operations in-house ensures that sensitive logs and incident data remain within the organization's jurisdiction, reducing third-party privacy risks and ensuring compliance with data control regulations.

* **Service Level Agreements (SLAs)**: An internal team eliminates the friction of vendor communication, allowing for immediate incident handling without breaching SLAs. This integrity is critical for maintaining stakeholder trust.

---

### 2. Proposed Technical Architecture

To support this capability, we propose a cost-effective, open-source focused technology stack:

* **Centralized Monitoring (SIEM)**: Deploy the ELK Stack (Elasticsearch, Logstash, Kibana). This will serve as the core Security Information and Event Management (SIEM) solution, responsible for ingesting event data from the network and processing it to detect malicious or suspicious activities.

* **Threat Intelligence Integration**: The architecture should integrate external threat feeds, such as AlienVault, to correlate internal logs with known global threat actors.

* **Incident Management & Alerting**: Integrate the SIEM with ticketing and alerting platforms like PagerDuty. When the ELK stack detects a "True Positive" based on custom correlation rules, it will trigger an immediate alert to the triage team to streamline the workflow.

---

### 3. Operational Workflow: The Incident Handling Process

The proposed workflow integrates Security Monitoring (detection) with Security Management (response), following a lifecycle approach:

* **Triage & Analysis**: Upon receiving an alert, the team analyzes the security incident to determine its validity and scope.

* **Containment**: The CSIRT coordinates the immediate response. This includes blocking malicious IP/DNS addresses and isolating affected systems to prevent lateral movement.

* **Eradication & Mitigation**: The team identifies the root cause and preserves forensic evidence. Remediation steps involve installing updates, patching unsupported systems, and implementing long-term fixes.

* **Recovery**: Once the threat is neutralized, the team assists in transitioning systems back to normal operations and removing temporary blocks.

* **Post-Incident Review**: The process concludes with a "Lessons Learned" phase to refine security protocols and prevent recurrence.

---

### 4. Resourcing Strategy

Providing 24/7 coverage is resource-intensive, typically requiring six distinct teams to cover all shifts and holidays. To balance budget and security coverage, we recommend a hybrid operational model:

* **Business Hours**: Full internal CSIRT operation.

* **Off-Hours**: Use of an "On-Call" duty phone for emergency escalations, or outsourcing night/weekend monitoring to a third-party partner while retaining incident management authority in-house.


---

Security resilience is achieved through continuous improvement, proactive validation, and operational readiness. Addressing the identified vulnerabilities and implementing the strategic recommendations will significantly strengthen the BodgeIt application’s defensive posture and reduce business risk exposure.

### Tools & Skills Demonstrated

This engagement demonstrates proficiency in the following areas:

* **Vulnerability Assessment Tools**: Nmap (Network Discovery), Nikto (Server Scanning), OWASP ZAP (Proxy/Interceptor), Burp Suite methodologies.

* **Manual Exploitation**: SQL Injection, Parameter Tampering, HTTP Method Manipulation.

* **Security Frameworks**: NIST SP 800-115, OWASP Top 10, MITRE ATT&CK.

* **Blue Team/Defensive Strategy**: Designing CSIRT workflows, SIEM architecture (ELK), and Patch Management policies.

* **Reporting**: Translating complex technical data into actionable business intelligence with calculated risk ratings (CVSS).


**Copyright Notice**

> *Copyright © 2024 [Sivarama_Krishnan_Chandran]. This work is the intellectual property of the author. No part of this publication may be reproduced, distributed, or transmitted in any form or by any means, including photocopying, recording, or other electronic or mechanical methods, without the prior written permission of the publisher, except in the case of brief quotations embodied in critical reviews and certain other noncommercial uses permitted by copyright law.*
----------------------------------------------------------------------------------

