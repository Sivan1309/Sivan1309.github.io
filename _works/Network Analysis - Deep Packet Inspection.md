---
Title: "Zeroing In: How Deep Packet Inspection Diagnosed a Rogue DHCP Server and Halted Network Reconnaissance."
Date: 2024-01-12
--- 

# Network Forensics and Advanced Threat Identification

## Problem: Transforming Network Traffic into Actionable Security Intelligence

Modern network infrastructure constantly faces sophisticated threats hidden within the high volume of daily traffic. The initial challenge was to take raw network communication data (a PCAP file) and perform **comprehensive network traffic analysis** to identify critical vulnerabilities, pinpoint active malicious communication, and diagnose the underlying network security posture. PCAP files store network traffic that has been captured and analyzed. Failure to interpret this data effectively leaves the network exposed to unauthorized intrusions, data leakage, and potential system compromise.

## My Solution: Executing Deep Packet Forensics and Threat Contextualization

I designed and executed a systematic network forensic investigation, demonstrating expertise in identifying, classifying, and contextualizing multiple layers of network threats. This involved deploying **industry-standard network analysis tools** such as **Wireshark** and integrating external threat intelligence services like **VirusTotal**.

My solution focused on the following key areas, bridging technical analysis (How) with direct security improvement (Why):

### 1. Protocol-Level Anomaly Detection (DHCP/ARP)

*   **Demonstrated Capability:** **Deep-level protocol inspection** and **DHCP spoofing mitigation**.
*   I performed deep analysis on Dynamic Host Configuration Protocol (**DHCP**) packets and Address Resolution Protocol (**ARP**) mapping.
*   By observing a suspicious change in the Ethernet MAC address within DHCP requests (specifically, the MAC changing from `02:60:AC:9A:BC:DD` in frame 2 to `02:60:AC:9A:BC:05` in frame 170, for IP `192.168.97.250`), I successfully **identified markers of a potential rogue DHCP server**.
*   This detection is crucial because it immediately highlighted the network’s vulnerability to a catastrophic **DHCP Spoofing Attack**, which grants unauthorized hosts control over network addressing.

<img width="1554" height="1128" alt="Image" src="https://github.com/user-attachments/assets/2844f798-a029-43a8-a1a0-5c0310d5409d" />

### 2. Vulnerability Exposure (HTTP)

*   **Demonstrated Capability:** **Application layer security auditing** and **risk remediation**.
*   I inspected application layer protocols (HTTP), immediately confirming that client and server communication was occurring over unencrypted **HTTP**.
*   This exposure creates an immediate, severe vulnerability, demonstrating my capability to **diagnose high-risk weaknesses that lead to Man-in-the-Middle (MITM) attacks** and expose sensitive data to adversaries.

<img width="1438" height="762" alt="Image" src="https://github.com/user-attachments/assets/40e2b109-f175-4927-8b02-9219005f4601" />

### 3. Active Reconnaissance Identification (TCP/ICMP)

*   **Demonstrated Capability:** **Threat hunting** and **behavioral anomaly detection**.
*   I monitored Transmission Control Protocol (**TCP**) and Internet Control Message Protocol (**ICMP**) traffic.
*   I confirmed that the IP address `192.168.97.4` was performing port scanning via incomplete TCP handshakes, which is not a legitimate activity.
*   Additionally, I identified sustained **ICMP ping requests** between multiple IPs—a technique used to check if a particular server is alive—confirming ongoing **network reconnaissance activity**.

<img width="1426" height="616" alt="Image" src="https://github.com/user-attachments/assets/69208046-7d53-42fe-9b3d-5045ad612e83" />

<img width="1464" height="346" alt="Image" src="https://github.com/user-attachments/assets/399fa0d1-4f70-4430-ae69-8bd79109f231" />

### 4. Integrated Threat Intelligence

*   **Demonstrated Capability:** **Host reputation analysis** and **external threat intelligence integration**.
*   I executed host reputation analysis and reviewed files communicated by involved hosts (including `192.168.97.4`, `192.168.97.41`, and `192.168.97.102`) by integrating findings with **VirusTotal**. This critical step ensured I could quickly **isolate potentially compromised endpoints** and document the risk posed by specific digital artifacts.

<img width="1286" height="1442" alt="Image" src="https://github.com/user-attachments/assets/c63de468-ad8d-43aa-8fe3-8742ba86a670" />

<img width="1874" height="1390" alt="Image" src="https://github.com/user-attachments/assets/b5405ea9-e2c2-4d4e-a2a4-c31847716965" />

## Impact: Quantifiable Results and Demonstrated Threat Mitigation

This forensic investigation successfully transformed ambiguous network activity into a clear, prioritized list of security defects, thereby **strengthening overall network security**.

*   **Threat Validation:** Confirmed multiple active and potential attack vectors, including **network reconnaissance** and evidence suggesting a **DHCP Spoofing Attack**.
*   **Vulnerability Remediation:** The identification of unencrypted HTTP communication provided necessary evidence to mandate the immediate enforcement of encryption standards, **mitigating high-risk data leakage opportunities** and preventing MITM intrusions.
*   **Actionable Reporting:** By correlating low-level packet data (from Wireshark) with reputation checks (from VirusTotal), I produced a final security report that precisely documented and contextualized the identified issues. This documentation directly enabled the immediate implementation of **response measures, including threat mitigation strategies and continuous monitoring protocols**.

## Key Learnings: Mastering Complex Threat Contextualization

The most significant challenge involved **correlating seemingly isolated protocol anomalies**—specifically the highly suspicious change in MAC address during the DHCP request—with the broader network environment defined by the ARP table, which maps IP addresses to MAC addresses.

I overcame this by meticulously cross-referencing the detailed DHCP findings with the mapped IP-to-MAC associations provided by the Address Resolution Protocol (ARP) table. This process confirmed the critical need to treat the packet as evidence of a potential **rogue DHCP server**. This experience significantly advanced my capability in **sophisticated security diagnostics**, ensuring that I move beyond surface-level observation to accurately diagnose and prioritize complex, multi-stage threats.



---------------------------------------------------------------------------------
**Copyright Notice**

> *Copyright © 2024 [Sivarama_Krishnan_Chandran]. This work is the intellectual property of the author. No part of this publication may be reproduced, distributed, or transmitted in any form or by any means, including photocopying, recording, or other electronic or mechanical methods, without the prior written permission of the publisher, except in the case of brief quotations embodied in critical reviews and certain other noncommercial uses permitted by copyright law.*
----------------------------------------------------------------------------------