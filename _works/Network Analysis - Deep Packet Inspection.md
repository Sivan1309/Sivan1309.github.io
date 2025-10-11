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

![Alt text](https://github.com/Sivan1309/Sivan1309.github.io/tree/c37f27504ac6ebd2738ce19ce8802c02fe596d9b/images/dhcp.png)

### 2. Vulnerability Exposure (HTTP)

*   **Demonstrated Capability:** **Application layer security auditing** and **risk remediation**.
*   I inspected application layer protocols (HTTP), immediately confirming that client and server communication was occurring over unencrypted **HTTP**.
*   This exposure creates an immediate, severe vulnerability, demonstrating my capability to **diagnose high-risk weaknesses that lead to Man-in-the-Middle (MITM) attacks** and expose sensitive data to adversaries.

### 3. Active Reconnaissance Identification (TCP/ICMP)

*   **Demonstrated Capability:** **Threat hunting** and **behavioral anomaly detection**.
*   I monitored Transmission Control Protocol (**TCP**) and Internet Control Message Protocol (**ICMP**) traffic.
*   I confirmed that the IP address `192.168.97.4` was performing port scanning via incomplete TCP handshakes, which is not a legitimate activity.
*   Additionally, I identified sustained **ICMP ping requests** between multiple IPs—a technique used to check if a particular server is alive—confirming ongoing **network reconnaissance activity**.

### 4. Integrated Threat Intelligence

*   **Demonstrated Capability:** **Host reputation analysis** and **external threat intelligence integration**.
*   I executed host reputation analysis and reviewed files communicated by involved hosts (including `192.168.97.4`, `192.168.97.41`, and `192.168.97.102`) by integrating findings with **VirusTotal**. This critical step ensured I could quickly **isolate potentially compromised endpoints** and document the risk posed by specific digital artifacts.

## Impact: Quantifiable Results and Demonstrated Threat Mitigation

This forensic investigation successfully transformed ambiguous network activity into a clear, prioritized list of security defects, thereby **strengthening overall network security**.

*   **Threat Validation:** Confirmed multiple active and potential attack vectors, including **network reconnaissance** and evidence suggesting a **DHCP Spoofing Attack**.
*   **Vulnerability Remediation:** The identification of unencrypted HTTP communication provided necessary evidence to mandate the immediate enforcement of encryption standards, **mitigating high-risk data leakage opportunities** and preventing MITM intrusions.
*   **Actionable Reporting:** By correlating low-level packet data (from Wireshark) with reputation checks (from VirusTotal), I produced a final security report that precisely documented and contextualized the identified issues. This documentation directly enabled the immediate implementation of **response measures, including threat mitigation strategies and continuous monitoring protocols**.

## Key Learnings: Mastering Complex Threat Contextualization

The most significant challenge involved **correlating seemingly isolated protocol anomalies**—specifically the highly suspicious change in MAC address during the DHCP request—with the broader network environment defined by the ARP table, which maps IP addresses to MAC addresses.

I overcame this by meticulously cross-referencing the detailed DHCP findings with the mapped IP-to-MAC associations provided by the Address Resolution Protocol (ARP) table. This process confirmed the critical need to treat the packet as evidence of a potential **rogue DHCP server**. This experience significantly advanced my capability in **sophisticated security diagnostics**, ensuring that I move beyond surface-level observation to accurately diagnose and prioritize complex, multi-stage threats.



---
**Copyright Notice**

Copyright © 2024 [Sivan1309.github.io].

This publication is the intellectual property of [Sivarama_Krishnan_Chandran] and is protected by international copyright law. All rights are reserved.

No part of this article may be reproduced, distributed, or transmitted in any form or by any means, including photocopying, recording, or other electronic or mechanical methods, without the prior written permission of the author. Brief quotations are permitted for noncommercial use in the case of reviews and critical analysis, provided that full and clear credit is given to 
[Sivarama_Krishnan_Chandran] with a link to the original content.