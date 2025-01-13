# Network-Traffic-PCAP-File-Analysis

<img width="1101" alt="Screenshot 2025-01-07 at 5 18 06 PM" src="https://github.com/user-attachments/assets/9e6eec95-6cef-4abe-a583-3ce55ad19b42" />


<img width="826" alt="Screenshot 2025-01-07 at 5 13 08 PM" src="https://github.com/user-attachments/assets/7ae93e6b-4a46-4e3b-b5e4-a22181d32bdd" />

---

## **Incident Report for PCAP Analysis**

### **1. Executive Summary**
- On Wednesday, 2024-09-04 at 17:35 UTC, suspicious network activity was detected on machine DESKTOP-RNVO9AT, used by Andrew Fletcher. The system exhibited abnormal ARP broadcast requests and established connections to known malicious IP addresses, suggesting a malware infection. Further analysis revealed communication with a Command and Control (C2) server associated with the Win32/Koi Stealer trojan. A total of 48 alerts were triggered due to this malicious activity.
  
![Screenshot 2025-01-09 at 4 06 40 PM](https://github.com/user-attachments/assets/8f429db3-348b-48bf-914e-b8c746998525)
![Screenshot 2025-01-09 at 5 17 39 PM](https://github.com/user-attachments/assets/fdc6b993-d5da-40ad-9898-f98f699ed086)
<img width="1297" alt="Screenshot 2025-01-07 at 7 25 26 PM" src="https://github.com/user-attachments/assets/c1c787a4-2d26-49f5-90e6-4364ffd1c5c2" />
<img width="680" alt="Screenshot 2025-01-07 at 7 26 14 PM" src="https://github.com/user-attachments/assets/39f32773-24f6-4396-ab0d-b3713bff8c61" />


- **Impact Summary**: The infection could lead to data exfiltration, system compromise, and network disruption.
---

### **2. Victim Details**
- **Hostname**: `DESKTOP-RNVO9AT`
- **IP Address**: `172.17.0.99`
- **MAC Address**: `18:3d:a2:b6:8d:c4`
- **User Account Name**: `afletcher`
- **Name of User**: Andrew Fletcher
<img width="1359" alt="Screenshot 2025-01-07 at 8 24 56 PM" src="https://github.com/user-attachments/assets/61864d5d-af48-48bc-b4b9-11522f8fbb96" />

---

### **3. Indicators of Compromise (IOCs)**
#### **Alert Information**
| Source IP:Port       | Destination IP:Port     | Alert Name |
|-----------------------|-------------------------|------------|
| `172.17.0.99:49813` | `79.124.78.197:80`  | `ETPRO TROJAN Win32/Koi Stealer CnC Checkin (POST) M2` |
#### **Malicious Domains:**
  - `a1961[.]g2[.]akamai[.][net` (used for internet connectivity testing)  
  - `www[.]bellantonicioccolato[.]it` (likely compromised and related to Koi Stealer)  
- **Malware:** `Win32/Koi Stealer`   
- **Malicious URLs:**  
  - `POST /foots.php`  
  - `POST /index.php?id&subid=qIOuKk7U` 
  - `POST /index.php`  
---

### **4. Analysis Steps**
 - Applied display filters:  
  - `ip.addr == 79.124.78.197 && tcp.port == 80` 
  - arp (to detect suspicious ARP broadcasts)  
  - `ldap.AttributeDescription == "givenName"` (to extract user information)  
- Identified outbound traffic to known malicious IPs.  
- Detected POST requests indicating malware C2 check-ins.
<img width="1564" alt="Screenshot 2025-01-07 at 8 07 13 PM" src="https://github.com/user-attachments/assets/d38b35db-04c2-4277-905b-3fa101ee4d88" />
<img width="1564" alt="Screenshot 2025-01-07 at 8 23 09 PM" src="https://github.com/user-attachments/assets/1add022c-df77-46ed-a8ba-b177d8ea45f8" />

---

### **5. Key Findings
- **ARP Broadcasts:** Unusual ARP requests originating from the user's machine.  
- **Malicious Communication:** Connection to **`79[.]124[.]78[.]197`** over port 80, known for malware C2 activity.  
- **Volume of Alerts:** 48 C2 check-in alerts were detected.  
- **Potential Data Exfiltration:** Possible data theft due to C2 communication.  

---

### **6. Additional Observations**
- **Malware Characteristics**: 
<img width="680" alt="Screenshot 2025-01-07 at 7 26 14 PM" src="https://github.com/user-attachments/assets/b74ab1f9-4c29-4d02-9c2e-eb89aa426692" />
<img width="1564" alt="Screenshot 2025-01-07 at 7 57 30 PM" src="https://github.com/user-attachments/assets/7fff989d-c62c-4f2b-a9fe-f0be76e32b18" />
<img width="1564" alt="Screenshot 2025-01-07 at 7 57 40 PM" src="https://github.com/user-attachments/assets/a9fe3da6-2bbf-422a-8d2e-31985969161f" />
- **Related Domains/IPs**:
- Frequent attempts to communicate with the external IP **`79.124.78.197`**.   
- Access to **`www[.]bellantonicioccolato[.]it`**, potentially linked to malware distribution.  
<img width="1564" alt="Screenshot 2025-01-07 at 7 33 50 PM" src="https://github.com/user-attachments/assets/a9f98a09-a543-42fe-b90b-3d7b1794a2e9" />
<img width="1564" alt="Screenshot 2025-01-07 at 7 43 38 PM" src="https://github.com/user-attachments/assets/5687db94-7e84-4ea0-aa89-51ac46558bb5" />
<img width="1564" alt="Screenshot 2025-01-07 at 7 44 49 PM" src="https://github.com/user-attachments/assets/4b0e2a7b-9e28-473c-90d0-50342d455ccc" />
<img width="1359" alt="Screenshot 2025-01-07 at 8 43 01 PM" src="https://github.com/user-attachments/assets/4813cbf3-64c5-448c-bf02-4a1f882ce73f" />

---

### **6. Recommendations**
  - **Containment**:
    - Immediately isolate **`DESKTOP-RNVO9AT`** from the network.  
    - Block IP **`79[.]124[.]78[.]197`** and related domains at the firewall.  
    - Block access to **`www[.]bellantonicioccolato[.]it`**.  
  - **Eradication**:
    - Perform a full malware scan and remove detected threats.  
    - If malware persists, reimage the affected system. 
  - **Recovery**:
    - Restore system from a clean backup.  
    - Change all associated passwords.  
    - Monitor network traffic for recurring suspicious activity. 
  - **Detection and Prevention**:
    - Regularly update antivirus and endpoint protection tools.  
    - Educate staff on phishing prevention and safe browsing practices.  
    - Enable logging and monitor network traffic for anomalies.  
    - Conduct regular vulnerability assessments and penetration testing. 

---

### **7. References**
- [Wireshark Display Filters Documentation](https://www.wireshark.org/docs/dfref/)  
- [Elastic SIEM Documentation](https://www.elastic.co/guide/en/security/current/index.html)  
- [Malware Traffic Analysis Exercise](https://www.malware-traffic-analysis.net/2024/09/04/index.html)

---
