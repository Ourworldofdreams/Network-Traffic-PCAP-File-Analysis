### **Unit 42 Wireshark Quiz Jan 2023 on Malware-Traffic-Analysis.net**

# Lab Documentation: Analyzing Malicious Network Traffic with Wireshark

## Executive Summary
This lab involves analyzing a packet capture (pcap) file containing malicious network traffic associated with an Agent Tesla variant, specifically OriginLogger. The goal is to identify key indicators of compromise (IoCs) and understand the behavior of the malware.

![Screenshot 2025-01-13 at 5 05 37 PM](https://github.com/user-attachments/assets/b9f4c116-17f7-452b-abc3-cfacb7d81e47)
![Screenshot 2025-01-13 at 5 05 53 PM](https://github.com/user-attachments/assets/bf699d87-27a9-4cdf-ac78-936b204bb4e9)
![Screenshot 2025-01-13 at 5 07 00 PM](https://github.com/user-attachments/assets/e14c697a-be96-4f71-9088-90a16005b4f2)

## Objectives
- Identify the timeline of malicious activity.
- Determine the infected host's details.
- Analyze the data exfiltration method used by the malware.

# Lab Documentation: Analyzing Malicious Network Traffic with Wireshark

## Quiz Questions and Answers

### Timeline of Activity
- **First Occurrence of Malicious Activity**: `Thur, 05 Jan 2023 22:51:00`

![Screenshot 2025-01-13 at 5 22 56 PM](https://github.com/user-attachments/assets/209a3a39-3309-4e2a-8a85-0311dad15e82)
![Screenshot 2025-01-13 at 5 25 57 PM](https://github.com/user-attachments/assets/6c830cb1-c7c4-4b00-a056-65e2422e4571)

### Infected Host Details
- **IP Address**: `192.168.1.27`
- **MAC Address**: `bc:ea:fa:22:74:fb`

![Screenshot 2025-01-13 at 5 35 22 PM](https://github.com/user-attachments/assets/dc6b4e2e-5625-417a-80cf-8f710b08bf87)

---

  ![Screenshot 2025-01-13 at 5 42 51 PM](https://github.com/user-attachments/assets/716476ff-a129-4558-b763-1e981e7a1d30)
![Screenshot 2025-01-13 at 5 43 13 PM](https://github.com/user-attachments/assets/53818a70-20bc-4ac5-ad51-2fee9570af5b)
- **Windows Host Name**: `DESKTOP-WIN11PC`

![Screenshot 2025-01-13 at 5 46 58 PM](https://github.com/user-attachments/assets/bfa1b530-8f67-48d2-8084-e18bba1b1c87)

- **Public IP Address**: `173.66.46.112`

![Screenshot 2025-01-13 at 5 53 45 PM](https://github.com/user-attachments/assets/8839f306-8b92-462a-8344-f77bb85c09d7)

---

- **Windows User Account Name**: `windows11user`
- **RAM**: `32165.83`
- **CPU Type**: `Intel(R) Core(TM) i5-13600k CPU @ 5.10GHz`

![Screenshot 2025-01-13 at 6 06 17 PM](https://github.com/user-attachments/assets/e469c27f-e7b3-4b82-b4c7-57a416da0244)

---

### Data Exfiltration

- **Type of Data Stolen**: Login account credentials from applications: Edge Chormium and Thunderbird, stealing credintials and passwords from Coca-Cola, linkedin, Amazon, NY Times and Target. (Note: Data was fake for this exercise)

![Screenshot 2025-01-13 at 6 19 38 PM](https://github.com/user-attachments/assets/bcff6e73-708e-40f8-90b3-4f9da978b7bf)

---

## Indicators of Compromise (IoCs)
- **IP Addresses**: `45.56.99[.]101` port 80 `204.11.58[.]28` port 587 
- **Domains**: `marketing@transgear.in` `zaritkt@arhitektondizajn.com` `savory[.]com[.]bd` `api.ipify.org`
- **File Hashes**: `90d977ca0a3331d78005912d2b191d26e33fa2c6ef17602d6173164ba83fd85e` `GET /sav/Ztvfo.png`

![Screenshot 2025-01-13 at 6 50 09 PM](https://github.com/user-attachments/assets/42f2db62-c45d-44f8-8076-a318e7c7d0a0)
![Screenshot 2025-01-13 at 7 13 52 PM](https://github.com/user-attachments/assets/62f4b5a3-dd27-4943-aa65-54f10ca54afd)

## Conclusion
This lab provided hands-on experience in analyzing malicious network traffic using Wireshark. By identifying key IoCs and understanding the malware's behavior, we can better prepare for and respond to similar threats in the future.

## References
- [Palo Alto Networks Unit 42 Blog Post](https://www.paloaltonetworks.com/unit42)
- [Malwre Traffic Analysis](https://www.malware-traffic-analysis.net/training-exercises.html)
- [Wireshark Official Documentation](https://www.wireshark.org/docs/)
