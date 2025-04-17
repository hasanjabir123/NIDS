## 📌 About the Project

This project was developed as part of our final year coursework. It is a lightweight and modular Network Intrusion Detection System (NIDS) built entirely using Python. The system detects various types of intrusions in network traffic and serves as a practical implementation of core cybersecurity concepts, aiming to support early threat detection.

📚 **Technologies Used**:

- **Programming Language**: Python
- **Libraries & Tools**:
  - Packet Sniffing: *libpcap* (Linux), *WinPcap* (Windows)
  - Python Modules: `socket`, `sys`, `os`, `turtle`, `selectors`

## 🛠️ Process of Working

The NIDS works by monitoring and analyzing network traffic in real time. Here's an overview of how it functions:

1. **Packet Capturing**: 
   - The system uses packet sniffing libraries (*libpcap* or *WinPcap*) to capture packets from the network interface in real-time.
   - It intercepts incoming and outgoing network packets and captures raw data for analysis.

2. **Data Analysis**:
   - The captured data is processed to extract important features such as source IP, destination IP, protocol type, packet length, etc.
   - The system uses Python modules like `socket` and `selectors` to parse the packet information and prepare it for analysis.

3. **Intrusion Detection**:
   - Using predefined rules or machine learning algorithms, the system compares the captured data against known patterns of network intrusions.
   - If suspicious activity is detected (such as port scanning, unusual packet sizes, or suspicious IP addresses), the system flags the packet as malicious.

4. **Alert Generation**:
   - If any malicious activity is detected, the system generates an alert and logs the incident.
   - Alerts can include details such as the type of attack, the source and destination of the traffic, and any other relevant information.

5. **Reporting**:
   - The system generates a summary report of detected intrusions, providing useful information for further analysis or investigation.

🧑‍💻 **Developed By**:
- **Team Name**: NIDS TEAM
- **Team Members**: Jabir Hasan, Anmol Gill, Ansh Maurya, Aadvik Gaur
- **Institution**: PTU


