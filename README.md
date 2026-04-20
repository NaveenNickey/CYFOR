# 🛡️ Cyber Forensic Investigation System

A web-based digital forensics platform designed to simplify and automate the process of analyzing digital evidence. This system integrates multiple forensic techniques into a single interface, helping investigators perform efficient, accurate, and structured analysis.

---

## 🚀 Overview

With the rapid growth of cybercrime, analyzing digital evidence has become more complex and time-consuming. This project focuses on building a unified forensic system that reduces manual effort and improves investigation efficiency.

The application allows users to upload files and perform multiple forensic analyses such as integrity verification, hidden data detection, low-level inspection, and automated reporting — all from one dashboard.

As described in the project report, the system is designed to assist cybersecurity professionals, students, and researchers in understanding and performing real-world forensic investigations.

---

## ✨ Features

- 🔐 **File Integrity Verification**  
  Generates SHA-256 hash to ensure data authenticity  

- 🕵️ **MIME Type Detection**  
  Detects real file type using magic bytes (even if renamed)  

- 🧩 **Hex Viewer (Low-Level Analysis)**  
  Analyze raw file structure at byte level  

- 🖼️ **Image Forensics (Steganography Detection)**  
  Detect hidden data using LSB analysis  

- 🖥️ **System Artifact Scanner**  
  Extracts logs, cache, and activity traces  

- 🔍 **Keyword & Pattern Search**  
  Search large datasets for relevant data quickly  

- 📄 **Automated Report Generator**  
  Generates structured forensic reports  

---

## 🛠️ Tech Stack

- **Backend:** Python  
- **Framework:** Flask  
- **Libraries:** OpenCV, NumPy, hashlib, python-magic  
- **Frontend:** HTML, CSS  
- **Tools:** VS Code  

---

## ⚙️ How It Works

1. Upload a file through the web interface  
2. File is processed through multiple forensic modules  
3. Each module analyzes specific aspects (hashing, MIME, hex, etc.)  
4. Results are combined and displayed in a dashboard  
5. Final report can be generated automatically  

---

## 📸 Screenshots

### 🔹 Dashboard
![Dashboard](screenshots/dashboard.png)

### 🔹 Hash Output
![Hash Output](https://github.com/NaveenNickey/CYFOR/blob/b7e03daf073451ff42c2995408ee30984b9b2475/Cyber_Forensic_Project/Screenshots/Screenshot%202026-04-03%20221543.png)

### 🔹 MIME Type Detection
![MIME](screenshots/mime_output.png)

### 🔹 Hex Viewer
![Hex Viewer](screenshots/hex_viewer.png)

### 🔹 Steganography Detection
![Stego](screenshots/stego_result.png)

### 🔹 Report Generation
![Report](screenshots/report.png)
---

## 🎯 Applications

- Cybercrime investigation  
- Digital evidence analysis  
- Malware detection  
- Incident response  
- Educational & research purposes  

---

## 🚧 Challenges Faced

- Handling multiple file formats efficiently  
- Detecting disguised/malicious files  
- Optimizing performance for large files  
- Improving steganography detection accuracy  
- Integrating multiple modules into one system  

---

## 🔮 Future Improvements

- AI/ML-based threat detection  
- Real-time network forensic analysis  
- Cloud-based deployment  
- Advanced multimedia forensics (audio/video)  
- Integration with threat intelligence systems  

---

## 📚 References

Included in the project documentation.

---

## 🤝 Contributing

Feel free to fork the repo, raise issues, or suggest improvements.

---

## 📬 Contact

If you found this useful or have suggestions, feel free to connect!
