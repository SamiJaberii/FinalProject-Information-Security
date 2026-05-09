# Information Security Final Project

## Group Project

**Students:** Mohammad Farid Hassani and Sami Jaberi  
**Course:** Information Security  

---

# Project Description

This project was developed for the Information Security course and includes two related cybersecurity tools:

1. Secure Password Generator  
2. File Integrity Monitoring System  

The purpose of this project is to improve system security by generating strong passwords and monitoring important files for unauthorized modifications.

The Secure Password Generator helps users create secure passwords with different complexity levels, password strength evaluation, symbol support, and secure random generation.

The File Integrity Monitoring System uses SHA-256 hashing to detect file tampering, modifications, deleted files, and newly added files. The system also creates security logs and stores integrity hashes in a JSON database.

Both projects are related because they focus on protecting systems, user authentication, and sensitive information.

---

# Problem It Solves

Weak passwords and unauthorized file modifications are common security problems in computer systems.

This project helps solve these problems by:

- Generating strong and secure passwords
- Monitoring files using SHA-256 hashing
- Detecting unauthorized modifications
- Logging security events
- Improving authentication and file integrity security
- Helping users protect sensitive information

---

# Features

## Secure Password Generator

- Strong password generation
- Multiple complexity levels
- Password strength evaluation
- Symbol support
- Multiple password generation
- Save passwords to files
- Command-line support

## File Integrity Monitoring System

- SHA-256 hashing
- File integrity verification
- Tampering detection
- Deleted file detection
- New file detection
- Security logging
- JSON hash database

---

# Technologies Used

## Programming Language

- Python 3

## Password Generator Libraries

- secrets
- argparse
- string
- pathlib

## File Integrity Monitoring System Libraries

- hashlib
- json
- os
- pathlib
- datetime

---

# Architecture Overview

```text
information-security-final-project/
│
├── password-generator/
│   └── main.py
│
├── file-integrity-checker/
│   ├── main.py
│   ├── hashes.json
│   ├── integrity_logs.txt
│   └── monitored_files/
│
├── screenshots/
├── presentation/
└── README.md
```

---

# Setup and Run Instructions

## Clone Repository

```bash
git clone https://github.com/MFHASSANI/-Secure-Password-Generator-Final-Project-for-Information-Security-Course.git
```

## Run Secure Password Generator

```bash
cd password-generator
python3 main.py
```

## Run File Integrity Monitoring System

```bash
cd file-integrity-checker
python3 main.py
```

---

# Screenshots

Project screenshots are available in the `screenshots/` folder.

Included screenshots:

- Password generator banner
- Password generation results
- Password CLI usage examples
- Password strength evaluation
- Integrity monitoring banner
- Tampering detection results

---

# Presentation

The final project presentation is available in the `presentation/` folder.

---

# Demo Video

## Project Walkthrough Video

[Click here to watch the demo video](https://drive.google.com/file/d/1hWVEZbpdNpR-UgFWsx9EotnaEElG-Ce5/view?usp=share_link)

---

# Conclusion

This project successfully demonstrates important Information Security concepts using Python.

The Secure Password Generator improves authentication security by helping users create strong passwords.

The File Integrity Monitoring System protects important files using SHA-256 hashing and tampering detection.

Both projects help improve cybersecurity awareness and system protection.