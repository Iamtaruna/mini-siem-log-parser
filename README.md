# 🕵️‍♂️ Mini SIEM Log Parser

A lightweight Python tool that parses SSH authentication logs, extracts failed login attempts, and flags potential brute-force attacks. Inspired by real-world SIEM (Security Information and Event Management) workflows.

---

## ✨ Features
- Detects **failed SSH login attempts** from log files  
- Extracts **username** and **IP address**  
- Summarizes login failures by IP  
- Flags **brute-force activity** (threshold configurable)  
- Optional: export alerts to **CSV** for further analysis  
