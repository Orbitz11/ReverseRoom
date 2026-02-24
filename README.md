# 🔍 ReverseRoom

**A comprehensive binary analysis and reverse engineering toolkit for security researchers, malware analysts, and penetration testers.**

<img width="1366" height="768" alt="Image" src="https://github.com/user-attachments/assets/937831e9-9375-4a47-a871-8ccf839d4cb9" />
<img width="1366" height="768" alt="Image" src="https://github.com/user-attachments/assets/01ab279f-0dbb-40cc-970f-319aba187cba" />
---

## 📋 Overview

ReverseRoom is a powerful command-line tool designed to streamline binary analysis workflows. Whether you're analyzing malware, performing security research, or participating in CTF competitions, ReverseRoom provides an intuitive interface to common reverse engineering tasks.

**Current Version:** 0.1  
**Language:** Python  
**Status:** Active Development

---

## ✨ Features

### Core Analysis Tools
- **File Type Detector** - Identify file types and structures automatically
- **Entropy Scanner** - Analyze entropy levels to detect compression/encryption
- **Import & API Viewer** - Extract and display imported functions and APIs
- **Show Strings** - Extract readable strings from binaries
- **Generate Analysis Report** - Comprehensive automated analysis reports

### Advanced Capabilities
- **UPX Test** - Detect and analyze UPX-packed executables
- **Anti-Debug Check** - Identify anti-debugging techniques
- **CTF Mode** - Optimized workflow for Capture The Flag challenges
- **Permission Manager** - Change file permissions (chmod)
- **Ghidra Integration** - Direct integration with Ghidra disassembler

### User Experience
- Clean, intuitive menu-driven interface
- Real-time binary analysis
- Extensible architecture for custom plugins
- Detailed logging and reporting

---

## 🚀 Quick Start

### Installation
```bash
git clone https://github.com/Orbitz11/ReverseRoom.git
cd ReverseRoom
python3 ReverseRoom.py
