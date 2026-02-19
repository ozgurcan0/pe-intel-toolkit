# pe-intel-toolkit

# PE Intel Framework

Educational static reverse engineering toolkit for Windows PE binaries.

This project was developed step-by-step while learning how to analyze game/network DLLs using Python.

It focuses on understanding binary structure before moving to full disassembly and call graph analysis.

---

# 🎯 Purpose

The goal of this project is to learn and demonstrate:

- How Windows PE files are structured
- How to extract meaningful intelligence from binaries
- How to identify networking behavior
- How to recover structural information (classes, functions)
- How to prepare for deeper disassembly analysis

This is a **static analysis educational tool**, not a full reverse engineering engine.

---

# 📚 Topics Covered

## 1️⃣ PE Structure Analysis

- DOS Header
- NT Headers
- Optional Header
- ImageBase
- Entry Point
- RVA basics
- Section parsing (.text, .rdata, .data)

---

## 2️⃣ Security Flags

- ASLR detection
- NX (DEP) detection

Understanding how the binary was compiled and protected.

---

## 3️⃣ Section Entropy Analysis

- Entropy calculation per section
- Detecting packed or suspicious sections

---

## 4️⃣ Import Table Intelligence

- Full import extraction
- Networking API detection (connect, send, recv, socket)
- File API detection
- Thread API detection

Helps identify:
- Network behavior
- File operations
- Multi-threading usage

---

## 5️⃣ String Extraction

- ASCII string extraction
- UTF-16 (Unicode) string extraction
- Keyword hunting (rpc, packet, join, player, server)
- Pattern detection (RakNet, JSON)

Used for:
- RPC detection
- Network logic hints
- Identifying internal subsystems

---

## 6️⃣ RTTI Class Recovery

- Detection of MSVC RTTI signatures
- Extraction of C++ class names using:

.?AVClassName@@

Allows partial class structure visibility.

---

## 7️⃣ VTable Candidate Detection

- Heuristic detection of vtable pointer clusters
- .rdata → .text pointer validation

Used to approximate:
- Virtual class structures
- Polymorphic behavior

---

## 8️⃣ Function Candidate Detection

- Prologue scanning
- Detection of common function start patterns

Examples:
- 55 8B EC (x86)
- Common x64 prologues

Provides:
- Approximate internal function mapping

---

## 9️⃣ Pattern Scanning

Custom byte pattern detection for:

- RakNet references
- JSON fragments

Allows extension with custom signatures.

---

# 🧠 What This Project Does NOT Do (Yet)

The following advanced reverse engineering features are NOT implemented:

- Instruction-level disassembly
- CALL instruction resolution
- Import cross-reference analysis
- String → function cross-reference
- Control Flow Graph (CFG)
- Call Graph generation
- Stack frame analysis

Those require integration with a disassembly engine such as Capstone.

---

# 🚀 Usage

Install requirements:

pip install -r requirements.txt

Run:

python analyzer.py target.dll

Outputs:

- report.json
- report.txt

---

# 🏗 Current Level

This framework operates at:

Static Surface Analysis + Structural Heuristics

It prepares the binary for deeper reverse engineering.

---

# ⚠ Disclaimer

This project is intended for educational and research purposes only.

Do not use it to violate software licenses, game terms of service, or local laws.
