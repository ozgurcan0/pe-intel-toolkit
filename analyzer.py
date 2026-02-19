import pefile
import sys
import re
import struct
import json
import datetime
import os

MIN_STRING = 5

NETWORK_APIS = ["connect", "send", "recv", "WSA", "socket"]
FILE_APIS = ["CreateFile", "WriteFile", "ReadFile"]
THREAD_APIS = ["CreateThread", "Sleep"]

KEYWORDS = ["rpc", "packet", "connect", "join", "player", "server"]

PROLOGUES = [
    b"\x55\x8B\xEC",      # push ebp / mov ebp,esp
    b"\x40\x55\x53",      # common x64 style
]

PATTERNS = {
    "RakNet": b"RakNet",
    "JSON": b"{\"",
}


def extract_strings(data):
    ascii_re = rb"[ -~]{%d,}" % MIN_STRING
    unicode_re = rb"(?:[ -~]\x00){%d,}" % MIN_STRING

    strings = set()

    for match in re.findall(ascii_re, data):
        try:
            strings.add(match.decode())
        except:
            pass

    for match in re.findall(unicode_re, data):
        try:
            strings.add(match.decode("utf-16le"))
        except:
            pass

    return sorted(strings)


def entropy(section):
    return round(section.get_entropy(), 2)


def scan_prologues(pe):
    results = []
    text = None
    image_base = pe.OPTIONAL_HEADER.ImageBase

    for s in pe.sections:
        if b".text" in s.Name:
            text = s
            break

    if not text:
        return results

    data = text.get_data()
    base = image_base + text.VirtualAddress

    for sig in PROLOGUES:
        for i in range(len(data) - len(sig)):
            if data[i:i+len(sig)] == sig:
                results.append(hex(base + i))

    return results


def scan_patterns(data):
    results = {}
    for name, pattern in PATTERNS.items():
        hits = []
        offset = 0
        while True:
            idx = data.find(pattern, offset)
            if idx == -1:
                break
            hits.append(hex(idx))
            offset = idx + 1
        results[name] = hits
    return results


def rtti_scan(pe):
    pattern = re.compile(rb'\.\?AV[^\@]+@@')
    classes = set()
    for s in pe.sections:
        data = s.get_data()
        for match in pattern.findall(data):
            try:
                classes.add(match.decode())
            except:
                pass
    return sorted(classes)


def vtable_scan(pe):
    vtables = []
    image_base = pe.OPTIONAL_HEADER.ImageBase

    text = None
    for s in pe.sections:
        if b".text" in s.Name:
            text = s
            break

    if not text:
        return vtables

    text_start = image_base + text.VirtualAddress
    text_end = text_start + text.Misc_VirtualSize

    for s in pe.sections:
        if b".rdata" in s.Name:
            data = s.get_data()
            base = image_base + s.VirtualAddress
            for i in range(0, len(data) - 16, 4):
                ptrs = struct.unpack("<IIII", data[i:i+16])
                if all(text_start <= p <= text_end for p in ptrs):
                    vtables.append(hex(base + i))

    return vtables


def analyze(file_path):
    pe = pefile.PE(file_path)
    data = open(file_path, "rb").read()

    report = {}

    # BASIC
    report["basic"] = {
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "compile_time_utc": str(datetime.datetime.utcfromtimestamp(
            pe.FILE_HEADER.TimeDateStamp))
    }

    # SECURITY
    flags = pe.OPTIONAL_HEADER.DllCharacteristics
    report["security"] = {
        "aslr": bool(flags & 0x40),
        "nx": bool(flags & 0x100)
    }

    # SECTIONS
    report["sections"] = []
    for s in pe.sections:
        report["sections"].append({
            "name": s.Name.decode().strip("\x00"),
            "entropy": entropy(s),
            "va": hex(s.VirtualAddress),
        })

    # IMPORTS
    imports = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    imports.append(imp.name.decode())
    report["imports"] = imports

    report["network_imports"] = [i for i in imports if any(n.lower() in i.lower() for n in NETWORK_APIS)]
    report["file_imports"] = [i for i in imports if any(n.lower() in i.lower() for n in FILE_APIS)]
    report["thread_imports"] = [i for i in imports if any(n.lower() in i.lower() for n in THREAD_APIS)]

    # STRINGS
    strings = extract_strings(data)
    report["total_strings"] = len(strings)
    report["keyword_hits"] = [s for s in strings if any(k in s.lower() for k in KEYWORDS)]

    # RTTI
    report["rtti_classes"] = rtti_scan(pe)

    # VTABLE
    report["vtable_candidates"] = vtable_scan(pe)

    # PROLOGUES
    report["function_candidates"] = scan_prologues(pe)

    # PATTERN SCAN
    report["pattern_hits"] = scan_patterns(data)

    return report

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyzer.py file.dll")
        sys.exit(1)

    result = analyze(sys.argv[1])

    with open("report.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4)

    with open("report.txt", "w", encoding="utf-8") as f:
        for k, v in result.items():
            f.write(f"{k}:\n{v}\n\n")

    print("Done. Output -> report.json + report.txt")
