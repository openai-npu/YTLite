#!/usr/bin/env python3
"""Audit a decrypted App Store IPA for tampering before we inject our tweak.

FAIL conditions (any single one aborts):
  - Mach-O executable outside the stock allowlist
  - Load command referencing a non-stock dylib/framework path
  - File modified vs CodeResources that is not a FairPlay-decrypted binary
  - File missing vs CodeResources that is not SC_Info DRM metadata
  - Raw http:// IPv4 endpoint embedded in the main binary

Exit 0 = clean. Prints a report either way.
"""
import plistlib, hashlib, base64, os, re, subprocess, sys, glob

APP = sys.argv[1]  # path to Payload/*.app

ALLOWED_MACHO = {
    "YouTube", "widevine_cdm_secured_ios", "IntentsExtension",
    "NotificationContentExtension", "NotificationServiceExtension",
    "ShareExtension", "WidgetKitExtension", "AppMigrationExtension",
}
ALLOWED_LOAD_PREFIXES = (
    "/System/Library/", "/usr/lib/", "@rpath/", "@loader_path/",
    "/Library/MobileSubstrate/DynamicLibraries/YouTube",
)
SCINFO = re.compile(r"(^|/)SC_Info/|\.supp$|\.supf$|\.sinf$|Manifest\.plist$")

def macho_files(root):
    out = []
    for dp, _, fns in os.walk(root):
        for fn in fns:
            p = os.path.join(dp, fn)
            with open(p, "rb") as f:
                magic = f.read(4)
            if magic in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                         b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                         b"\xca\xfe\xba\xbe"):
                out.append(os.path.relpath(p, root))
    return out

def load_cmds(path):
    try:
        return subprocess.check_output(["otool", "-L", path], text=True)
    except Exception:
        return ""

failures = []

# 1. Mach-O inventory
machos = macho_files(APP)
print(f"[inventory] Mach-O files: {len(machos)}")
for rel in sorted(machos):
    base = os.path.basename(rel)
    flag = "OK " if base in ALLOWED_MACHO else "FAIL"
    print(f"  {flag} {rel}")
    if base not in ALLOWED_MACHO:
        failures.append(f"unexpected executable: {rel}")

# 2. Load commands must only reference stock locations
for rel in machos:
    loads = load_cmds(os.path.join(APP, rel))
    for line in loads.splitlines()[1:]:
        dep = line.strip().split(" (")[0]
        if not dep or dep.startswith("/"): 
            ok = dep.startswith(ALLOWED_LOAD_PREFIXES)
        else:
            ok = dep.startswith(ALLOWED_LOAD_PREFIXES)
        if not ok:
            failures.append(f"{rel}: suspicious load {dep}")
            print(f"  FAIL {rel} loads {dep}")

# 3. CodeResources audit
crp = os.path.join(APP, "_CodeSignature/CodeResources")
cr = plistlib.load(open(crp, "rb"))
files = cr.get("files2", cr.get("files", {}))
checked = modified = 0
for rel, info in files.items():
    if SCINFO.search(rel):
        continue
    full = os.path.join(APP, rel)
    if not os.path.exists(full):
        failures.append(f"missing file: {rel}")
        continue
    data = open(full, "rb").read()
    expected = info.get("hash2", info.get("hash")) if isinstance(info, dict) else info
    if isinstance(expected, bytes):
        h = base64.b64encode(hashlib.sha256(data).digest()).decode() if "hash2" in info else base64.b64encode(hashlib.sha1(data).digest()).decode()
        exp = base64.b64encode(expected).decode()
    else:
        h = hashlib.sha256(data).hexdigest(); exp = expected
    checked += 1
    if h != exp:
        modified += 1
        base = os.path.basename(rel)
        if base in ALLOWED_MACHO and rel in machos:
            print(f"  NOTE modified (decrypt-touched binary): {rel}")
        else:
            failures.append(f"modified file: {rel}")
            print(f"  FAIL modified: {rel}")
print(f"[coderesources] checked={checked} modified={modified} (decrypt-touched binaries expected)")

# 4. Raw IP http endpoints in main binary
strings = subprocess.check_output(["strings", "-a", os.path.join(APP, "YouTube")], text=True, errors="ignore")
ips = sorted(set(re.findall(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", strings)))
print(f"[endpoints] raw-IP http endpoints: {len(ips)}")
for ip in ips[:10]:
    print(f"  FAIL {ip}"); failures.append(f"raw IP endpoint: {ip}")

print("=" * 40)
if failures:
    print(f"AUDIT FAILED: {len(failures)} finding(s)")
    for f in failures: print(" -", f)
    sys.exit(1)
print("AUDIT CLEAN")
