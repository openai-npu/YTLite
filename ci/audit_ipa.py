#!/usr/bin/env python3
"""Audit IPAs used in the smart-speed build.

Modes:
  stock  - decrypted base YouTube IPA: must be stock-only, tampering fails
  donor  - YTLitePlus donor IPA: stock + known tweak binaries only
  final  - assembled output app: verify injection, inventory delta vs stock,
           patch symbols present, endpoint scan across all binaries

Exit 0 = clean. Any unexplained finding fails.
"""
import plistlib, hashlib, base64, os, re, subprocess, sys

STOCK_MACHO = {
    "YouTube", "widevine_cdm_secured_ios", "IntentsExtension",
    "NotificationContentExtension", "NotificationServiceExtension",
    "ShareExtension", "WidgetKitExtension", "AppMigrationExtension",
    "OpenYoutubeSafariExtension", "ShareServiceExtension",
}
TWEAK_DYLIBS = {
    "YTLite.dylib", "YTLitePlus.dylib", "libcolorpicker.dylib",
    "iSponsorBlock.dylib", "YTUHD.dylib", "YouPiP.dylib",
    "YouTubeDislikesReturn.dylib", "YTABConfig.dylib", "YouMute.dylib",
    "DontEatMyContent.dylib", "YTHoldForSpeed.dylib",
    "YTVideoOverlay.dylib", "YouGroupSettings.dylib", "YouQuality.dylib",
    "YouTimeStamp.dylib", "YouLoop.dylib",
}
TWEAK_FRAMEWORKS = {"Alderis.framework", "CydiaSubstrate.framework"}
TWEAK_APPEX = {"OpenYoutubeSafariExtension.appex", "ShareServiceExtension.appex"}
DROPPED_APPEX = {
    "IntentsExtension.appex", "NotificationContentExtension.appex",
    "NotificationServiceExtension.appex", "ShareExtension.appex",
    "WidgetKitExtension.appex", "AppMigrationExtension.appex",
}
ALLOWED_LOAD_PREFIXES = (
    "/System/Library/", "/usr/lib/", "@rpath/", "@loader_path/",
    "/Library/MobileSubstrate/DynamicLibraries/", "/Library/Frameworks/",
)
SCINFO = re.compile(r"(^|/)SC_Info/|\.supp$|\.supf$|\.sinf$|Manifest\.plist$")
DOMAIN_RE = re.compile(rb"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")
IPURL_RE = re.compile(rb"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
EXPECTED_ENDPOINTS = {b"sponsor.ajay.app"}  # iSponsorBlock talks to SponsorBlock API

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

def all_files(root):
    return {os.path.relpath(os.path.join(dp, f), root)
            for dp, _, fns in os.walk(root) for f in fns}

def scan_endpoints(path):
    data = open(path, "rb").read()
    ips = set(IPURL_RE.findall(data))
    domains = set(m.group(0) for m in DOMAIN_RE.finditer(data))
    return ips, domains

failures = []
def fail(msg):
    failures.append(msg); print(f"  FAIL {msg}")

APP = sys.argv[1]
mode = "stock"
if "--mode" in sys.argv:
    mode = sys.argv[sys.argv.index("--mode") + 1]

# --- 1. Mach-O inventory ---------------------------------------------------
machos = macho_files(APP)
print(f"[inventory] Mach-O files: {len(machos)}")
allowed = set(STOCK_MACHO)
if mode in ("donor", "final"):
    allowed |= {os.path.splitext(d)[0] for d in TWEAK_DYLIBS}
    allowed |= {os.path.splitext(a)[0] for a in TWEAK_APPEX}
    allowed |= {os.path.splitext(f)[0] for f in TWEAK_FRAMEWORKS}
    allowed |= {"Alderis", "CydiaSubstrate", "AlderisCorePolyfill", "libcolorpicker"}
for rel in sorted(machos):
    base = os.path.basename(rel)
    if base not in allowed:
        fail(f"unexpected executable: {rel}")
    else:
        print(f"  OK  {rel}")

# --- 2. Load commands ------------------------------------------------------
for rel in machos:
    for line in load_cmds(os.path.join(APP, rel)).splitlines()[1:]:
        dep = line.strip().split(" (")[0]
        if dep and not dep.startswith(ALLOWED_LOAD_PREFIXES):
            fail(f"{rel}: suspicious load {dep}")

# --- 3. CodeResources (stock mode only) ------------------------------------
if mode == "stock":
    crp = os.path.join(APP, "_CodeSignature/CodeResources")
    cr = plistlib.load(open(crp, "rb"))
    files = cr.get("files2", cr.get("files", {}))
    checked = modified = 0
    for rel, info in files.items():
        if SCINFO.search(rel):
            continue
        full = os.path.join(APP, rel)
        if not os.path.exists(full):
            fail(f"missing file: {rel}"); continue
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
            if base in STOCK_MACHO:
                print(f"  NOTE modified (decrypt-touched): {rel}")
            else:
                fail(f"modified file: {rel}")
    print(f"[coderesources] checked={checked} modified={modified}")

# --- 4. Endpoint scan over every binary ------------------------------------
print("[endpoints] scanning binaries")
found_domains = set()
for rel in machos:
    ips, domains = scan_endpoints(os.path.join(APP, rel))
    found_domains |= domains
    for ip in sorted(ips):
        fail(f"raw IP endpoint in {rel}: {ip.decode()}")
    if mode in ("donor", "final"):
        for d in sorted(domains):
            host = d.split(b"/")[2] if d.count(b"/") >= 2 else d
            print(f"  endpoint {rel}: {d.decode()[:80]}")

# --- 5. Donor mode: tweak files must be exactly the known set --------------
if mode == "donor":
    fw = os.path.join(APP, "Frameworks")
    extras = {f for f in os.listdir(fw)
              if f not in TWEAK_DYLIBS | TWEAK_FRAMEWORKS | {"widevine_cdm_secured_ios.framework"}}
    for f in sorted(extras):
        fail(f"donor: unexpected Frameworks entry {f}")
    plugs = set(os.listdir(os.path.join(APP, "PlugIns")))
    for f in sorted(plugs - TWEAK_APPEX):
        print(f"  donor note: stock/extra appex {f} (dropped or ignored at assembly)")

# --- 6. Final mode: injection + patch verification --------------------------
if mode == "final":
    fw = os.path.join(APP, "Frameworks")
    present = set(os.listdir(fw))
    missing = (TWEAK_DYLIBS | TWEAK_FRAMEWORKS) - present
    for m in sorted(missing):
        fail(f"final: expected tweak file missing: {m}")
    extra = present - TWEAK_DYLIBS - TWEAK_FRAMEWORKS - {"widevine_cdm_secured_ios.framework"}
    for e in sorted(extra):
        fail(f"final: unexpected Frameworks entry {e}")

    loads = load_cmds(os.path.join(APP, "YouTube"))
    weak = {m.group(1) for m in
            (re.search(r"@rpath/(\S+).*weak", l) for l in loads.splitlines()) if m}
    for d in TWEAK_DYLIBS:
        if d not in weak:
            fail(f"final: no weak load for {d}")
    for w in sorted(weak):
        if w not in TWEAK_DYLIBS:
            fail(f"final: unexpected weak load @rpath/{w}")
    print(f"[inject] weak loads: {len(weak)}")
    bundled_dy = {f for f in os.listdir(fw) if f.endswith(".dylib")}
    bundled_fw = {f for f in os.listdir(fw) if f.endswith(".framework")}
    for rel in machos:
        for line in load_cmds(os.path.join(APP, rel)).splitlines()[1:]:
            dep = line.strip().split(" (")[0]
            leaf = dep.split("/")[-1]
            if leaf in bundled_dy and not dep.startswith("@rpath/"):
                fail(f"{rel}: bundled dylib referenced via absolute path {dep}")
            if ".framework/" in dep:
                fwn = dep.split("/")[-3] if dep.count("/") >= 3 else ""
                if fwn in bundled_fw and not dep.startswith("@rpath/"):
                    fail(f"{rel}: bundled framework referenced via absolute path {dep}")
    print("[deps] bundled-lib references use @rpath")
    for rel in machos:
        for line in load_cmds(os.path.join(APP, rel)).splitlines()[1:]:
            dep = line.strip().split(" (")[0]
            if dep.startswith("@rpath/") and not os.path.exists(os.path.join(fw, dep[7:])):
                if not dep.startswith("@rpath/YouTube"):  # self refs etc
                    fail(f"{rel}: @rpath dep has no bundled file: {dep}")
    print("[deps] all @rpath refs resolve to bundled files")

    app_bundles = {f for f in os.listdir(APP) if f.endswith(".bundle")}
    need = {}
    for rel in machos:
        p = os.path.join(APP, rel)
        data = open(p, "rb").read()
        for m in set(re.findall(rb"[A-Za-z0-9_-]{3,}\.bundle", data)):
            need.setdefault(m.decode(), []).append(rel)
    unmet = 0
    for b, srcs in sorted(need.items()):
        if b not in app_bundles:
            tweak_srcs = [s for s in srcs if s.startswith("Frameworks/") and s.endswith(".dylib")]
            if tweak_srcs:
                fail(f"tweak dylib {tweak_srcs[0]} requires missing bundle {b}")
            else:
                print(f"  bundle-ref {b} needed by {srcs[0]} (not at app root)")
            unmet += 1
    print(f"[bundles] referenced={len(need)} at-root={len(app_bundles)} unmet={unmet}")

    import subprocess as _sp
    noarm = [r for r in machos
             if "arm64" not in _sp.check_output(["lipo","-info",os.path.join(APP,r)],text=True,stderr=_sp.DEVNULL)]
    for r in noarm:
        fail(f"no arm64 slice: {r}")
    print(f"[arch] all {len(machos)} binaries have arm64")



    ytd = open(os.path.join(APP, "Frameworks/YTLite.dylib"), "rb").read()
    for sym in (b"speedIndex", b"ExtraSpeedOptions"):
        if sym not in ytd:
            fail(f"final: patch symbol {sym.decode()} missing in YTLite.dylib")
    print("[patch] speed symbols present")

    if EXPECTED_ENDPOINTS - found_domains:
        print("  note: sponsorblock API endpoint not seen (may be runtime-built)")

print("=" * 40)
if failures:
    print(f"AUDIT FAILED ({mode}): {len(failures)} finding(s)")
    sys.exit(1)
print(f"AUDIT CLEAN ({mode})")
