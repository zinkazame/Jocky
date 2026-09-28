# agent/android_collector.py
# JOCKY Android forensic module (ADB-based, no root required)
# Runs on INVESTIGATOR machine -- no agent installed on phone
# requires: adb in PATH (Android Platform Tools)

import subprocess, json, re, logging
from datetime import datetime
log = logging.getLogger("jocky.android")

class AndroidCollector:

    def __init__(self, device: str = None):
        # device: None = first USB device, or "192.168.x.x:5555" for WiFi
        self.device = device
        self._adb   = ["adb"] + (["-s", device] if device else [])

    def _adb_shell(self, cmd: str) -> str:
        result = subprocess.run(
            self._adb + ["shell", cmd],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout.strip()

    def _adb_pull(self, remote: str, local: str) -> bool:
        result = subprocess.run(
            self._adb + ["pull", remote, local],
            capture_output=True, timeout=60
        )
        return result.returncode == 0

    def connect_wifi(self, ip: str, port: int = 5555) -> bool:
        """Connect to phone over WiFi ADB"""
        r = subprocess.run(
            ["adb", "connect", f"{ip}:{port}"],
            capture_output=True, text=True
        )
        return "connected" in r.stdout.lower()

    def device_info(self) -> dict:
        """Basic device fingerprint"""
        props = {
            "manufacturer": self._adb_shell("getprop ro.product.manufacturer"),
            "model":        self._adb_shell("getprop ro.product.model"),
            "android":      self._adb_shell("getprop ro.build.version.release"),
            "sdk":          self._adb_shell("getprop ro.build.version.sdk"),
            "serial":       self._adb_shell("getprop ro.serialno"),
            "imei":         self._adb_shell("service call iphonesubinfo 1 | grep -o '[0-9a-f ]*'"),
            "sim_country":  self._adb_shell("getprop gsm.sim.country"),
            "operator":     self._adb_shell("getprop gsm.operator.alpha"),
            "wifi_ip":      self._adb_shell("ip route | grep wlan"),
        }
        return props

    def installed_apps(self) -> dict:
        """All installed packages + third-party flag"""
        all_pkgs   = self._adb_shell("pm list packages").splitlines()
        user_pkgs  = self._adb_shell("pm list packages -3").splitlines()
        user_set   = set(p.replace("package:", "") for p in user_pkgs)

        apps = []
        for line in all_pkgs:
            pkg = line.replace("package:", "").strip()
            apps.append({
                "package":    pkg,
                "user_installed": pkg in user_set,
                "suspicious": any(x in pkg for x in [
                    "spy","track","monitor","keylog","rat","remote","backdoor"
                ])
            })
        suspicious = [a for a in apps if a["suspicious"]]
        return {
            "total": len(apps),
            "user_installed": len(user_set),
            "suspicious": suspicious,
            "apps": apps,
        }

    def running_processes(self) -> dict:
        """Active processes"""
        raw = self._adb_shell("ps -A")
        procs = []
        for line in raw.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 9:
                procs.append({
                    "user": parts[0], "pid": parts[1],
                    "ppid": parts[2], "name": parts[-1]
                })
        return {"count": len(procs), "processes": procs}

    def network_connections(self) -> dict:
        """Active TCP/UDP connections"""
        tcp = self._adb_shell("cat /proc/net/tcp6 2>/dev/null || cat /proc/net/tcp")
        udp = self._adb_shell("cat /proc/net/udp6 2>/dev/null || cat /proc/net/udp")
        wifi = self._adb_shell("dumpsys wifi | grep 'mNetworkInfo\\|SSID\\|BSSID'")
        return {
            "tcp_raw": tcp[:2000],
            "udp_raw": udp[:2000],
            "wifi_info": wifi,
        }

    def call_log(self) -> dict:
        """Recent call history"""
        raw = self._adb_shell(
            "content query --uri content://call_log/calls "
            "--projection number:date:duration:type "
            "--sort 'date DESC' --limit 100"
        )
        calls = []
        for line in raw.splitlines():
            if "number=" in line:
                c = {}
                for f in ["number","date","duration","type"]:
                    m = re.search(rf"{f}=([^,\]]+)", line)
                    if m: c[f] = m.group(1).strip()
                calls.append(c)
        return {"count": len(calls), "calls": calls}

    def sms(self) -> dict:
        """SMS messages"""
        raw = self._adb_shell(
            "content query --uri content://sms "
            "--projection address:date:body:type "
            "--sort 'date DESC' --limit 200"
        )
        messages = []
        for line in raw.splitlines():
            if "address=" in line:
                m = {}
                for f in ["address","date","body","type"]:
                    match = re.search(rf"{f}=([^,\]]+)", line)
                    if match: m[f] = match.group(1).strip()
                messages.append(m)
        return {"count": len(messages), "messages": messages}

    def location_history(self) -> dict:
        """Last known GPS location"""
        raw = self._adb_shell(
            "dumpsys location | grep 'Last Known Locations' -A 20"
        )
        return {"location_dump": raw}

    def browser_history(self) -> dict:
        """Chrome browser history (needs root for direct DB, else backup method)"""
        raw = self._adb_shell(
            "content query --uri content://com.android.browser/history "
            "--projection url:title:date 2>/dev/null"
        )
        entries = []
        for line in raw.splitlines():
            if "url=" in line:
                e = {}
                for f in ["url","title","date"]:
                    m = re.search(rf"{f}=([^,\]]+)", line)
                    if m: e[f] = m.group(1).strip()
                entries.append(e)
        return {"count": len(entries), "history": entries}

    def collect_all(self) -> dict:
        """Run all collectors and return unified bundle"""
        log.info("[android] starting collection...")
        results = {
            "timestamp":   datetime.utcnow().isoformat() + "Z",
            "device_info": self.device_info(),
            "collectors":  {},
            "errors":      {},
        }
        collectors = {
            "apps":         self.installed_apps,
            "processes":    self.running_processes,
            "network":      self.network_connections,
            "call_log":     self.call_log,
            "sms":          self.sms,
            "location":     self.location_history,
            "browser_hist": self.browser_history,
        }
        for name, fn in collectors.items():
            try:
                results["collectors"][name] = fn()
                log.info(f"[android] {name}: OK")
            except Exception as e:
                results["errors"][name] = str(e)
                log.warning(f"[android] {name}: FAILED -- {e}")
        return results