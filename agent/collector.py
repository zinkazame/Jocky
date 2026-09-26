"""
agent/collector.py -- JOCKY Real Forensic Collectors
Pure Windows forensic evidence collection using stdlib only.
Every function returns a serializable dict ready to encrypt + POST.
"""

from __future__ import annotations
import ctypes, hashlib, json, os, re, sqlite3, struct, subprocess
import winreg, time, shutil, tempfile, logging
from datetime import datetime, timezone
from pathlib  import Path
from typing   import Any, Dict, List, Optional

log = logging.getLogger("jocky.collector")

def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _sha256_file(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
        return h.hexdigest()
    except Exception: return ""

def _run(cmd: list) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=15, creationflags=0x08000000)
        return r.stdout.strip()
    except Exception: return ""

def _reg_read_key(hive, path: str) -> Dict[str, Any]:
    result = {}
    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
        i = 0
        while True:
            try:
                name, data, _ = winreg.EnumValue(key, i)
                result[name] = str(data); i += 1
            except OSError: break
        winreg.CloseKey(key)
    except Exception: pass
    return result

# ── 1. Process List ──────────────────────────────────────────────────────────
def proc_list() -> Dict[str, Any]:
    procs = []; suspicious = []
    try:
        out = _run(["tasklist", "/FO", "CSV", "/V"])
        for line in out.strip().splitlines()[1:]:
            try:
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) < 5: continue
                procs.append({"pid": int(parts[1]) if parts[1].isdigit() else 0,
                               "name": parts[0], "mem_kb": parts[3].replace(",","").replace(" K",""),
                               "username": parts[5] if len(parts)>5 else "", "path":"","sha256":"","flags":[]})
            except Exception: continue

        wmic_out = _run(["wmic","process","get","ProcessId,ExecutablePath,CommandLine","/FORMAT:CSV"])
        path_map: Dict[int, dict] = {}
        for line in wmic_out.splitlines():
            cols = line.split(",")
            if len(cols) >= 4:
                try: path_map[int(cols[2])] = {"cmdline":cols[1].strip(),"path":cols[3].strip()}
                except Exception: pass

        suspicious_paths = ["\\temp\\","\\tmp\\","\\appdata\\local\\temp\\",
                             "\\appdata\\roaming\\","\\users\\public\\","\\programdata\\"]
        for entry in procs:
            info = path_map.get(entry["pid"], {})
            entry["path"] = info.get("path",""); entry["cmdline"] = info.get("cmdline","")
            if entry["path"]:
                entry["sha256"] = _sha256_file(entry["path"])
                p_lower = entry["path"].lower()
                for sp in suspicious_paths:
                    if sp in p_lower: entry["flags"].append("SUSPICIOUS_PATH"); break
            else:
                entry["flags"].append("NO_DISK_IMAGE")
            if "NO_DISK_IMAGE" in entry["flags"] and entry["pid"] > 4:
                suspicious.append({"pid":entry["pid"],"name":entry["name"],"reason":"no executable path"})
    except Exception as e: log.warning(f"proc_list: {e}")
    return {"timestamp":_utcnow(),"count":len(procs),"suspicious":suspicious,"processes":procs}

# ── 2. Network State ─────────────────────────────────────────────────────────
def net_state() -> Dict[str, Any]:
    connections = []; external_ips = []; suspicious_conns = []
    try:
        out = _run(["netstat","-ano"])
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4 or parts[0] not in ("TCP","UDP"): continue
            proto = parts[0]; local = parts[1]; remote = parts[2] if len(parts)>2 else ""
            state = parts[3] if proto=="TCP" and len(parts)>3 else ""
            pid   = parts[-1] if parts[-1].isdigit() else ""
            conn  = {"proto":proto,"local":local,"remote":remote,"state":state,
                     "pid":int(pid) if pid else 0,"process":"","flags":[]}
            if remote and remote not in ("*:*","0.0.0.0:0"):
                ip = remote.rsplit(":",1)[0].strip("[]")
                if ip and not ip.startswith(("127.","::1","0.0.0.0","10.","192.168.","172.")):
                    external_ips.append(ip); conn["flags"].append("EXTERNAL_IP")
                    if ip.startswith(("185.220.","195.123.","5.188.")):
                        conn["flags"].append("THREAT_IP")
                        suspicious_conns.append({"remote":remote,"pid":conn["pid"],"reason":"known bad range"})
            connections.append(conn)

        pid_names: Dict[int,str] = {}
        for line in _run(["wmic","process","get","ProcessId,Name","/FORMAT:CSV"]).splitlines():
            cols = line.split(",")
            if len(cols)>=3:
                try: pid_names[int(cols[2])] = cols[1].strip()
                except Exception: pass
        for conn in connections:
            conn["process"] = pid_names.get(conn["pid"],"")
    except Exception as e: log.warning(f"net_state: {e}")
    return {"timestamp":_utcnow(),"total":len(connections),
            "external_ips":list(set(external_ips)),"suspicious":suspicious_conns,"connections":connections}

# ── 3. Registry Persistence ──────────────────────────────────────────────────
def reg_persistence() -> Dict[str, Any]:
    results: Dict[str,Any] = {"timestamp":_utcnow(),"keys":{},"suspicious":[]}
    keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"),
    ]
    suspicious_values = ["powershell","cmd.exe","wscript","cscript","mshta",
                         "rundll32","regsvr32","bitsadmin","certutil",".bat",
                         ".vbs",".ps1","temp","tmp","appdata","base64"]
    for hive, path in keys:
        values = _reg_read_key(hive, path)
        label = ("HKLM" if hive==winreg.HKEY_LOCAL_MACHINE else "HKCU") + "\\" + path
        results["keys"][label] = values
        for name, data in values.items():
            for sv in suspicious_values:
                if sv in str(data).lower():
                    results["suspicious"].append({"key":label,"value":name,"data":data,"reason":f"contains '{sv}'"})
                    break
    return results

# ── 4. Event Log ─────────────────────────────────────────────────────────────
def event_log(max_events: int = 100) -> Dict[str, Any]:
    events = []; errors = []
    try:
        import win32evtlog, win32evtlogutil
        target = {"Security":{4624,4625,4688,4720,4726,4732,4776},"System":{7045,7036,7040}}
        for log_name, eids in target.items():
            try:
                hand = win32evtlog.OpenEventLog(None, log_name)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
                count = 0
                while count < max_events:
                    records = win32evtlog.ReadEventLog(hand, flags, 0)
                    if not records: break
                    for r in records:
                        eid = r.EventID & 0xFFFF
                        if eids and eid not in eids: continue
                        try: msg = win32evtlogutil.SafeFormatMessage(r, log_name)
                        except Exception: msg = ""
                        events.append({"log":log_name,"event_id":eid,
                                        "time":r.TimeGenerated.Format(),
                                        "source":r.SourceName,"message":msg[:300]})
                        count += 1
                        if count >= max_events: break
                win32evtlog.CloseEventLog(hand)
            except Exception as e: errors.append(f"{log_name}: {e}")
    except ImportError:
        for log_name in ["Security","System"]:
            out = _run(["wevtutil","qe",log_name,"/c:50","/rd:true","/f:text"])
            for block in out.split("Event["):
                if not block.strip(): continue
                eid_m = re.search(r"EventID:\s*(\d+)", block)
                time_m = re.search(r"Date:\s*([\d/: APM]+)", block)
                events.append({"log":log_name,"event_id":int(eid_m.group(1)) if eid_m else 0,
                                "time":time_m.group(1) if time_m else "","message":block[:200],"source":""})
    suspicious_eids = {4625:"failed logon",4688:"process created",7045:"service installed",4720:"user created"}
    return {"timestamp":_utcnow(),"count":len(events),
            "suspicious":[{**e,"reason":suspicious_eids[e["event_id"]]} for e in events if e["event_id"] in suspicious_eids][:50],
            "events":events[:max_events],"errors":errors}

# ── 5. USB History ───────────────────────────────────────────────────────────
def usb_history() -> Dict[str, Any]:
    devices = []
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                              r"SYSTEM\CurrentControlSet\Enum\USBSTOR",0,winreg.KEY_READ)
        i = 0
        while True:
            try:
                dc = winreg.EnumKey(key, i); i += 1
                ck = winreg.OpenKey(key, dc, 0, winreg.KEY_READ)
                j = 0
                while True:
                    try:
                        serial = winreg.EnumKey(ck, j); j += 1
                        sk = winreg.OpenKey(ck, serial, 0, winreg.KEY_READ)
                        try: friendly,_ = winreg.QueryValueEx(sk, "FriendlyName")
                        except Exception: friendly = ""
                        devices.append({"device_class":dc,"serial":serial,"friendly":friendly})
                        winreg.CloseKey(sk)
                    except OSError: break
                winreg.CloseKey(ck)
            except OSError: break
        winreg.CloseKey(key)
    except Exception as e: log.warning(f"usb_history: {e}")
    return {"timestamp":_utcnow(),"count":len(devices),"devices":devices}

# ── 6. Prefetch ──────────────────────────────────────────────────────────────
def prefetch() -> Dict[str, Any]:
    pf_dir = Path(r"C:\Windows\Prefetch"); entries = []
    if not pf_dir.exists():
        return {"timestamp":_utcnow(),"count":0,"note":"Prefetch directory not found","entries":[]}
    for pf in sorted(pf_dir.glob("*.pf"))[:200]:
        try:
            data = pf.read_bytes()
            if len(data) < 84: continue
            version = struct.unpack_from("<I",data,0)[0]
            try: exe_name = data[16:76].decode("utf-16-le").rstrip("\x00")
            except Exception: exe_name = pf.stem
            run_count = 0; last_run = ""
            try:
                if version >= 30: run_count = struct.unpack_from("<I",data,208)[0]; ft = struct.unpack_from("<Q",data,128)[0]
                else:             run_count = struct.unpack_from("<I",data,160)[0]; ft = struct.unpack_from("<Q",data,120)[0]
                if ft>0:
                    epoch = (ft-116444736000000000)//10000000
                    last_run = datetime.utcfromtimestamp(epoch).strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception: pass
            entries.append({"name":exe_name,"file":pf.name,"run_count":run_count,
                             "last_run":last_run,"size":pf.stat().st_size})
        except Exception: continue
    entries.sort(key=lambda x: x["last_run"] or "",reverse=True)
    bad = ["mimikatz","psexec","wce","fgdump","pwdump","procdump","lazagne","nc.exe"]
    suspicious = [e for e in entries if any(s in e["name"].lower() for s in bad)]
    return {"timestamp":_utcnow(),"count":len(entries),"suspicious":suspicious,"entries":entries[:100]}

# ── 7. Browser History ───────────────────────────────────────────────────────
def browser_hist(max_urls: int = 200) -> Dict[str, Any]:
    results = {"timestamp":_utcnow(),"urls":[],"downloads":[],"errors":[]}
    profiles = {
        "Chrome": Path(os.environ.get("LOCALAPPDATA","")) / "Google"/"Chrome"/"User Data"/"Default"/"History",
        "Edge":   Path(os.environ.get("LOCALAPPDATA","")) / "Microsoft"/"Edge"/"User Data"/"Default"/"History",
    }
    for browser, db_path in profiles.items():
        if not db_path.exists(): continue
        try:
            tmp_path = tempfile.mktemp(suffix=".db"); shutil.copy2(db_path, tmp_path)
            conn = sqlite3.connect(tmp_path); cur = conn.cursor()
            try:
                cur.execute("SELECT u.url,u.title,u.visit_count,datetime(v.visit_time/1000000-11644473600,'unixepoch') FROM urls u JOIN visits v ON u.id=v.url ORDER BY v.visit_time DESC LIMIT ?",(max_urls,))
                for row in cur.fetchall():
                    results["urls"].append({"browser":browser,"url":row[0],"title":row[1],"visits":row[2],"last":row[3]})
            except Exception as e: results["errors"].append(f"{browser} urls: {e}")
            try:
                cur.execute("SELECT target_path,tab_url,total_bytes,datetime(start_time/1000000-11644473600,'unixepoch'),danger_type FROM downloads ORDER BY start_time DESC LIMIT 50")
                for row in cur.fetchall():
                    results["downloads"].append({"browser":browser,"path":row[0],"source_url":row[1],"size":row[2],"time":row[3],"danger":row[4]})
            except Exception as e: results["errors"].append(f"{browser} downloads: {e}")
            conn.close(); os.unlink(tmp_path)
        except Exception as e: results["errors"].append(f"{browser}: {e}")
    results["url_count"]=len(results["urls"]); results["download_count"]=len(results["downloads"])
    return results

# ── 8. Scheduled Tasks ───────────────────────────────────────────────────────
def scheduled_tasks() -> Dict[str, Any]:
    tasks = []; suspicious = []
    try:
        out = _run(["schtasks","/query","/FO","CSV","/V"])
        lines = out.strip().splitlines()
        if len(lines) < 2: return {"timestamp":_utcnow(),"count":0,"tasks":[],"suspicious":[]}
        headers = [h.strip('"') for h in lines[0].split('","')]
        for line in lines[1:]:
            if not line.strip(): continue
            try:
                cols = [c.strip('"') for c in line.split('","')]
                task = dict(zip(headers, cols))
                entry = {"name":task.get("TaskName",""),"status":task.get("Status",""),
                         "run_as":task.get("Run As User",""),"action":task.get("Task To Run",""),
                         "next":task.get("Next Run Time",""),"last":task.get("Last Run Time",""),
                         "result":task.get("Last Result",""),"flags":[]}
                al = entry["action"].lower()
                for tok in ["powershell","cmd.exe","wscript","cscript","mshta","rundll32",
                             "regsvr32","certutil","bitsadmin","\\temp\\","\\tmp\\"]:
                    if tok in al: entry["flags"].append(f"ACTION:{tok}")
                if "system" in entry["run_as"].lower(): entry["flags"].append("RUN_AS_SYSTEM")
                if entry["flags"]: suspicious.append(entry)
                tasks.append(entry)
            except Exception: continue
    except Exception as e: log.warning(f"scheduled_tasks: {e}")
    return {"timestamp":_utcnow(),"count":len(tasks),"suspicious":suspicious,"tasks":tasks}

# ── Master collector ─────────────────────────────────────────────────────────
def collect_all(collectors=None) -> Dict[str, Any]:
    AVAILABLE = {
        "proc_list":       proc_list,
        "net_state":       net_state,
        "reg_persistence": reg_persistence,
        "event_log":       event_log,
        "usb_history":     usb_history,
        "prefetch":        prefetch,
        "browser_hist":    browser_hist,
        "scheduled_tasks": scheduled_tasks,
    }
    to_run = collectors or list(AVAILABLE.keys())
    bundle: Dict[str,Any] = {
        "collected_at": _utcnow(),
        "hostname":     os.environ.get("COMPUTERNAME","unknown"),
        "username":     os.environ.get("USERNAME","unknown"),
        "collectors":   {}, "errors": {},
    }
    for name in to_run:
        fn = AVAILABLE.get(name)
        if not fn: bundle["errors"][name]="unknown collector"; continue
        try:
            log.info(f"[collector] running: {name}")
            bundle["collectors"][name] = fn()
        except Exception as e:
            bundle["errors"][name] = str(e)
            log.warning(f"[collector] {name} failed: {e}")
    return bundle

if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    data = collect_all()
    print(json.dumps(data, indent=2, default=str)[:6000])
