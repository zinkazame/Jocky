/*
 * test_forensics.c — JOCKY Phase 13.1 + 13.2: Forensic Collector Verification
 * execution_engine/forensics/test_forensics.c
 *
 * Windows x64 | MinGW/Clang | Intel x86-64 ABI
 *
 * Phase 13.1 — Process Analysis:
 *   procs.json          full process + thread + hollow report
 *   modules_self.json   module list of THIS process
 *   lsass hollow check
 *
 * Phase 13.2 — Memory Acquisition:
 *   vad_self.json        full VAD map of THIS process
 *   suspicious_self.json private+executable regions
 *   phys_ranges.json     physical memory layout
 *
 * Build:
 *   clang execution_engine/forensics/proc_analysis.c  \
 *         execution_engine/forensics/mem_acquire.c     \
 *         execution_engine/forensics/test_forensics.c  \
 *         -Iexecution_engine/forensics                 \
 *         -Iexecution_engine                           \
 *         -o test_forensics.exe -lkernel32 -lpsapi -lshell32
 */

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>

#include "forensics.h"

/* ── elevation helpers ───────────────────────────────────────── */

static BOOL is_elevated(void)
{
    BOOL e = FALSE; HANDLE ht = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &ht)) return FALSE;
    TOKEN_ELEVATION te; DWORD sz = sizeof(te);
    if (GetTokenInformation(ht, TokenElevation, &te, sizeof(te), &sz))
        e = (te.TokenIsElevated != 0);
    CloseHandle(ht); return e;
}

static void self_elevate(void)
{
    WCHAR path[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, path, MAX_PATH);
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb       = L"runas";
    sei.lpFile       = path;
    sei.lpParameters = L"/elevated";
    sei.nShow        = SW_NORMAL;
    sei.fMask        = SEE_MASK_NOASYNC;
    if (!ShellExecuteExW(&sei)) { printf("[!] UAC failed\n"); exit(1); }
    exit(0);
}

static void attach_console(void)
{
    AllocConsole(); FILE *fp = NULL;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);
    SetConsoleTitleW(L"JOCKY Phase 13 -- Forensic Collectors");
}

static BOOL enable_debug_privilege(void)
{
    HANDLE ht = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &ht))
        return FALSE;
    LUID luid;
    LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid);
    TOKEN_PRIVILEGES tp = { 1, {{ luid, SE_PRIVILEGE_ENABLED }} };
    AdjustTokenPrivileges(ht, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError(); CloseHandle(ht);
    return err != ERROR_NOT_ALL_ASSIGNED;
}

/* ─────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    BOOL elevated_child = FALSE;
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], "/elevated") == 0) { elevated_child = TRUE; break; }
    if (elevated_child) attach_console();
    if (!is_elevated()) { printf("[*] requesting UAC elevation\n"); self_elevate(); }

    printf("JOCKY Phase 13 -- Forensic Collector Verification\n");
    printf("=================================================\n\n");

    /* ── SeDebugPrivilege ── */
    printf("[priv] Enabling SeDebugPrivilege...  ");
    if (!enable_debug_privilege()) { printf("FAILED\n"); goto bail; }
    printf("ok\n\n");

    /* ============================================================
       PHASE 13.1 — PROCESS ANALYSIS
       ============================================================ */

    printf("── Phase 13.1: Process Analysis ──────────────────────────\n\n");

    /* 13.1a: full process report */
    printf("[13.1a] Enumerating all processes + threads + hollow detection...\n");
    printf("        output -> procs.json\n");
    fflush(stdout);

    int proc_count = JOCKY_enum_processes("procs.json");
    if (proc_count < 0) { printf("[13.1a] FAILED\n"); goto bail; }
    printf("[13.1a] ok -- %d processes enumerated\n\n", proc_count);

    /* 13.1b: module list of THIS process */
    printf("[13.1b] Enumerating modules of THIS process (PID=%lu)...\n",
           GetCurrentProcessId());
    printf("        output -> modules_self.json\n");
    fflush(stdout);

    int mod_count = JOCKY_enum_modules(GetCurrentProcessId(), "modules_self.json");
    if (mod_count < 0) { printf("[13.1b] FAILED\n"); goto bail; }
    printf("[13.1b] ok -- %d modules found\n\n", mod_count);

    /* 13.1c: hollow detection on lsass.exe */
    printf("[13.1c] Hollow detection on lsass.exe...\n");
    fflush(stdout);

    DWORD lsass_pid = 0;
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
            if (Process32FirstW(snap, &pe))
                do {
                    if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                        lsass_pid = pe.th32ProcessID; break;
                    }
                } while (Process32NextW(snap, &pe));
            CloseHandle(snap);
        }
    }

    if (lsass_pid) {
        BOOL is_hollow = FALSE;
        BOOL checked   = JOCKY_detect_hollow(lsass_pid, &is_hollow);
        printf("[13.1c] lsass.exe (PID=%lu): hollow=%s  (check %s)\n\n",
               lsass_pid,
               is_hollow ? "TRUE  <- SUSPICIOUS" : "false",
               checked   ? "completed" : "skipped (access denied — PPL protected, expected)");
    } else {
        printf("[13.1c] lsass.exe not found\n\n");
    }

    printf("Phase 13.1 complete.\n");
    printf("  procs.json          -- full process + thread report\n");
    printf("  modules_self.json   -- module list of test harness\n\n");

    /* ============================================================
       PHASE 13.2 — MEMORY ACQUISITION
       ============================================================ */

    printf("-- Phase 13.2: Memory Acquisition ---------------------\n\n");

    /* 13.2a: VAD walk on THIS process */
    printf("[13.2a] VAD walk -- THIS process (PID=%lu)...\n",
           GetCurrentProcessId());
    printf("        output -> vad_self.json\n");
    fflush(stdout);

    int vad_count = JOCKY_map_vad(GetCurrentProcessId(), "vad_self.json");
    if (vad_count < 0) { printf("[13.2a] FAILED\n"); goto bail; }
    printf("[13.2a] ok -- %d regions mapped\n\n", vad_count);

    /* 13.2b: suspicious region scan on THIS process */
    printf("[13.2b] Suspicious region scan -- THIS process...\n");
    printf("        output -> suspicious_self.json\n");
    fflush(stdout);

    int sus_count = JOCKY_dump_suspicious(GetCurrentProcessId(),
                                          "suspicious_self.json",
                                          NULL,     /* no .bin dumps */
                                          0x1000);  /* cap 4 KB per region */
    if (sus_count < 0) { printf("[13.2b] FAILED\n"); goto bail; }
    printf("[13.2b] ok -- %d suspicious region(s) found\n\n", sus_count);

    /* 13.2c: physical memory ranges */
    printf("[13.2c] Physical memory range enumeration...\n");
    printf("        output -> phys_ranges.json\n");
    fflush(stdout);

    int phys_count = JOCKY_physical_ranges("phys_ranges.json");
    if (phys_count < 0) { printf("[13.2c] FAILED\n"); goto bail; }
    printf("[13.2c] ok -- %d physical range(s) enumerated\n\n", phys_count);

    printf("Phase 13.2 complete.\n");
    printf("  vad_self.json        -- full VAD map of this process\n");
    printf("  suspicious_self.json -- private+executable regions\n");
    printf("  phys_ranges.json     -- physical memory layout\n\n");

     /* ============================================================
       PHASE 13.3 — NETWORK STATE
        ============================================================ */

    printf("-- Phase 13.3: Network State --------------------------\n\n");

    /* 13.3a: TCP/UDP connection table */
    printf("[13.3a] Enumerating TCP/UDP connections...\n");
    printf("        output -> connections.json\n");
    fflush(stdout);

    int conn_count = JOCKY_enum_connections("connections.json");
    if (conn_count < 0) { printf("[13.3a] FAILED\n"); goto bail; }
    printf("[13.3a] ok -- %d endpoints enumerated\n\n", conn_count);

    /* 13.3b: DNS resolver cache */
    printf("[13.3b] Reading DNS resolver cache...\n");
    printf("        output -> dns_cache.json\n");
    fflush(stdout);

    int dns_count = JOCKY_dns_cache("dns_cache.json");
    if (dns_count < 0) { printf("[13.3b] FAILED\n"); goto bail; }
    printf("[13.3b] ok -- %d DNS cache entries\n\n", dns_count);

    printf("Phase 13.3 complete.\n");
    printf("  connections.json -- TCP/UDP endpoints + process names\n");
    printf("  dns_cache.json   -- DNS resolver cache entries\n\n");
        /* ============================================================
       PHASE 13.4 — REGISTRY INSPECTION
       ============================================================ */

    printf("-- Phase 13.4: Registry Inspection --------------------\n\n");

    /* 13.4a: Run / RunOnce persistence keys */
    printf("[13.4a] Enumerating Run/RunOnce persistence keys...\n");
    printf("        output -> persistence.json\n");
    fflush(stdout);

    int persist_count = JOCKY_enum_persistence("persistence.json");
    if (persist_count < 0) { printf("[13.4a] FAILED\n"); goto bail; }
    printf("[13.4a] ok -- %d persistence entries found\n\n", persist_count);

    /* 13.4b: Services registry */
    printf("[13.4b] Enumerating services registry...\n");
    printf("        output -> services.json\n");
    fflush(stdout);

    int svc_count = JOCKY_enum_services_reg("services.json");
    if (svc_count < 0) { printf("[13.4b] FAILED\n"); goto bail; }
    printf("[13.4b] ok -- %d services enumerated\n\n", svc_count);

    /* 13.4c: TypedURLs */
    printf("[13.4c] Reading TypedURLs (browser address-bar history)...\n");
    printf("        output -> typed_urls.json\n");
    fflush(stdout);

    int url_count = JOCKY_enum_typed_urls("typed_urls.json");
    if (url_count < 0) { printf("[13.4c] FAILED\n"); goto bail; }
    printf("[13.4c] ok -- %d typed URL(s) found\n\n", url_count);

    printf("Phase 13.4 complete.\n");
    printf("  persistence.json  -- Run/RunOnce autostart entries\n");
    printf("  services.json     -- service name + ImagePath + start type\n");
    printf("  typed_urls.json   -- browser address-bar URL history\n\n");    
    
      /* ============================================================
       PHASE 13.5 — FILESYSTEM ANALYSIS
       ============================================================ */

    printf("-- Phase 13.5: Filesystem Analysis -------------------\n\n");

    /* 13.5a: MFT sample — first 500 inodes of C: */
    printf("[13.5a] Reading MFT sample (first 500 inodes of C:)...\n");
    printf("        output -> mft_sample.json\n");
    fflush(stdout);

    int mft_count = JOCKY_scan_mft_sample("C", 500, "mft_sample.json");
    if (mft_count < 0) { printf("[13.5a] FAILED\n"); goto bail; }
    printf("[13.5a] ok -- %d MFT records parsed\n\n", mft_count);

    /* 13.5b: prefetch enumeration */
    printf("[13.5b] Enumerating prefetch files...\n");
    printf("        output -> prefetch.json\n");
    fflush(stdout);

    int pf_count = JOCKY_enum_prefetch("prefetch.json");
    if (pf_count < 0) { printf("[13.5b] FAILED\n"); goto bail; }
    printf("[13.5b] ok -- %d prefetch entries found\n\n", pf_count);

    /* 13.5c: ADS detection on C:\Windows\Temp */
    printf("[13.5c] ADS detection on C:\\Windows\\Temp...\n");
    printf("        output -> ads.json\n");
    fflush(stdout);

    int ads_count = JOCKY_detect_ads("C:\\Windows\\Temp", 500, "ads.json");
    if (ads_count < 0) { printf("[13.5c] FAILED\n"); goto bail; }
    printf("[13.5c] ok -- %d ADS stream(s) detected\n\n", ads_count);

    printf("Phase 13.5 complete.\n");
    printf("  mft_sample.json  -- NTFS file record timestamps\n");
    printf("  prefetch.json    -- executed program list\n");
    printf("  ads.json         -- alternate data streams\n\n");
    
    /* ============================================================
       SUMMARY
       ============================================================ */

    printf("=================================================\n");
    printf("JOCKY Phase 13 -- ALL 5 COLLECTORS PASSED\n");
    printf("=================================================\n");

    if (elevated_child) { printf("\nPress Enter to close...\n"); getchar(); }
    return 0;

bail:
    if (elevated_child) { printf("\nPress Enter to close...\n"); getchar(); }
    return 1;
}