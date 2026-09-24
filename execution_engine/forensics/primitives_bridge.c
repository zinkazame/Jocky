#include <stdio.h>
#include <windows.h>
#include "forensics.h"

int JOCKY_main(void);

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    return JOCKY_main();
}

int JOCKY_acquire_process_list(void) {
    return JOCKY_full_process_report("procs.json") ? 0 : 1;
}

int JOCKY_acquire_memory_region(int pid, long long size) {
    return JOCKY_dump_suspicious((DWORD)pid, "suspicious.json", NULL, (SIZE_T)size) >= 0 ? 0 : 1;
}

int JOCKY_acquire_cpu_registers(void) {
    return 0;
}

int JOCKY_acquire_connections(void) {
    return JOCKY_enum_connections("connections.json") >= 0 ? 0 : 1;
}

int JOCKY_acquire_dns_cache(void) {
    return JOCKY_dns_cache("dns.json") >= 0 ? 0 : 1;
}

int JOCKY_capture_traffic(int duration, const char *iface) {
    (void)duration; (void)iface;
    return 0;
}

int JOCKY_inspect_registry(const char *key) {
    (void)key;
    return JOCKY_reg_report("registry.json") ? 0 : 1;
}

int JOCKY_inspect_services(const char *state) {
    (void)state;
    return JOCKY_enum_services_reg("services.json") >= 0 ? 0 : 1;
}

int JOCKY_inspect_startup_items(void) {
    return JOCKY_enum_persistence("startup.json") >= 0 ? 0 : 1;
}

int JOCKY_inspect_file_metadata(const char *path) {
    (void)path;
    return 0;
}

int JOCKY_inspect_recent_files(int count) {
    (void)count;
    return JOCKY_enum_prefetch("prefetch.json") >= 0 ? 0 : 1;
}

int JOCKY_hash_file(const char *path) {
    (void)path;
    return 0;
}
