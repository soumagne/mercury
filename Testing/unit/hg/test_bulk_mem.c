/**
 * Copyright (c) 2013-2022 UChicago Argonne, LLC and The HDF Group.
 * Copyright (c) 2022-2024 Intel Corporation.
 * Copyright (c) 2024-2025 Hewlett Packard Enterprise Development LP.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "mercury_unit.h"

#include "mercury_param.h"

/****************/
/* Local Macros */
/****************/

#define HG_TEST_BUF_SIZE  (1024)
#define HG_TEST_BUF_COUNT (65536)

/************************************/
/* Local Type and Struct Definition */
/************************************/

/********************/
/* Local Prototypes */
/********************/

/*******************/
/* Local Variables */
/*******************/

/*---------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
    struct hg_unit_info info;
    hg_return_t hg_ret;
    size_t buf_size = HG_TEST_BUF_SIZE;
    size_t buf_count = HG_TEST_BUF_COUNT;
    size_t i, start_index = 0;
    void **buf_ptrs = NULL;
    void *buf = NULL;
    hg_bulk_t *bulk_handles = NULL;

    /* Initialize the interface */
    hg_ret = hg_unit_init(argc, argv, false, &info);
    HG_TEST_CHECK_HG_ERROR(cleanup, hg_ret, "hg_unit_init() failed (%s)",
        HG_Error_to_string(hg_ret));

    buf_ptrs = malloc(buf_count * sizeof(void *));
    HG_TEST_CHECK_ERROR_NORET(
        buf_ptrs == NULL, cleanup, "malloc(buf_ptrs) failed");

    bulk_handles = calloc(buf_count, sizeof(hg_bulk_t));
    HG_TEST_CHECK_ERROR_NORET(
        bulk_handles == NULL, cleanup, "calloc(bulk_handles) failed");

    buf = calloc(buf_count, buf_size);
    HG_TEST_CHECK_ERROR_NORET(buf == NULL, cleanup, "calloc(buf) failed");

again:
    HG_TEST_LOG_WARNING("Registering %d buffers", (int)(buf_count - start_index));
    for (i = start_index; i < buf_count; i++) {
        buf_ptrs[i] = (char *) buf + i * buf_size;

        hg_ret = HG_Bulk_create(info.hg_class, 1, &buf_ptrs[i], &buf_size,
            HG_BULK_READWRITE, &bulk_handles[i]);
        HG_TEST_CHECK_HG_ERROR(error, hg_ret, "HG_Bulk_create() failed (%s)",
            HG_Error_to_string(hg_ret));
    }

cleanup:
    if (bulk_handles) {
        for (i = 0; i < buf_count; i++) {
            if (bulk_handles[i]) {
                hg_ret = HG_Bulk_free(bulk_handles[i]);
                HG_TEST_CHECK_HG_ERROR(cleanup, hg_ret,
                    "HG_Bulk_free() failed (%s)", HG_Error_to_string(hg_ret));
            }
        }
        free(bulk_handles);
    }
    free(buf);
    free(buf_ptrs);
    hg_unit_cleanup(&info);

    return EXIT_SUCCESS;

error:
    if (hg_ret == HG_NOMEM) {
        HG_TEST_LOG_WARNING("HG_Bulk_create() failed with HG_NOMEM, retrying "
                            "from idx=%d after freeing space...",
            (int) start_index);
        for (i = 0; i < start_index; i++) {
            if (bulk_handles[i]) {
                hg_ret = HG_Bulk_free(bulk_handles[i]);
                HG_TEST_CHECK_HG_ERROR(cleanup, hg_ret,
                    "HG_Bulk_free() failed (%s)", HG_Error_to_string(hg_ret));
                bulk_handles[i] = HG_BULK_NULL;
            }
        }
        start_index = i;
        goto again;
    } else {
        HG_TEST_LOG_ERROR("Cannot retry HG_Bulk_create() after failure");
        goto cleanup;
    }
}
