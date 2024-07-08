#define LOG_TAG "[ANC][custom]"

#include <linux/kernel.h>

// clang-format off
#include "jiiov_log.h"
#include "jiiov_platform.h"
// clang-format on

void clear_last_touch_state(void) {
    ANC_LOGD("nothing clear");
    // todo
}

int custom_init(void) {
    int ret_val = 0;

    // todo

    return ret_val;
}

void custom_deinit(void) {
    // todo
}
