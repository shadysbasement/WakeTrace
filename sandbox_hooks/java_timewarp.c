#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static long long offset_seconds(void) {
    const char *value = getenv("WAKETRACE_OFFSET_SEC");
    if (!value || !*value) return 0;
    return strtoll(value, NULL, 10);
}

int clock_gettime(clockid_t clock, struct timespec *result) {
    int status = syscall(SYS_clock_gettime, clock, result);
    if (status == 0 && (clock == CLOCK_REALTIME || clock == CLOCK_REALTIME_COARSE))
        result->tv_sec += offset_seconds();
    return status;
}

int gettimeofday(struct timeval *result, void *zone) {
    int status = syscall(SYS_gettimeofday, result, zone);
    if (status == 0) result->tv_sec += offset_seconds();
    return status;
}

time_t time(time_t *result) {
    struct timespec current;
    if (clock_gettime(CLOCK_REALTIME, &current) != 0) return (time_t)-1;
    if (result) *result = current.tv_sec;
    return current.tv_sec;
}
