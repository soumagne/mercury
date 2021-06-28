#ifndef UTIL_H_
#define UTIL_H_

#include <stdint.h> /* uint8_t */
#include <unistd.h> /* size_t */

#define NELTS(a)   (sizeof(a) / sizeof((a)[0]))

#if defined(__GNUC__)
#   define wireup_printf_like(fmt,firstarg)    \
    __attribute__((format(printf, fmt, firstarg)))
#endif

int colon_separated_octets_to_bytes(const char *, uint8_t **, size_t *);

size_t twice_or_max(size_t);

void *header_alloc(size_t, size_t, size_t);
void header_free(size_t, size_t, void *);

#endif /* UTIL_H_ */
