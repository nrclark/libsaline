#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "randombytes_config.h"

static inline void randombytes_stdlib(uint8_t *output, uint64_t length)
{
    while (length-- > 0) {
        *output++ = rand();
    }
}

static inline void randombytes_rand_device(uint8_t *output, uint64_t length,
                                           const char *device)
{
    static int fd = -1;

    if (fd == -1) {
        fd = open(device, O_RDONLY);
        while (fd == -1) {
            sleep(1);
            fd = open(device, O_RDONLY);
        }
    }

    while (length > 0) {
        uint32_t chunk = (length < 1048576) ? length : 1048576;
        uint32_t count = read(fd, output, chunk);

        if (count < 1) {
            sleep(1);
            continue;
        }

        output += count;
        length -= count;
    }
}

static inline void randombytes_urandom(uint8_t *output, uint64_t length)
{
    randombytes_rand_device(output, length, "/dev/urandom");
}

static inline void randombytes_devrandom(uint8_t *output, uint64_t length)
{
    randombytes_rand_device(output, length, "/dev/random");
}

void randombytes(uint8_t *output, uint64_t length)
{
#if defined(RANDOMBYTES_USE_STDLIB)
    randombytes_stdlib(output, length);
#elif defined(RANDOMBYTES_USE_URANDOM)
    randombytes_urandom(output, length);
#elif defined(RANDOMBYTES_USE_DEVRANDOM)
    randombytes_devrandom(output, length);
#else
#error randombytes: no method specified!
#endif
}
