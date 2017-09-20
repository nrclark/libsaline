#ifndef _RANDOMBYTES_H_
#define _RANDOMBYTES_H_

#include <stdint.h>

/* This library provides the randombytes() function needed by ua_nacl
 * for generating random numbers. In order to compile it, a config
 * file called "randombytes_config.h" should be placed in the search
 * compiler's search path.
 * 
 * In the file, one (and only one) symbol should be defined to specify
 * the flavor of RNG. At the time of this writing, the three possible
 * symbols are:
 * 
 * RANDOMBYTES_USE_URANDOM
 * Use /dev/urandom to generate random numbers. Works great on Linux-flavored
 * OSes.
 * 
 * RANDOMBYTES_USE_DEVRANDOM
 * Use /dev/random to generate random numbers. Works terrible on Linux, and
 * great on most other Unixlikes.
 *
 * RANDOMBYTES_USE_STDLIB
 * Use the deterministic stdlib. This. Is. Not. Random. Don't use it in any
 * system which is generating keys, because those keys WILL NOT BE UNIQUE.
 * 
 * If some other behavior is desired, randombytes can be implemented elsewhere.
 * It's a simple function that generates 'length' random bytes and writes
 * them into *output. */

void randombytes(unsigned char *output, uint64_t length);

#endif
