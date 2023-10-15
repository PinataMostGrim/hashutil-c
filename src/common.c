#ifndef HASHUTIL_COMMON
#define HASHUTIL_COMMON

#include <stdint.h>
#include <stdbool.h>

#if HASHUTIL_SLOW
#include <assert.h>
#define hashutil_static_assert(expression, string) static_assert(expression, string)
#define hashutil_assert(expression) assert(expression)
#else
#define hashutil_static_assert(expression, string)
#define hashutil_assert(Expression)
#endif

#define ArrayCount(Array) (sizeof(Array) / sizeof((Array)[0]))


static bool IsSystemLittleEndian()
{
    uint32_t endianTest = 0xdeadbeef;
    bool isLittleEndian = (*(unsigned char *)&endianTest == 0xef);

    return isLittleEndian;
}

static void *MemoryCopy(void *destPtr, void const *sourcePtr, size_t size)
{
    hashutil_assert(size > 0);

    unsigned char *source = (unsigned char *)sourcePtr;
    unsigned char *dest = (unsigned char *)destPtr;
    while(size--) *dest++ = *source++;

    return destPtr;
}

// TODO (Aaron): memset_explicit() uses this function signature and converts 'c'
// into an unsigned char. I don't fully understand why. Investigate.
// - [link](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n2897.htm)
// TODO (Aaron): 'memset()' may be optimized away by the compiler if the
// object it operates on is never accessed again and can't be used to scrub
// sensitive information from memory.
// Look into whether or not the same thing occurs with this method.
static void *MemorySet(uint8_t *destPtr, int c, size_t count)
{
    hashutil_assert(count > 0);

    unsigned char *dest = (unsigned char *)destPtr;
    while(count--) *dest++ = (unsigned char)c;

    return destPtr;
}

// TODO (Aaron): I should test the speed of mirroring bits this way
// vs the method used for loading message blocks into the W[] registers

// TODO (Aaron): Test this
// Swap endianness of 16 bit value
static void MirrorBits16(uint16_t *bits)
{
    *bits = ((*bits >> 8) & 0xff00)
          | ((*bits << 8) & 0xff00);
}

// TODO (Aaron): Test this
// Swap endianness of 32 bit value
static void MirrorBits32(uint32_t *bits)
{
    *bits = ((*bits >> 24) & 0xff000000)
          | ((*bits >> 8) & 0xff000000)
          | ((*bits << 8) & 0xff000000)
          | ((*bits << 24) & 0xff000000);
}

// Swap endianness of 64 bit value
static void MirrorBits64(uint64_t *bits)
{
    *bits = ((*bits >> 56) & 0xff)
         | ((*bits >> 40) & 0xff00)
         | ((*bits >> 24) & 0xff0000)
         | ((*bits >> 8) & 0xff000000)
         | ((*bits << 8) & 0xff00000000)
         | ((*bits << 24) & 0xff0000000000)
         | ((*bits << 40) & 0xff000000000000)
         | ((*bits << 56) & 0xff00000000000000);
}

// 32-bit Circular bit shift left
static uint32_t ROTL(uint32_t value, uint8_t count)
{
    return (value << count) | (value >> (32 - count));
}

// 32-bit Circular bit shift right
static uint32_t ROTR32(uint32_t value, uint8_t count)
{
    return (value >> count) | (value << (32 - count));
}

// 64-bit Circular bit shift right
static uint64_t ROTR64(uint64_t value, uint8_t count)
{
    return (value >> count) | (value << (64 - count));
}

#endif
