#ifndef HASHUTIL_COMMON
#define HASHUTIL_COMMON

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#if HASHUTIL_SLOW
#define Assert(Expression) if (!(Expression)) {*(int *)0 = 0;}
#else
#define Assert(Expression)
#endif

#define ArrayCount(Array) (sizeof(Array) / sizeof((Array)[0]))


static bool IsSystemLittleEndian()
{
    uint32_t endianTest = 0xdeadbeef;
    bool isLittleEndian = *(unsigned char *)&endianTest = 0xef;

    return isLittleEndian;
}

static void *MemoryCopy(void *destPtr, void const *sourcePtr, size_t size)
{
    Assert(size > 0);

    unsigned char *source = (unsigned char *)sourcePtr;
    unsigned char *dest = (unsigned char *)destPtr;
    while(size--) *dest++ = *source++;

    return destPtr;
}

static void *MemorySet(uint8_t *destPtr, int c, size_t count)
{
    Assert(count > 0);

    unsigned char *dest = (unsigned char *)destPtr;
    while(count--) *dest++ = (unsigned char)c;

    return destPtr;
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

// 32bit Circular bit shift left
static uint32_t ROTL(uint32_t value, uint8_t count)
{
    return (value << count) | (value >> (32 - count));
}

// 32bit Circular bit shift right
static uint32_t ROTR32(uint32_t value, uint8_t count)
{
    return (value >> count) | (value << (32 - count));
}

// 64bit Circular bit shift right
static uint64_t ROTR64(uint64_t value, uint8_t count)
{
    return (value >> count) | (value << (64 - count));
}

#endif
