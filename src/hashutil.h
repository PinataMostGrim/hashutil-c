#if !defined(HASHUTIL_H)

/*
    Note (Aaron):
    HASHUTIL_SLOW:
        0 - No slow code allowed!
        1 - Slow code welcome
*/

#include <stdint.h>

#define internal static
#define global_variable static

typedef uint8_t uint8;
typedef uint32_t uint32;
typedef uint64_t uint64;

#if HASHUTIL_SLOW

#define Assert(Expression) if (!(Expression)) {*(int *)0 = 0;}
#else
#define Assert(Expression)
#endif

#define ArrayCount(Array) (sizeof(Array) / sizeof((Array)[0]))

// Note (Aaron): This is a naive implementation
internal void
MemoryCopy(const uint8 *source, uint8 *destination, size_t count)
{
    for (int i = 0; i < count; ++i)
    {
        *(destination + i) = *(source + i);
    }
}

internal void
MemoryZero(uint8 *ptr, size_t count)
{
    for (int i = 0; i < count; ++i)
    {
        *(ptr + i) = 0;
    }
}

internal uint32
CircularBitShiftLeft(uint32 value, uint8 count)
{
    return (value << count) | (value >> (32-count));
}

#define HASHUTIL_H
#endif
