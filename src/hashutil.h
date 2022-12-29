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

#endif
