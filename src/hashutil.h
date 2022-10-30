#if !defined(HASHUTIL_H)

/*
    Note (Aaron):
    HASHUTIL_SLOW:
        0 - No slow code allowed!
        1 - Slow code welcome
*/

#if HASHUTIL_SLOW
#define Assert(Expression) if (!(Expression)) {*(int *)0 = 0;}
#else
#define Assert(Expression)
#endif

#define ArrayCount(Array) (sizeof(Array) / sizeof((Array)[0]))

#endif
