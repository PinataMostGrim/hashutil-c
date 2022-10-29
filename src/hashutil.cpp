#include <stdio.h>
#include "hashutil.h"

int main(int argc, char const *argv[])
{
    for (int i = 0; i < argc; ++i)
    {
        printf("Argument %i: %s\n", i, argv[i]);
    }

    return 0;
}
