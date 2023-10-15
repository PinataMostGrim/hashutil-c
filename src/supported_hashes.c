#include <assert.h>
#include <string.h>

#include "supported_hashes.h"


static hash_algorithm GetHashAlgorithm(char *algorithmPtr)
{
    for (int i = 0; i < hash_algorithm_count; ++i)
    {
        if (strcmp(algorithmPtr, HashAlgorithmMnemonics[i]) == 0)
        {
            return (hash_algorithm)i;
        }
    }

    return hash_unknown;
}


static const char *GetHashMenemonic(hash_algorithm algorithm)
{
    hashutil_static_assert(ArrayCount(HashAlgorithmMnemonics) == hash_algorithm_count,
              "'hash_algorithm' and 'HashAlgorithmMnemonics' do not share the sane number of elements\n");

    return HashAlgorithmMnemonics[algorithm];
}
