/*  test-shared-library.c

    Test driver for ensuring the usage of md5.h, sha1.h and sha2.h as DLLs.
*/

#include "md5.h"
#include "sha1.h"
#include "sha2.h"

#include <stdio.h>
#include <stdint.h>

#pragma comment (lib, "md5.lib")
#pragma comment (lib, "sha1.lib")
#pragma comment (lib, "sha2.lib")

int main(int argc, char const *argv[])
{
    printf("\n");
    char *messagePtr = (char *)"";


    uint32_t md5Version = MD5_GetVersion();
    printf("md5.h version: %i\n", md5Version);

    messagePtr = (char *)"abcde";
    md5_context md5Context = MD5_HashString(messagePtr);
    printf("sha1 digest for 'abcde': %s\n", md5Context.DigestStr);
    printf("\n");


    uint32_t sha1Version = SHA1_GetVersion();
    printf("sha1.h version: %i\n", sha1Version);

    messagePtr = (char *)"abcde";
    sha1_context sha1Context = SHA1_HashString(messagePtr);
    printf("sha1 digest for 'abcde': %s\n", sha1Context.DigestStr);
    printf("\n");

    uint32_t sha2Version = SHA2_GetVersion();
    printf("sha2.h version: %i\n", sha2Version);

    messagePtr = (char *)"abcde";
    sha2_256_context sha256Context = SHA2_HashStringSHA256(messagePtr);
    printf("sha256 digest for 'abcde': %s\n", sha256Context.DigestStr);
    printf("\n");

    return 0;
}
