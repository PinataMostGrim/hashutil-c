/* TODO (Aaron):
    - Add error flag and messages to all context structs and return from hash methods rather than exit program
    - Add compare hash functionality ('-c' or '--compare' sets COMPARE_FLAG bool)
    - Support case insensitive algorithm strings
    - Add a method to each header for retrieving supported algorithms?

    - Create library for parsing command line arguments
    - Consider compiling hashutil with C++ to take advantage of some features (declare arra of const strings)
    - Enforce C99 in build batch files
*/

/*  hashutil.c

    Command line application that hashes files and strings using the MD5 and SHA1-SHA2
    family of algorithms. Run 'hashutil --help' for usage instructions.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define HASHUTIL_MD5_IMPLEMENTATION
#include "md5.h"
#define HASHUTIL_SHA1_IMPLEMENTATION
#include "sha1.h"
#define HASHUTIL_SHA2_IMPLEMENTATION
#include "sha2.h"


#define ArrayCount(Array) (sizeof(Array) / sizeof((Array)[0]))


static char *HashAlgorithmMnemonics[] =
{
    "unknown",
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha512-224",
    "sha512-256",
};


typedef enum hash_algorithm
{
    hash_unknown,
    hash_md5,
    hash_sha1,
    hash_sha224,
    hash_sha256,
    hash_sha384,
    hash_sha512,
    hash_sha512_224,
    hash_sha512_256,

    hash_algorithm_count,

} hash_algorithm;


typedef struct arguments
{
    bool usageFlag;
    bool listFlag;
    bool fileFlag;
    bool algorithmConsumed;
    bool messageConsumed;
    char *algorithmPtr;
    hash_algorithm algorithm;
    char *messagePtr;
} arguments;


hash_algorithm GetHashAlgorithm(char *algorithmPtr)
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


char *GetHashMenemonic(hash_algorithm algorithm)
{
    static_assert(ArrayCount(HashAlgorithmMnemonics) == hash_algorithm_count,
              "'hash_algorithm' and 'HashAlgorithmMnemonics' do not share the sane number of elements\n");

    return HashAlgorithmMnemonics[algorithm];
}


static void PrintUsage()
{
    printf("usage: hashutil [-l -f -h] algorithm message\n\n");
    printf("Produces a message or file digest using various hashing algorithms.\n\n");

    printf("positional arguments:\n");
    printf("  algorithm\t\tHashing algorithm to use\n");
    printf("  message\t\tMessage to hash\n");
    printf("\n");

    printf("options:\n");
    printf("-l, --list\t\tList all supported hashing algorithms\n");
    printf("-f, --file\t\tHashes a file. Message is treated as a path\n");
    printf("-h, --help\t\tPrints these usage instructions\n");
    printf("\n");
}


static void PrintSupportedAlgorithms()
{
    printf("Algorithms supported:\n");
    printf(" ");
    // Note (Aaron): Initialize 'i' to 1 to skip "unknown"
    for (int i = 1; i < ArrayCount(HashAlgorithmMnemonics); ++i)
    {
        printf(" %s", HashAlgorithmMnemonics[i]);
    }

    printf("\n");
}


static void PrintErrorAndExit(char *errorStr)
{
    printf("ERROR: %s\n", errorStr);
    exit(1);
}


void ParseArgs(int argc, char const *argv[], arguments *arguments)
{
    bool processOptionalArgs = true;
    bool algorithmConsumed = false;
    bool messageConsumed = false;

    arguments->usageFlag = false;
    arguments->listFlag = false;
    arguments->fileFlag = false;
    arguments->algorithmPtr = (char *)"";
    arguments->messagePtr = (char *)"";

    for (int i = 1; i < argc; ++i)
    {
        if ((strncmp(argv[i], "-h", 2) == 0) || (strncmp(argv[i], "--help", 6) == 0))
        {
            arguments->usageFlag = true;
            break;
        }

        if ((strncmp(argv[i], "-l", 2) == 0) || (strncmp(argv[i], "--list", 6) == 0))
        {
            arguments->listFlag = true;
            break;
        }

        if (strcmp(argv[i], "--") == 0)
        {
            processOptionalArgs = false;
            continue;
        }

        if (processOptionalArgs
            && ((strncmp(argv[i], "-f", 2) == 0) || (strncmp(argv[i], "--file", 6) == 0)))
        {
            arguments->fileFlag = true;
            continue;
        }

        if (!algorithmConsumed)
        {
            // TODO (Aaron): What kind of sanitization do I need to do to this input?
            arguments->algorithmPtr = (char *)argv[i];
            algorithmConsumed = true;
            continue;
        }

        if (!messageConsumed)
        {
            // TODO (Aaron): What kind of sanitization do I need to do to this input?
            arguments->messagePtr = (char *)argv[i];
            messageConsumed = true;
            continue;
        }
    }
}


int main(int argc, char const *argv[])
{
    arguments arguments;
    ParseArgs(argc, argv, &arguments);

    if (arguments.usageFlag)
    {
        PrintUsage();
        return 0;
    }

    if (arguments.listFlag)
    {
        PrintSupportedAlgorithms();
        return 0;
    }

    // Error out on missing or invalid arguments
    if (strlen(arguments.algorithmPtr) == 0)
    {
        printf("ERROR: 'algorithm' argument missing\n");
        PrintUsage();
        return 1;
    }

    if(strlen(arguments.messagePtr) == 0)
    {
        printf("ERROR: 'message' argument missing\n");
        PrintUsage();
        return 1;
    }

    // Control flow on the selected algorithm and hash
    hash_algorithm algorithm = GetHashAlgorithm(arguments.algorithmPtr);
    printf("%s %s\t: %s\n",
        GetHashMenemonic(algorithm),
        arguments.fileFlag ? "[file]" : "[string]",
        arguments.messagePtr);

    char *digest;
    switch (algorithm)
    {
        case hash_md5:
        {
            md5_context context;
            if(arguments.fileFlag)
            {
                context = MD5HashFile(arguments.messagePtr);
            }
            else
            {
                context = MD5HashString(arguments.messagePtr);
            }

            digest = context.DigestStr;
            break;
        }
        case hash_sha1:
        {
            sha1_context context;
            if(arguments.fileFlag)
            {
                context = SHA1HashFile(arguments.messagePtr);
            }
            else
            {
                context = SHA1HashString(arguments.messagePtr);
            }

            digest = context.DigestStr;
            break;
        }
        case hash_sha224:
        {
            sha2_256_context context;
            if(arguments.fileFlag)
            {
                context = SHA2_HashFileSHA224(arguments.messagePtr);
            }
            else
            {
                context = SHA2_HashStringSHA224(arguments.messagePtr);
            }

            if (context.Error)
            {
                PrintErrorAndExit(context.ErrorStr);
            }

            digest = context.DigestStr;
            break;
        }
        case hash_sha256:
        {
            sha2_256_context context;
            if(arguments.fileFlag)
            {
                context = SHA2_HashFileSHA256(arguments.messagePtr);
            }
            else
            {
                context = SHA2_HashStringSHA256(arguments.messagePtr);
            }

            if (context.Error)
            {
                PrintErrorAndExit(context.ErrorStr);
            }

            digest = context.DigestStr;
            break;
        }
        case hash_sha512_224:
        {
            sha2_512_context context;
            if(arguments.fileFlag)
            {
                context = SHA2_HashFileSHA512_224(arguments.messagePtr);
            }
            else
            {
                context = SHA2_HashStringSHA512_224(arguments.messagePtr);
            }

            if (context.Error)
            {
                PrintErrorAndExit(context.ErrorStr);
            }

            digest = context.DigestStr;
            break;
        }
        case hash_sha512_256:
        {
            sha2_512_context context;
            if(arguments.fileFlag)
            {
                context = SHA2_HashFileSHA512_256(arguments.messagePtr);
            }
            else
            {
                context = SHA2_HashStringSHA512_256(arguments.messagePtr);
            }

            if (context.Error)
            {
                PrintErrorAndExit(context.ErrorStr);
            }

            digest = context.DigestStr;
            break;
        }
        case hash_sha384:
        {
            sha2_512_context context;
            if(arguments.fileFlag)
            {
                context = SHA2_HashFileSHA384(arguments.messagePtr);
            }
            else
            {
                context = SHA2_HashStringSHA384(arguments.messagePtr);
            }

            if (context.Error)
            {
                PrintErrorAndExit(context.ErrorStr);
            }

            digest = context.DigestStr;
            break;
        }
        case hash_sha512:
        {
            sha2_512_context context;
            if(arguments.fileFlag)
            {
                context = SHA2_HashFileSHA512(arguments.messagePtr);
            }
            else
            {
                context = SHA2_HashStringSHA512(arguments.messagePtr);
            }

            if (context.Error)
            {
                PrintErrorAndExit(context.ErrorStr);
            }

            digest = context.DigestStr;
            break;
        }
        default:
        {
            printf("ERROR: Unsupported algorithm selected\n");
            return 1;
        }
    }

    printf("%s\n", digest);
    return 0;
}
