# hashutil
`hashutil` is a command line application written in C that hashes files and strings using the MD5 and SHA1-SHA2 family of algorithms. In addition, hashutil aims to include algorithm implementations as stb-style (single file) headers for use with C/C++ under a maximally permissive license.

**NOTE:** This project is being written primarily to learn programming in C as well as static analysis, fuzzing, and performance optimization on a small code-base. Work is on-going and the API will almost certainly change so use currently entirely at your own risk. A long-term project goal is to be usable on the widest variety of hardware possible but it will be a long road getting there. Constructive criticism and feedback welcome.


## Building
### Windows
`hashutil` can be built on Windows by running `build-hashutil.bat` from the project root. Requirements are as follows:
- MSVC accessible from PATH
- `vcvarsall.bat x64` run in the shell before the batch file is executed
- Batch file must be executed from the project root

The test runners (`test-hashutil` and `test-shared-library`) can be built on Windows by running `build-test-hashutil.bat` and `build-test-lib.bat` respectively. They have the same build requirements as `hashutil`.

### Linux
`hashutil` can be built on Linux by running `buld-hashutil.sh`.
Requirements are as follows:
- clang accessible from PATH
- Shell script must be executed from the project root

`test-hashutil` can be built on Linux by running `build-test-hashutil.sh`. It has the same build requirements as `hashutil`.


## Usage
`hashutil` usage:
```
usage: hashutil [-l -f -h] algorithm message

Produces a message or file digest using various hashing algorithms.

positional arguments:
  algorithm             Hashing algorithm to use
  message               Message to hash

options:
-l, --list              List all supported hashing algorithms
-f, --file              Hashes a file. Message is treated as a path
-h, --help              Prints these usage instructions
```

See header files for their individual usage instructions.


## Special Thanks
Special thanks to:
- Sean T. Barrett (https://github.com/nothings)
- Casey Muratori (https://github.com/cmuratori)
