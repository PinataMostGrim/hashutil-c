# Build script for hashutil-c.

# Save the script's folder
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# Set the DEBUG environment variable to 0 if
# it isn't already defined
if [ -z $DEBUG ]
then
    DEBUG=0
fi

if [ $DEBUG = "1" ]
then
    # Making debug build
    CompilerFlags="-g -DHASHUTIL_SLOW=1"
else
    # Making release build
    CompilerFlags="-DHASHUTIL_SLOW=0"
fi

BuildFolder="bin"

# Create build folder if it doesn't exist
mkdir -p "$SCRIPT_DIR/$BuildFolder"

# Change to the build folder (and redirect stdout to /dev/null and the redirect stderr to stdout)
pushd $BuildFolder > /dev/null 2>&1

# Compile hashutil
clang $CompilerFlags "$SCRIPT_DIR/src/hashutil.cpp" -o "hashutil"
popd > /dev/null 2>&1
