#!/bin/bash

# This script automates the build process for the project.
# It ensures a clean build by removing the old build directory,
# installs Conan dependencies, configures CMake using presets,
# and finally builds and runs the tests.

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
BUILD_DIR="cmake-build-debug"
BUILD_TYPE="Debug"
# You can change the target to build everything by leaving it empty: BUILD_TARGET=""
BUILD_TARGET=""
CORES=$(( $(nproc) - 4 ))

# --- Colors for output ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# --- Script Start ---
echo -e "${YELLOW}Starting the build process...${NC}"

# 1. Clean the previous build directory.
echo -e "\n${GREEN}--> Step 1: Cleaning previous build directory...${NC}"
rm -rf "$BUILD_DIR"
echo "Directory '$BUILD_DIR' removed."

# 2. Install Conan dependencies.
echo -e "\n${GREEN}--> Step 2: Installing Conan dependencies...${NC}"
conan install . -s build_type="$BUILD_TYPE" --output-folder="$BUILD_DIR" --build=missing

# 3. Configure the CMake project using the Conan-generated preset.
echo -e "\n${GREEN}--> Step 3: Configuring CMake project...${NC}"
# The preset name is constructed from "conan-" and the lowercase build type.
PRESET_NAME="conan-$(echo "$BUILD_TYPE" | tr '[:upper:]' '[:lower:]')"
cmake --preset "$PRESET_NAME"

# 4. Build the specified target.
echo -e "\n${GREEN}--> Step 4: Building target '$BUILD_TARGET' with $CORES cores...${NC}"
if [ -z "$BUILD_TARGET" ]; then
    cmake --build --preset "$PRESET_NAME" --parallel "${CORES}"
else
    cmake --build --preset "$PRESET_NAME" --target "$BUILD_TARGET" --parallel "${CORES}"
fi

# 5. Run the tests using CTest.
echo -e "\n${GREEN}--> Step 5: Running tests...${NC}"
BUILD_SUBDIR="$BUILD_DIR/build"

#Might have to change this config
CONFIG=${CMAKE_BUILD_TYPE:-Debug}

if [ -d "$BUILD_SUBDIR/$CONFIG" ]; then
  TEST_DIR="$BUILD_SUBDIR/$CONFIG"
else
  TEST_DIR="$BUILD_SUBDIR"
fi

cd "$TEST_DIR"
ctest --output-on-failure

 # back to the project root
cd - > /dev/null

echo -e "\n${YELLOW}Build and test script finished successfully!${NC}"

