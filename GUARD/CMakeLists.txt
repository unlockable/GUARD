cmake_minimum_required(VERSION 3.15)

# Set the project name
project(GUARD)

# Enable C++ standard for the GUARD project
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set policies to avoid deprecated OLD behaviors
if (POLICY CMP0048)
    cmake_policy(SET CMP0048 NEW)  # Project version must be specified
endif()

if (POLICY CMP0051)
    cmake_policy(SET CMP0051 NEW)  # List TARGET_OBJECTS in SOURCES
endif()

# Fetch Capstone, Unicorn, and Keystone using FetchContent
include(FetchContent)

FetchContent_Declare(
    capstone
    GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
    GIT_TAG        5.0
)
FetchContent_MakeAvailable(capstone)

FetchContent_Declare(
    unicorn
    GIT_REPOSITORY https://github.com/unicorn-engine/unicorn.git
    GIT_TAG        2.0.0
)
FetchContent_MakeAvailable(unicorn)

FetchContent_Declare(
    keystone
    GIT_REPOSITORY https://github.com/keystone-engine/keystone.git
    GIT_TAG        e1547852d9accb9460573eb156fc81645b8e1871  
)
FetchContent_MakeAvailable(keystone)

# Ensure Capstone and Keystone are built as static libraries
set(CAPSTONE_BUILD_STATIC ON)
set(KESTONE_BUILD_STATIC ON)

# Disable shared libraries globally to prevent conflicts
set(BUILD_SHARED_LIBS OFF)

# Add the executable for the GUARD project
add_executable(GUARD 
    GUARD/main.cpp 
    GUARD/disassembler.cpp 
    GUARD/instruction.cpp 
    GUARD/module_view.cpp
    GUARD/GUARD.cpp
    GUARD/pe_constructor.cpp
)

# Include directories for Capstone, Unicorn, and Keystone
target_include_directories(GUARD PRIVATE 
    ${capstone_SOURCE_DIR}/include
    ${keystone_SOURCE_DIR}/include
    ${unicorn_SOURCE_DIR}/include
)

# Link Capstone, Keystone, and Unicorn libraries to GUARD executable
target_link_libraries(GUARD PRIVATE 
    capstone
    keystone
    unicorn
)

# If needed, specify where to look for the binary outputs
target_link_directories(GUARD PRIVATE 
    ${capstone_BINARY_DIR}/Release
    ${keystone_BINARY_DIR}/Release
)

# Ensure Keystone uses C++11
set_property(TARGET keystone PROPERTY CXX_STANDARD 11)
set_property(TARGET keystone PROPERTY CXX_STANDARD_REQUIRED ON)
