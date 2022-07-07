cmake_minimum_required(VERSION 3.11)

# These configurations before "project":
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(ifenum VERSION 1.0 LANGUAGES CXX)
# The version number.
set(APP_VERSION_MAJOR "1")
set(APP_VERSION_MINOR "0")
set(APP_VERSION_PATCH "2")
set(APP_VERSION_STRING "${APP_VERSION_MAJOR}.${APP_VERSION_MINOR}.${APP_VERSION_PATCH}")

add_executable(ifenum main.cpp)
target_compile_features(ifenum PUBLIC "cxx_std_20")
configure_file(ifenum_config.h.in ifenum_config.h)
# Find includes in corresponding build directories
set(CMAKE_INCLUDE_CURRENT_DIR ON)

include(GNUInstallDirs)
if(NOT WIN32 AND CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    #set(CMAKE_INSTALL_PREFIX "/opt/${PROJECT_NAME}")
    set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()

include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported OUTPUT error)

option(enable_asan "build with address sanitizer" FALSE)
option(enable_ubsan "build with undefined behavior sanitizer" FALSE)
option(WITH_LTO "build with link-time (inter-procedural) optimization (LTO, IPO)" TRUE)

# Optional compiler options:
target_compile_options(ifenum PRIVATE -march=native -Wall -Werror)
target_compile_options(ifenum PRIVATE -Wextra)

# Optional sanitizers
# see https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html
#
# with sanatize=address: At runtime set environment variable
#   "ASAN_OPTIONS=detect_stack_use_after_return=1"

# note, that if both asan and ubsan are used, asan must appear first in
# the list of libraries
if(asan)
    message("Enabling memory address sanitizer (ASAN)")
    target_compile_options(ifenum PRIVATE -fsanitize=address)
    target_link_libraries(ifenum PRIVATE asan)
endif()

if(ubsan)
    message("Enabling undefined behavior sanitizer (UBSAN)")
    target_compile_options(ifenum PRIVATE -fsanitize=undefined)
    target_link_libraries(ifenum PRIVATE ubsan)
endif()

if(${WITH_LTO})
    if(${ipo_supported})
        set_property(TARGET ifenum PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
    else()
        message(SEND_ERROR "inter-procedural optimization (LTO) requested but not supported")
    endif()
endif()

install(TARGETS ifenum RUNTIME DESTINATION bin)
