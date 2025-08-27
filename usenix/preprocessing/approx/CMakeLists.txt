cmake_minimum_required(VERSION 3.16)
project(DHFTest LANGUAGES CXX)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

#---------------------------------------
# pybind11
#---------------------------------------
execute_process(
    COMMAND python3 -m pybind11 --cmakedir
    OUTPUT_VARIABLE pybind11_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

set(pybind11_DIR ${pybind11_DIR} CACHE PATH "Path to pybind11Config.cmake")
find_package(pybind11 REQUIRED)

#---------------------------------------
# NTL (shared library)
#---------------------------------------
set(NTL_INCLUDE_DIR "/usr/local/include")  # headers installed by make install
find_library(NTL_LIBRARY NAMES ntl PATHS /usr/local/lib)

if(NOT NTL_LIBRARY)
  message(FATAL_ERROR "NTL library not found in /usr/local/lib")
endif()

#---------------------------------------
# GMP (required by NTL)
#---------------------------------------
find_path(GMP_INCLUDE_DIR NAMES gmp.h)
find_library(GMP_LIBRARY NAMES gmp)
find_library(GMPXX_LIBRARY NAMES gmpxx)

if(NOT GMP_INCLUDE_DIR OR NOT GMP_LIBRARY OR NOT GMPXX_LIBRARY)
  message(FATAL_ERROR "GMP / GMPXX not found. Please install libgmp-dev.")
endif()

#---------------------------------------
# Core C++ library (no pybind11 here!)
#---------------------------------------
add_library(dhf_core SHARED
    src/DetectableHashFunction.cpp
)

target_include_directories(dhf_core PUBLIC
    inc
    ${NTL_INCLUDE_DIR}
    ${GMP_INCLUDE_DIR}
)

target_link_libraries(dhf_core PUBLIC
    ${NTL_LIBRARY}
    ${GMP_LIBRARY}
    ${GMPXX_LIBRARY}
)

set_target_properties(dhf_core PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

#---------------------------------------
# Python module (pybind11 bindings)
#---------------------------------------
pybind11_add_module(dhf
    src/dhf_bindings.cpp
)

target_link_libraries(dhf PRIVATE dhf_core)

set_target_properties(dhf PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

#---------------------------------------
# Executable for testing (pure C++)
#---------------------------------------
add_executable(dhf_main
    src/main.cpp
)

target_link_libraries(dhf_main PRIVATE dhf_core)

set_target_properties(dhf_main PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)
