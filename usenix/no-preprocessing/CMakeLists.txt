# All deps are installed locally, the first build may
# take a little longer becuase everything is fetched and build
# from source in the self contained directory
project(Dpsi)
cmake_minimum_required(VERSION 3.22)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_STANDARD 17)
#set(CMAKE_EXE_LINKER_FLAGS "-static -static-libgcc -static-libstdc++")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -I/usr/include/c++/11 -I/usr/include/x86_64-linux-gnu/c++/11 -fcoroutines")
include_directories("${CMAKE_CURRENT_LIST_DIR}/inc/")
include_directories("${CMAKE_CURRENT_LIST_DIR}/proto/")

# find the protobug include dirs
include_directories("${CMAKE_BINARY_DIR}/_deps/grpc-src/third_party/protobuf/src/")
include_directories("${CMAKE_BINARY_DIR}/_deps/grpc-src/include/")
include_directories("${CMAKE_BINARY_DIR}/_deps/grpc-src/third_party/abseil-cpp")
include(ExternalProject)
include(FetchContent)

set(FETCHCONTENT_QUIET OFF)
set(BOOST_INCLUDE_LIBRARIES  program_options property_tree)
set(BOOST_ENABLE_CMAKE ON)
FetchContent_Declare(
  Boost
  GIT_REPOSITORY https://github.com/boostorg/boost.git
  GIT_TAG boost-1.87.0
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(Boost)
# Fetch and build dependencies

# Get the NTL
#FetchContent_Declare(
#    NTL
#    GIT_REPOSITORY https://github.com/libntl/ntl.git
#    GIT_TAG        main
#)
#FetchContent_MakeAvailable(ntl)

ExternalProject_Add(
  ntl
  URL https://www.shoup.net/ntl/ntl-11.5.1.tar.gz
  URL_HASH SHA256=210d06c31306cbc6eaf6814453c56c776d9d8e8df36d74eb306f6a523d1c6a8a
  CONFIGURE_COMMAND ./configure PREFIX=${CMAKE_BINARY_DIR}/ntl-install
  BUILD_COMMAND make
  INSTALL_COMMAND make install
  BUILD_IN_SOURCE 1
  SOURCE_SUBDIR src
)

set(NTL_INCLUDE_DIR ${CMAKE_BINARY_DIR}/ntl-install/include)
set(NTL_LIBRARY ${CMAKE_BINARY_DIR}/ntl-install/lib/libntl.a)

link_directories(${CMAKE_BINARY_DIR}/ntl-install/lib)
include_directories(${CMAKE_BINARY_DIR}/ntl-install/include)

FetchContent_Declare(
  Catch2
  GIT_SHALLOW    TRUE
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        devel
)
FetchContent_MakeAvailable(Catch2)

# Get CryptoPP
#FetchContent_Declare(
#    cryptopp
#    GIT_REPOSITORY https://github.com/weidai11/cryptopp.git
#    GIT_TAG        master
#)
#FetchContent_MakeAvailable(cryptopp)

# include_directories(${cryptopp_SOURCE_DIR})


set(ABSL_ENABLE_INSTALL ON)

# # # # NEEDED for gRPC

FetchContent_Declare(
  grpc
  GIT_REPOSITORY https://github.com/grpc/grpc
  GIT_TAG        v1.71.0
  )
FetchContent_MakeAvailable(gRPC)


# Make sure you install CryptoPP
include_directories(/usr/local/include/cryptopp)
link_directories(/usr/local/lib)

# got from: https://github.com/grpc/grpc/blob/master/examples/cpp/cmake/common.cmake
set(_PROTOBUF_LIBPROTOBUF libprotobuf)
set(_REFLECTION grpc++_reflection)
set(_PROTOBUF_PROTOC $<TARGET_FILE:protoc>)
set(_GRPC_GRPCPP grpc++)
if(CMAKE_CROSSCOMPILING)
  find_program(_GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin)
else()
  set(_GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:grpc_cpp_plugin>)
endif()

include_directories("${CMAKE_CURRENT_LIST_DIR}/inc/")
include_directories("${CMAKE_CURRENT_LIST_DIR}/proto/")
include_directories(${Boost_INCLUDE_DIRS})

# # # # REBUILD THE CUTSTOM PROTOBUFS

get_filename_component(baseprotocol_proto "${CMAKE_CURRENT_LIST_DIR}/proto/baseprotocol.proto" ABSOLUTE)
get_filename_component(baseprotocol_proto_path "${baseprotocol_proto}" PATH)

set(baseprotocol_proto_srcs "${CMAKE_CURRENT_LIST_DIR}/proto/baseprotocol.pb.cc")
set(baseprotocol_proto_hdrs "${CMAKE_CURRENT_LIST_DIR}/proto/baseprotocol.pb.h")
set(baseprotocol_grpc_srcs "${CMAKE_CURRENT_LIST_DIR}/proto/baseprotocol.grpc.pb.cc")
set(baseprotocol_grpc_hdrs "${CMAKE_CURRENT_LIST_DIR}/proto/baseprotocol.grpc.pb.h")

add_custom_command(
      OUTPUT "${baseprotocol_proto_srcs}" "${baseprotocol_proto_hdrs}" "${baseprotocol_grpc_srcs}" "${baseprotocol_grpc_hdrs}"
      COMMAND ${_PROTOBUF_PROTOC}
      ARGS --grpc_out "${CMAKE_CURRENT_LIST_DIR}/proto"
        --cpp_out "${CMAKE_CURRENT_LIST_DIR}/proto/"
        -I "${baseprotocol_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${baseprotocol_proto}"
      DEPENDS "${baseprotocol_proto}")

# custom library for the gRPC code
add_library(baseprotocol_grpc_proto
  ${baseprotocol_grpc_srcs}
  ${baseprotocol_grpc_hdrs}
  ${baseprotocol_proto_srcs}
  ${baseprotocol_proto_hdrs})

target_link_libraries(baseprotocol_grpc_proto
  absl::check
  absl::flags
  absl::flags_parse
  absl::log
  ${_REFLECTION}
  ${_GRPC_GRPCPP}
  ${_PROTOBUF_LIBPROTOBUF})

add_library(dynamicblocklist src/DynamicBlockList.cpp)
add_library(detectablehashfunction src/DetectableHashFunction.cpp)
add_library(projections src/Projections.cpp)
add_library(dpsiUtils src/DpsiUtils.cpp)
add_library(actors src/actors/Auditor.cpp src/actors/Client.cpp src/actors/Server.cpp)

add_dependencies(dpsiUtils ntl)
add_dependencies(dynamicblocklist ntl)
add_dependencies(detectablehashfunction ntl)
add_dependencies(projections ntl)
add_dependencies(actors ntl detectablehashfunction dpsiUtils)

target_link_libraries(dpsiUtils ${NTL_LIBRARY} gmp Boost::program_options Boost::property_tree)
target_link_libraries(actors detectablehashfunction projections baseprotocol_grpc_proto ${NTL_LIBRARY} gmp Boost::program_options Boost::property_tree )

# Tests
add_executable(tests src/tests/unittests.cpp)
add_executable(auditor-test src/tests/auditor-test.cpp)
add_executable(non-networked-example src/tests/non-networked-example.cpp)
add_executable(networked-aud2048 src/tests/networkedtest/aud-example.cpp)
add_executable(networked-aud4096 src/tests/networkedtest/aud-example4096.cpp)
add_executable(networked-aud1024 src/tests/networkedtest/aud-example1024.cpp)
add_executable(fuzzy-aud src/tests/FuzzyAud.cpp)
add_executable(base-client-test src/tests/base-client-test.cpp)
add_executable(grpc-test src/tests/networkedtest/grpc-example-setup.cpp)
add_executable(DHF-benchmark src/tests/DHFbenchmark.cpp)
add_executable(DHFServerBenchmark src/tests/DHFServerSideDetectBenchmark.cpp)
add_executable(ExactClientBenchmark src/tests/ClientBenchMark.cpp)
add_executable(SingleExactClientBenchmark src/tests/SingleExactClinetMatch.cpp)
add_executable(ProjectionBenchmark src/tests/ProjectionBenchmark.cpp)
add_executable(FullPSIBenchmark src/tests/FullPSIBenchmark.cpp)
add_executable(FullPSINoMatchBenchmark src/tests/FullPSINoMatchBenchmark.cpp)
add_executable(FullPSIClientBenchmark src/tests/FullPSIClientBenchmark.cpp)

target_link_libraries(DHF-benchmark PRIVATE detectablehashfunction gmp ${NTL_LIBRARY})
target_link_libraries(ProjectionBenchmark PRIVATE projections gmp ${NTL_LIBRARY})
target_link_libraries(DHFServerBenchmark PRIVATE detectablehashfunction gmp ${NTL_LIBRARY})
target_link_libraries(ExactClientBenchmark PRIVATE actors dpsiUtils ${NTL_LIBRARY} gmp cryptopp)
target_link_libraries(SingleExactClientBenchmark PRIVATE actors dpsiUtils ${NTL_LIBRARY} gmp cryptopp)
target_link_libraries(tests PRIVATE projections  actors dpsiUtils detectablehashfunction dynamicblocklist Catch2::Catch2WithMain ${NTL_LIBRARY} gmp cryptopp)
target_link_libraries(FullPSIBenchmark PRIVATE projections  actors dpsiUtils detectablehashfunction dynamicblocklist Catch2::Catch2WithMain ${NTL_LIBRARY} gmp cryptopp)
target_link_libraries(FullPSINoMatchBenchmark PRIVATE projections  actors dpsiUtils detectablehashfunction dynamicblocklist Catch2::Catch2WithMain ${NTL_LIBRARY} gmp cryptopp)
target_link_libraries(FullPSIClientBenchmark PRIVATE projections  actors dpsiUtils detectablehashfunction dynamicblocklist Catch2::Catch2WithMain ${NTL_LIBRARY} gmp cryptopp)
target_link_libraries(auditor-test PRIVATE actors dpsiUtils ${NTL_LIBRARY} gmp cryptopp)
target_link_libraries(non-networked-example PRIVATE  absl::log absl::flags absl::flags_parse absl::check baseprotocol_grpc_proto actors dpsiUtils ${NTL_LIBRARY} gmp cryptopp dynamicblocklist Boost::property_tree Boost::program_options)
target_link_libraries(networked-aud1024 PRIVATE absl::log absl::flags absl::flags_parse absl::check baseprotocol_grpc_proto actors dpsiUtils ${NTL_LIBRARY} gmp cryptopp dynamicblocklist Boost::property_tree Boost::program_options)
target_link_libraries(networked-aud2048 PRIVATE absl::log absl::flags absl::flags_parse absl::check baseprotocol_grpc_proto actors dpsiUtils ${NTL_LIBRARY} gmp cryptopp dynamicblocklist Boost::property_tree Boost::program_options)
target_link_libraries(networked-aud4096 PRIVATE absl::log absl::flags absl::flags_parse absl::check baseprotocol_grpc_proto actors dpsiUtils ${NTL_LIBRARY} gmp cryptopp dynamicblocklist Boost::property_tree Boost::program_options)
target_link_libraries(fuzzy-aud PRIVATE absl::log absl::flags absl::flags_parse absl::check baseprotocol_grpc_proto actors dpsiUtils ${NTL_LIBRARY} gmp cryptopp dynamicblocklist Boost::property_tree Boost::program_options)
target_link_libraries(grpc-test PRIVATE absl::log absl::flags absl::flags_parse absl::check baseprotocol_grpc_proto actors dpsiUtils ${NTL_LIBRARY} gmp cryptopp dynamicblocklist Boost::property_tree Boost::program_options )
target_link_libraries(base-client-test PRIVATE projections  actors dpsiUtils detectablehashfunction dynamicblocklist Catch2::Catch2WithMain ${NTL_LIBRARY} gmp cryptopp)







