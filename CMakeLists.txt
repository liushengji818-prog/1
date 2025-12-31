cmake_minimum_required(VERSION 3.18)
project(tron_gpu_vanity LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

option(ENABLE_CUDA "Enable CUDA acceleration" ON)

if(ENABLE_CUDA)
  find_package(CUDAToolkit QUIET)
endif()

add_library(core STATIC
  src/crypto.cpp
  src/generator.cpp
)

target_include_directories(core PUBLIC include)
target_link_libraries(core PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

target_compile_definitions(core PUBLIC -DOPENSSL_API_COMPAT=0x10100000L)

if(CUDAToolkit_FOUND)
  enable_language(CUDA)
  add_library(gpu_kernels STATIC src/cuda/kernels.cu)
  target_include_directories(gpu_kernels PUBLIC include)
  target_link_libraries(gpu_kernels PUBLIC CUDA::cudart)
  target_compile_definitions(gpu_kernels PUBLIC -DHAVE_CUDA=1)
else()
  add_library(gpu_kernels STATIC src/cuda/kernels_stub.cpp)
  target_include_directories(gpu_kernels PUBLIC include)
  target_compile_definitions(gpu_kernels PUBLIC -DHAVE_CUDA=0)
endif()

add_executable(tron_gpu src/main.cpp)

target_link_libraries(tron_gpu PRIVATE core gpu_kernels OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

target_compile_options(tron_gpu PRIVATE $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic>)

include(GNUInstallDirs)
install(TARGETS tron_gpu RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
