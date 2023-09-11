cmake_minimum_required(VERSION 3.20.0)
project(RunInSession VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
add_compile_options(/utf-8 /MT)

include(FetchContent)

FetchContent_Declare(
  format
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG        10.1.1
)

FetchContent_Declare(
  cli11
  GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
  GIT_TAG 520c0c60916e0a82b349a510d3c71773a96b74ff
)

FetchContent_MakeAvailable(format cli11)

add_executable(RunAsUser main.cpp)

target_compile_definitions(RunAsUser PRIVATE UNICODE _UNICODE)
target_link_libraries(RunAsUser PRIVATE CLI11::CLI11 fmt 	Userenv.dll Wtsapi32.dll Advapi32.dll Kernel32.dll)
