cmake_minimum_required(VERSION 3.15)
project(wirespeed CXX)

# Static CRT, so the exe also runs on machines without the VC++ redistributable.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(wirespeed wirespeed.cpp)
target_compile_options(wirespeed PRIVATE /W4)
