cmake_minimum_required (VERSION 3.5.1)


project(helib_demo)
set(CMAKE_CXX_STANDARD 17)
option( BUILD_STATIC "Set to ON to include static versions of the library" OFF)

# find_package(SEAL 4.1 REQUIRED)

find_package(helib)

include_directories(${HELIB_INCLUDE_DIRS})


add_executable(${PROJECT_NAME} bgv_test.cpp)
target_link_libraries(${PROJECT_NAME} helib)
