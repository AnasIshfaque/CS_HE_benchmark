cmake_minimum_required (VERSION 3.5.1)

### In order to create OpenFHE's static libraries you should enable
### the BUILD_STATIC option. For that, you run "cmake .. -DBUILD_STATIC=ON".
### After having your link completed you will find static libs
### with the suffix "_static" in ./build/libs/.
### Examples: OPENFHEpke_static.a, OPENFHEcore_static.a, etc.
### After you run "make install" in your build directory, you can build your custom application.
### If you need your application to be linked statically, then run "cmake .. -DBUILD_STATIC=ON"

project(seal_demo)
set(CMAKE_CXX_STANDARD 17)
option( BUILD_STATIC "Set to ON to include static versions of the library" OFF)

find_package(SEAL 4.1 REQUIRED)

# include_directories(${SEAL_INCLUDE_DIRS})


add_executable(${PROJECT_NAME} main.cpp)
target_link_libraries(${PROJECT_NAME} SEAL::seal)