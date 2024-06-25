cmake_minimum_required (VERSION 3.5.1)


project(seal_demo)
set(CMAKE_CXX_STANDARD 17)
option( BUILD_STATIC "Set to ON to include static versions of the library" OFF)

find_package(SEAL 4.1 REQUIRED)

# include_directories(${SEAL_INCLUDE_DIRS})


add_executable(${PROJECT_NAME} ./serialize_exps/serialize_bfv_bgv.cpp)
target_link_libraries(${PROJECT_NAME} SEAL::seal)
