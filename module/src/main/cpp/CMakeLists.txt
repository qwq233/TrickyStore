cmake_minimum_required(VERSION 3.28)
project(trick_store)

find_package(cxx REQUIRED CONFIG)
link_libraries(cxx::cxx)

add_definitions(-std=c++20)

add_library(my_logging STATIC logging/logging.cpp)

add_subdirectory(external)

target_include_directories(my_logging PUBLIC logging/include)

target_link_libraries(my_logging log)

# libutils stub
add_library(utils SHARED binder/stub_utils.cpp)
target_include_directories(utils PUBLIC binder/include)

# libbinder stub
add_library(binder SHARED binder/stub_binder.cpp)
target_include_directories(binder PUBLIC binder/include)
target_link_libraries(binder PRIVATE utils)

add_executable(libinject.so inject/main.cpp inject/utils.cpp)
target_link_libraries(libinject.so PRIVATE lsplt my_logging)

add_library(${MODULE_NAME} SHARED binder_interceptor.cpp)
target_link_libraries(${MODULE_NAME} PRIVATE log binder lsplt utils my_logging)
