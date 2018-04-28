cmake_minimum_required(VERSION 3.10)
project(ldapquota C)

SET(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMake" ${CMAKE_MODULE_PATH})
set(CMAKE_C_STANDARD 11)

find_package(Ldap REQUIRED)
include_directories(LDAP_INCLUDE_DIR)
add_executable(ldapquota main.c)
target_link_libraries(ldapquota ${LDAP_LIBRARIES})