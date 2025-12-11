#
# Copyright (c) 2025-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.14)
project("mquire" LANGUAGES NONE)

set(MQUIRE_REPOSITORY_PATH "" CACHE PATH "This is the path where mquire has been cloned")
if(NOT EXISTS "${MQUIRE_REPOSITORY_PATH}/Cargo.toml")
  message(FATAL_ERROR "The MQUIRE_REPOSITORY_PATH parameter is either empty or not valid")
endif()

execute_process(
  COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/scripts/extract_version.sh" "${MQUIRE_REPOSITORY_PATH}/mq/Cargo.toml"
  OUTPUT_VARIABLE MQUIRE_VERSION
  COMMAND_ERROR_IS_FATAL ANY
)

set(PACKAGE_VERSION 1)

string(REPLACE "." ";" MQUIRE_VERSION_COMPONENTS "${MQUIRE_VERSION}")
list(GET MQUIRE_VERSION_COMPONENTS 0 CPACK_PACKAGE_VERSION_MAJOR)
list(GET MQUIRE_VERSION_COMPONENTS 1 CPACK_PACKAGE_VERSION_MINOR)
list(GET MQUIRE_VERSION_COMPONENTS 2 CPACK_PACKAGE_VERSION_PATCH)

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/description.txt" CPACK_PACKAGE_DESCRIPTION_SUMMARY)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "mquire is a Linux memory dump analyzer.")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/description.txt")

set(CPACK_PACKAGE_NAME "mquire")
set(CPACK_PACKAGE_VENDOR "Trail of Bits")
set(CPACK_PACKAGE_CONTACT "info@trailofbits.com")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://www.trailofbits.com")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${MQUIRE_VERSION}-${PACKAGE_VERSION}.${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_PACKAGE_RELOCATABLE ON)

set(CPACK_DEBIAN_PACKAGE_RELEASE "${PACKAGE_VERSION}")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "extra")
set(CPACK_DEBIAN_PACKAGE_SECTION "default")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>=2.35)")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "${CPACK_PACKAGE_HOMEPAGE_URL}")

set(CPACK_RPM_PACKAGE_RELEASE_DIST "${PACKAGE_VERSION}")
set(CPACK_RPM_PACKAGE_DESCRIPTION "${CPACK_PACKAGE_DESCRIPTION_SUMMARY}")
set(CPACK_RPM_PACKAGE_GROUP "default")
set(CPACK_RPM_PACKAGE_REQUIRES "glibc >= 2.35")

set(CPACK_GENERATOR "TGZ")
message(STATUS "MQUIRE - The TGZ generator has been enabled")

unset(rpm_executable_path CACHE)
find_program(rpm_executable_path "rpm")
if("${rpm_executable_path}" STREQUAL "rpm_executable_path-NOTFOUND")
  message(WARNING "MQUIRE - The RPM package generator requires the 'rpm' tool")
else()
  list(APPEND CPACK_GENERATOR "RPM")
  message(STATUS "MQUIRE - The RPM generator has been enabled")
endif()

unset(dpkg_executable_path CACHE)
find_program(dpkg_executable_path "dpkg")
if("${dpkg_executable_path}" STREQUAL "dpkg_executable_path-NOTFOUND")
  message(WARNING "MQUIRE - The DEB package generator requires the 'dpkg' tool")
else()
  list(APPEND CPACK_GENERATOR "DEB")
  message(STATUS "MQUIRE - The DEB generator has been enabled")
endif()

include(CPack)

if(UNIX)
  if(APPLE)
    set(mq_executable_path "${MQUIRE_REPOSITORY_PATH}/target/release/mq")
    set(mq_file_dump_executable_path "${MQUIRE_REPOSITORY_PATH}/target/release/mq-file-dump")
  else()
    set(mq_executable_path "${MQUIRE_REPOSITORY_PATH}/target/x86_64-unknown-linux-musl/release/mq")
    set(mq_file_dump_executable_path "${MQUIRE_REPOSITORY_PATH}/target/x86_64-unknown-linux-musl/release/mq-file-dump")
  endif()
else()
  message(FATAL_ERROR "MQUIRE - Currently, only Linux and macOS operating systems are supported")
endif()

if(NOT EXISTS "${mq_executable_path}")
    message(FATAL_ERROR "The mq binary was not found. Expected path: ${mq_executable_path}")
endif()

if(NOT EXISTS "${mq_file_dump_executable_path}")
    message(FATAL_ERROR "The mq-file-dump binary was not found. Expected path: ${mq_file_dump_executable_path}")
endif()

install(
  FILES
    "${mq_executable_path}"
    "${mq_file_dump_executable_path}"

  DESTINATION
    "bin"

  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
              GROUP_READ GROUP_WRITE GROUP_EXECUTE
              WORLD_READ             WORLD_EXECUTE
)
