cmake_minimum_required(VERSION 3.16)

project(nationstech-uartboot-iap LANGUAGES C)

find_package(Git REQUIRED)

execute_process(COMMAND ${GIT_EXECUTABLE} log --pretty=format:'%h' -n 1
                OUTPUT_VARIABLE GIT_REV
                WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                ERROR_QUIET)

if ("${GIT_REV}" STREQUAL "")
  set(GIT_REV "N/A")
  set(GIT_DIFF "")
  set(GIT_TAG "N/A")
  set(GIT_BRANCH "N/A")
else()
  execute_process(
    COMMAND ${GIT_EXECUTABLE} diff --quiet --exit-code
    OUTPUT_VARIABLE GIT_DIFF
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    RESULT_VARIABLE GIT_DIFF_RETURN)
  if (${GIT_DIFF_RETURN} EQUAL 0)
    set(GIT_DIFF "+")
  else()
    set(GIT_DIFF "-")
  endif()

  execute_process(
    COMMAND ${GIT_EXECUTABLE} describe --exact-match --tags
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_TAG ERROR_QUIET)
  execute_process(
    COMMAND ${GIT_EXECUTABLE} rev-parse --abbrev-ref HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_BRANCH)

  string(STRIP "${GIT_REV}" GIT_REV)
  string(SUBSTRING "${GIT_REV}" 1 7 GIT_REV)
  string(STRIP "${GIT_DIFF}" GIT_DIFF)
  string(STRIP "${GIT_TAG}" GIT_TAG)
  string(STRIP "${GIT_BRANCH}" GIT_BRANCH)
endif()

if ("${GIT_TAG}" STREQUAL "")
  set(GIT_TAG "0")
endif()

set(CPACK_PACKAGE_VERSION "${GIT_TAG}${GIT_DIFF}git.${GIT_REV}")

execute_process(COMMAND ${GIT_EXECUTABLE} remote get-url origin
                OUTPUT_VARIABLE HOMEPAGE
                WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                ERROR_QUIET)

add_compile_definitions(GIT_REPO_NAME="${CMAKE_PROJECT_NAME}")
add_compile_definitions(GIT_REV="${GIT_REV}")
add_compile_definitions(GIT_BRANCH="${GIT_BRANCH}")
add_compile_definitions(GIT_TAG="${GIT_TAG}")
add_compile_definitions(VERSION="${CPACK_PACKAGE_VERSION}")
add_compile_definitions(HOMEPAGE="${HOMEPAGE}")

add_compile_options(-Wno-pointer-to-int-cast -fsanitize=address)
add_link_options(-fsanitize=address)

add_executable(nationstech-uartboot-iap main.c)
