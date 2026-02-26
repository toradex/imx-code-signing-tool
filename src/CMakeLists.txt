cmake_minimum_required(VERSION 3.5)
project(CST VERSION 4.0.1 DESCRIPTION "" LANGUAGES C)
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

option(CST_WITH_OPENSSL "Enable OpenSSL backend" ON)
if (CST_WITH_OPENSSL)
  set(OPENSSL_USE_STATIC_LIBS TRUE)
  find_package(OpenSSL 3.0.0 REQUIRED)
  if(NOT OPENSSL_FOUND)
      message(FATAL "Cannot find OpenSSL, please check environment")
  endif()
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib/static)

if(NOT DEFINED OSTYPE)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            if(CMAKE_SIZEOF_VOID_P EQUAL 8)
                set(OSTYPE linux64)
            elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
                set(OSTYPE linux32)
            endif()
        elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
            set(OSTYPE mingw32)
        else()
            message(FATAL_ERROR "Unsupported system: ${CMAKE_SYSTEM_NAME}")
        endif()
    else()
        message(FATAL_ERROR "Unsupported compiler: ${CMAKE_C_COMPILER_ID}")
    endif()
endif()

message(STATUS "OSTYPE is set to ${OSTYPE}")

option(CST_INSTALL "Generate install targets for CST" ON)

include(GNUInstallDirs)
include(cmake/compiler_options.cmake)

if(NOT DEFINED CST_WITH_PKCS11)
    set(CST_WITH_PKCS11 OFF)
endif()

message(STATUS "Build CST with PKCS#11 support: ${CST_WITH_PKCS11}")

if(NOT DEFINED CST_WITH_PQC)
    set(CST_WITH_PQC OFF)
endif()

if(NOT DEFINED CST_WITH_PQC)
    set(CST_WITH_PQC OFF)
endif()

message(STATUS "Build CST with PQC support: ${CST_WITH_PQC}")

function(add_cst_component name)
    set(sources ${ARGN})
    add_library(${name} ${sources})
    add_library(CST::${name} ALIAS ${name})
    target_include_directories(${name} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
    set_target_properties(${name} PROPERTIES
        OUTPUT_NAME cst_${name})
    if(CST_INSTALL)
      install(TARGETS ${name}
              EXPORT ${PROJECT_NAME}
              DESTINATION ${CMAKE_INSTALL_LIBDIR}
        )
    endif()
    set_property(GLOBAL APPEND PROPERTY CST_COMPONENTS ${name})
endfunction()

function(find_cst_dependency_library LIB_NAME LIB_DIR_VAR LIB_VAR INCLUDE_VAR)
    unset(LIB_DIR CACHE)
    unset(LIB_PATH CACHE)
    unset(INCLUDE_PATH CACHE)
    message(STATUS "Looking for ${LIB_NAME}...")
    if (DEFINED ${LIB_DIR_VAR})
        set(LIB_DIR ${${LIB_DIR_VAR}})
        message(STATUS "Using ${LIB_NAME} location provided by ${LIB_DIR_VAR}: ${LIB_DIR}")
        find_library(LIB_PATH
            NAMES ${LIB_NAME}
            HINTS ${LIB_DIR}
            PATH_SUFFIXES lib lib64
        )
    else()
        message(STATUS "${LIB_DIR_VAR} is not set. Falling back to system paths for ${LIB_NAME}.")
        find_library(LIB_PATH
            NAMES ${LIB_NAME}
            PATHS /usr/lib /usr/local/lib
            PATH_SUFFIXES lib lib64
        )
    endif()
    if (LIB_PATH)
        message(STATUS "Found ${LIB_NAME}: ${LIB_PATH}")
    else()
        message(FATAL_ERROR "Could not find ${LIB_NAME}. Please provide a valid ${LIB_DIR_VAR} or ensure it is available in system paths.")
    endif()
    if (DEFINED ${INCLUDE_VAR})
        set(INCLUDE_PATH ${${INCLUDE_VAR}})
        include_directories(${INCLUDE_PATH})
        message(STATUS "Using ${LIB_NAME} includes from: ${INCLUDE_PATH}")
    else()
        if (LIB_DIR)
            set(INCLUDE_PATH ${LIB_DIR}/include)
        else()
            get_filename_component(LIB_DIR ${LIB_PATH} DIRECTORY)
            set(INCLUDE_PATH ${LIB_DIR}/include)
        endif()
        include_directories(${INCLUDE_PATH})
        message(STATUS "Guessed include path for ${LIB_NAME}: ${INCLUDE_PATH}")
    endif()
    set(${LIB_VAR} ${LIB_PATH} CACHE PATH "Path to ${LIB_NAME} library")
    set(${INCLUDE_VAR} ${INCLUDE_PATH} CACHE PATH "Path to ${LIB_NAME} include directory")
endfunction()

if(CST_WITH_PKCS11)
    find_cst_dependency_library("libpkcs11.a" libp11_DIR PKCS11_LIB PKCS11_INCLUDE_DIR)
    add_compile_definitions(CST_WITH_PKCS11)
endif()

if(CST_WITH_PQC)
    find_cst_dependency_library("liboqs.a" liboqs_DIR LIBOQS_LIB LIBOQS_INC)
    find_cst_dependency_library("liboqsprovider.a" oqsprovider_DIR OQSPROVIDER_LIB OQSPROVIDER_INC)
    add_compile_definitions(CST_WITH_PQC)
endif()

add_subdirectory(lib)
add_subdirectory(scripts)
add_subdirectory(tools)

get_property(_components GLOBAL PROPERTY CST_COMPONENTS)
add_library(CST INTERFACE)
add_library(CST::CST ALIAS CST)
foreach(_component IN LISTS _components)
  target_link_libraries(CST INTERFACE ${_component})
endforeach()
