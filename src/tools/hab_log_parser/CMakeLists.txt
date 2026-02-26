add_executable(hab_log_parser
    hab_log_parser.c
    usbhid.c
)

find_cst_dependency_library("libusb-1.0.a" libusb_DIR LIBUSB_LIB LIBUSB_INCLUDE_DIR)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    find_cst_dependency_library("libhidapi.a" hidapi_DIR LIBHIDAPI_LIB LIBHIDAPI_INCLUDE_DIR)
else()
    find_cst_dependency_library("libhidapi-libusb.a" hidapi_DIR LIBHIDAPI_LIB LIBHIDAPI_INCLUDE_DIR)
endif()

target_include_directories(hab_log_parser PUBLIC ${LIBHIDAPI_INCLUDE_DIR})

target_link_libraries(hab_log_parser PRIVATE
    ${LIBHIDAPI_LIB}
    ${LIBUSB_LIB}
    m
    pthread
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBUDEV libudev)
    if (LIBUDEV_FOUND)
        message(STATUS "libudev found, linking to it.")
        target_link_libraries(hab_log_parser PRIVATE ${LIBUDEV_LIBRARIES})
        target_include_directories(hab_log_parser PRIVATE ${LIBUDEV_INCLUDE_DIRS})
    else()
        message(WARNING "libudev not found, continuing without it.")
    endif()
endif()

install(
    TARGETS hab_log_parser
    EXPORT ${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)
