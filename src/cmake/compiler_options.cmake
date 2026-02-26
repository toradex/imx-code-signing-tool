set(CMAKE_COMPILE_WARNING_AS_ERROR ON)

add_compile_definitions(
    VERSION=${PROJECT_VERSION}
)

if(${OSTYPE} STREQUAL "linux32")
    add_compile_options(-m32)
    add_link_options(-m32)
endif()
