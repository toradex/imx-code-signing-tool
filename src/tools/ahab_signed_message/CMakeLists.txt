find_cst_dependency_library("libjson-c.a" json_c_DIR JSONC_LIB JSONC_INCLUDE_DIR)

add_executable(ahab_signed_message
    ahab_signed_message.c
)

target_link_libraries(ahab_signed_message PRIVATE
    CST::common
    ${JSONC_LIB}
)

install(TARGETS ahab_signed_message
    EXPORT ${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)
