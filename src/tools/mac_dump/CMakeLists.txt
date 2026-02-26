add_executable(hab4_mac_dump
    hab4_mac_dump.c
)

install(
    TARGETS hab4_mac_dump
    EXPORT ${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)
