add_executable(convlb
    convlb.c
)

install(
    TARGETS convlb
    EXPORT ${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)
