add_executable(ahab_split_container
    ahab_split_container.c
)

target_link_libraries(ahab_split_container PRIVATE
    CST::front_end
    ${CMAKE_DL_LIBS}
)

install(TARGETS ahab_split_container
    EXPORT ${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)
