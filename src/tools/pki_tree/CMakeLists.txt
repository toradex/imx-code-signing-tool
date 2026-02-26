add_executable(ahab_pki_tree
    ahab_pki_tree.c
    pki_helper.c
)

add_executable(hab4_pki_tree
    hab4_pki_tree.c
    pki_helper.c
)

add_executable(add_key
    add_key.c
    pki_helper.c
)

target_link_libraries(ahab_pki_tree PRIVATE
    CST::front_end
    CST::back_end
    ${CMAKE_DL_LIBS}
)

target_link_libraries(hab4_pki_tree PRIVATE
    CST::front_end
    CST::back_end
    ${CMAKE_DL_LIBS}
)

target_link_libraries(add_key PRIVATE
    CST::front_end
    CST::back_end
    ${CMAKE_DL_LIBS}
)

install(
    TARGETS ahab_pki_tree
    EXPORT ${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(
    TARGETS hab4_pki_tree
    EXPORT ${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(
    TARGETS add_key
    EXPORT ${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)
