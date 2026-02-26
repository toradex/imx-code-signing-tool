add_executable(ahab_image_verifier
    verifier_helper.c
    ahab_image_verifier.c
)

add_executable(hab4_image_verifier
    verifier_helper.c
    hab4_image_verifier.c
)

target_link_libraries(ahab_image_verifier PRIVATE
    CST::front_end
    CST::back_end
    ${CMAKE_DL_LIBS}
)

target_link_libraries(hab4_image_verifier PRIVATE
    CST::front_end
    CST::back_end
    ${CMAKE_DL_LIBS}
)

install(TARGETS ahab_image_verifier
    EXPORT ${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(TARGETS hab4_image_verifier
    EXPORT ${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)
