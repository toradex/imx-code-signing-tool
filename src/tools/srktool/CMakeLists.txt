add_executable(srktool
    srktool.c
)

target_link_libraries(srktool PRIVATE
    CST::front_end
    CST::back_end
    ${CMAKE_DL_LIBS}
)

install(TARGETS srktool 
    EXPORT ${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)
