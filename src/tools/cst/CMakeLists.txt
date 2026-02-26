add_executable(cst
    cst.c
)

target_link_libraries(cst PRIVATE
    CST::front_end
    CST::back_end
    ${CMAKE_DL_LIBS}
)

install(TARGETS cst 
    EXPORT ${PROJECT_NAME} 
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)
