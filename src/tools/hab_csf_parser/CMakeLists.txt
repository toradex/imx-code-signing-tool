add_executable(hab_csf_parser
    csf_parser.c
    extract_csf.c
)

install(TARGETS hab_csf_parser EXPORT ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
