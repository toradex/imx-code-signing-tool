find_package(BISON)
find_package(FLEX)

BISON_TARGET(CSTParser cst_parser.y ${CMAKE_CURRENT_BINARY_DIR}/cst_parser.c
             DEFINES_FILE ${CMAKE_CURRENT_BINARY_DIR}/cst_parser.h)

FLEX_TARGET(CSTLexer cst_lexer.l  ${CMAKE_CURRENT_BINARY_DIR}/cst_lexer.c)

set(C_SOURCES
    acst.c
    csf_cmd_aut_dat.c
    csf_cmd_ins_key.c
    csf_cmd_misc.c
    misc_helper.c
    ${BISON_CSTParser_OUTPUTS}
    ${FLEX_CSTLexer_OUTPUTS}
)

add_cst_component(front_end ${C_SOURCES})

if(CST_WITH_PQC)
    target_include_directories(front_end PRIVATE ${OQSPROVIDER_INCLUDE_DIR})
endif()

target_link_libraries(
    front_end
    PUBLIC
        CST::common
        CST::back_end
        OpenSSL::Crypto
)
