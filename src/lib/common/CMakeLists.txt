set(C_SOURCES
    err.c
    openssl_helper.c
    srk_helper.c
)

add_cst_component(common ${C_SOURCES})

if(CST_WITH_PQC)
    target_include_directories(common PRIVATE ${OQSPROVIDER_INCLUDE_DIR})
endif()

target_link_libraries(
    common
    PUBLIC
        $<$<BOOL:${CST_WITH_PQC}>:${OQSPROVIDER_LIB}>
        $<$<BOOL:${CST_WITH_PQC}>:${LIBOQS_LIB}>
        OpenSSL::Crypto
)
