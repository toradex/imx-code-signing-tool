set(C_SOURCES
    adapt_layer_openssl.c
    cert.c
    pkey.c
    ssl_wrapper.c
    engine.c
)

add_cst_component(back_end ${C_SOURCES})

if(CST_WITH_PKCS11)
    target_include_directories(back_end PRIVATE ${LIBP11_INCLUDE_DIR})
endif()

if(CST_WITH_PQC)
    target_include_directories(back_end PRIVATE ${OQSPROVIDER_INCLUDE_DIR})
endif()

target_link_libraries(
    back_end
    PUBLIC
        CST::common
        $<$<BOOL:${CST_WITH_PQC}>:${OQSPROVIDER_LIB}>
        $<$<BOOL:${CST_WITH_PQC}>:${LIBOQS_LIB}>
        $<$<BOOL:${CST_WITH_PKCS11}>:${PKCS11_LIB}>
        OpenSSL::Crypto
)
