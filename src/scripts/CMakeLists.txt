# Copy key and certificate generation scripts

set(PKI_DIRS
    ca
    keys
    crts
)

foreach(pki_dir IN LISTS PKI_DIRS)
  file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${pki_dir})
  execute_process(COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/${pki_dir})
endforeach()

file(GLOB CONF_FILES "*.cnf")
file(GLOB BAT_FILES "*.bat")
file(GLOB SH_FILES "*.sh")

set(EXCLUDE_SCRIPTS "${CMAKE_CURRENT_SOURCE_DIR}/build.sh")
list(REMOVE_ITEM SH_FILES ${EXCLUDE_SCRIPTS})

set(SCRIPT_FILES ${BAT_FILES} ${SH_FILES})

message(STATUS "SH_FILES: ${SH_FILES}")

file(COPY ${CONF_FILES} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/ca)
file(COPY ${SCRIPT_FILES} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/keys)
