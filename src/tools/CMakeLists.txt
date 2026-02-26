option(BUILD_CST "Build CST application" ON)
if(BUILD_CST)
  add_subdirectory(cst)
endif()

option(BUILD_SRKTOOL "Build SRK Tool application" ON)
if(BUILD_SRKTOOL)
  add_subdirectory(srktool)
endif()

option(BUILD_XHAB_PKI_TREE "Build AHAB/HAB PKI tree generation application" ON)
if(BUILD_XHAB_PKI_TREE)
  add_subdirectory(pki_tree)
endif()

option(BUILD_CONVLB "Build CONVLB application" ON)
if(BUILD_CONVLB)
  add_subdirectory(convlb)
endif()

option(BUILD_MAC_DUMP "Build mac_dump application" ON)
if(BUILD_MAC_DUMP)
  add_subdirectory(mac_dump)
endif()

option(BUILD_AHAB_SIGNED_MESSAGE "Build ahab_signed_message tool" ON)
if(BUILD_AHAB_SIGNED_MESSAGE)
  add_subdirectory(ahab_signed_message)
endif()

option(BUILD_AHAB_SPLIT_CONTAINER "Build ahab_split_container tool" ON)
if(BUILD_AHAB_SPLIT_CONTAINER)
  add_subdirectory(ahab_split_container)
endif()

option(BUILD_IMAGE_VERIFIER "Build xHAB image verifier tools" ON)
if(BUILD_IMAGE_VERIFIER)
  add_subdirectory(image_verifier)
endif()

option(BUILD_HAB_CSF_PARSER "Build HAB CSF parser application" ON)
if(BUILD_HAB_CSF_PARSER)
  add_subdirectory(hab_csf_parser)
endif()

option(BUILD_HAB_LOG_PARSER "Build HAB log parser application" OFF)
if(BUILD_HAB_LOG_PARSER)
  add_subdirectory(hab_log_parser)
endif()

option(BUILD_AHAB_SIGBLK_PARSER "Build AHAB signature block parser application" OFF)
if(BUILD_AHAB_SIGBLK_PARSER)
  add_subdirectory(ahab_signature_block_parser)
endif()

option(BUILD_HAB_SRKTOOL_SCRIPTS "Build HAB srk tool scripts" OFF)
if(BUILD_HAB_SRKTOOL_SCRIPTS)
  add_subdirectory(hab_srktool_scripts)
endif()
