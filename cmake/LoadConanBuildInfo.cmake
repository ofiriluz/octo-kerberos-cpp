FUNCTION(LOAD_CONAN_BUILD_INFO)
    STRING(TOLOWER ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE_LOWER)
    # Find Conan cmake definition
    FIND_FILE(CONAN_${PROJECT_NAME}_BUILD_INFO
        conanbuildinfo.cmake
        PATHS
        ${CMAKE_CURRENT_BINARY_DIR}/../
        ${CMAKE_CURRENT_SOURCE_DIR}/build/conan/${PROJECT_NAME}/${CMAKE_BUILD_TYPE}
        ${CMAKE_BINARY_DIR}/../
        ${CMAKE_SOURCE_DIR}/build/conan/${PROJECT_NAME}/${CMAKE_BUILD_TYPE}
        ${CONAN_IDE_BUILD_INFO_PATH_HINT}
        )
    # Include Conan definition and set RPATHS
    INCLUDE(${CONAN_${PROJECT_NAME}_BUILD_INFO})
    CONAN_BASIC_SETUP(TARGETS KEEP_RPATHS)

    SET(CONAN_BUILD_INFO_FOUND TRUE PARENT_SCOPE)
    SET(LIBFMT_ROOT ${CONAN_LIBFMT_ROOT} PARENT_SCOPE)
    SET(KRB5_ROOT ${CONAN_KRB5_ROOT} PARENT_SCOPE)
    SET(OPENSSL_ROOT ${CONAN_OPENSSL_ROOT} PARENT_SCOPE)
    SET(NLOHMANN_JSON_ROOT ${CONAN_NLOHMANN-JSON_ROOT} PARENT_SCOPE)
    SET(OCTO_LOGGER_CPP_ROOT ${CONAN_OCTO-LOGGER-CPP_ROOT} PARENT_SCOPE)
    SET(OCTO_ENCRYPTION_CPP_ROOT ${CONAN_OCTO-ENCRYPTION-CPP_ROOT} PARENT_SCOPE)
ENDFUNCTION()
