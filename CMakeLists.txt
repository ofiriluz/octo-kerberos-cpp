CMAKE_MINIMUM_REQUIRED(VERSION 3.16)

PROJECT(octo-kerberos-cpp)

# Add CMake options to path
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/)
INCLUDE(ConfigOptions)
INCLUDE(LoadConanBuildInfo)
LOAD_CONAN_BUILD_INFO()
SET(OPENSSL_USE_STATIC_LIBS TRUE)
FIND_PACKAGE(fmt REQUIRED PATHS ${LIBFMT_ROOT}/lib/cmake/fmt)
FIND_PACKAGE(OpenSSL REQUIRED)
FIND_PACKAGE(Python3 COMPONENTS Development REQUIRED)
FIND_PROGRAM(PipEnv pipenv)
IF ("${PipEnv}" STREQUAL "PipEnv-NOTFOUND")
    SET(PipEnv "python3" "-m" "pipenv")
ENDIF ("${PipEnv}" STREQUAL "PipEnv-NOTFOUND")

SET(KERBEROS_INTERFACE_SRCS
    src/kerberos-user-credentials.cpp
)

SET(KRB5_KERBEROS_SRCS
    src/krb5/krb5-kerberos-authenticator.cpp
    src/krb5/krb5-kerberos-serializer.cpp
    src/krb5/krb5-kerberos-tgt-ticket.cpp
    src/krb5/krb5-kerberos-service-ticket.cpp
    src/krb5/python/krb5-kerberos-py-bindings.cpp
    src/krb5/python/krb5-kerberos-py-types-authenticator.cpp
    src/krb5/python/krb5-kerberos-py-types-service-ticket.cpp
    src/krb5/python/krb5-kerberos-py-types-tgt-ticket.cpp
    src/krb5/python/krb5-kerberos-py-types-user-credentials.cpp
    src/krb5/python/krb5-kerberos-py-serializer.cpp
)

# Library definition
ADD_LIBRARY(octo-kerberos-cpp STATIC
    ${KERBEROS_INTERFACE_SRCS}
    ${KRB5_KERBEROS_SRCS}
)

# Properties
SET_TARGET_PROPERTIES(octo-kerberos-cpp PROPERTIES CXX_STANDARD 17 POSITION_INDEPENDENT_CODE ON)

TARGET_COMPILE_OPTIONS(octo-kerberos-cpp
    PRIVATE
    -Werror=return-type
    -Werror=switch
    -Werror=unused-result
)

SET(OCTO_LOGGER_LEVEL "DEBUG")
TARGET_COMPILE_DEFINITIONS(octo-kerberos-cpp
    PRIVATE
    LOGGER_LEVEL=${OCTO_LOGGER_LEVEL}
)

TARGET_INCLUDE_DIRECTORIES(octo-kerberos-cpp
    PUBLIC
        # Kerberos includes
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${KRB5_ROOT}/include
        ${NLOHMANN_JSON_ROOT}/include
        ${Python3_INCLUDE_DIRS}
)

TARGET_LINK_LIBRARIES(octo-kerberos-cpp
    # Octo Libraries, all static
    octo::octo-encryption-cpp
    octo::octo-logger-cpp

    # 3rd parties
    $<$<PLATFORM_ID:Darwin>:${KRB5_ROOT}/lib/libkrb5${CMAKE_SHARED_LIBRARY_SUFFIX}>
    $<$<PLATFORM_ID:Linux>:${KRB5_ROOT}/lib/libkrb5${CMAKE_STATIC_LIBRARY_SUFFIX}>
    $<$<PLATFORM_ID:Linux>:${KRB5_ROOT}/lib/libk5crypto${CMAKE_STATIC_LIBRARY_SUFFIX}>
    $<$<PLATFORM_ID:Linux>:${KRB5_ROOT}/lib/libkrb5support${CMAKE_STATIC_LIBRARY_SUFFIX}>
    $<$<PLATFORM_ID:Linux>:${KRB5_ROOT}/lib/libcom_err${CMAKE_STATIC_LIBRARY_SUFFIX}>
    fmt::fmt

    # System libraries
    $<$<PLATFORM_ID:Linux>:resolv>
    $<$<PLATFORM_ID:Linux>:dl>
    ${${PROJECT_NAME}_SYSTEM_LIBS}

    # Static linkage libc for compatibility with different servers
    $<$<PLATFORM_ID:Linux>:-pthread -static-libgcc -static-libstdc++>
    $<$<PLATFORM_ID:Linux>:${CMAKE_CURRENT_SOURCE_DIR}/libc/stat.o>
    $<$<PLATFORM_ID:Linux>:${CMAKE_CURRENT_SOURCE_DIR}/libc/stat64.o>
    $<$<PLATFORM_ID:Linux>:${CMAKE_CURRENT_SOURCE_DIR}/libc/fstat.o>
    $<$<PLATFORM_ID:Linux>:${CMAKE_CURRENT_SOURCE_DIR}/libc/fstat64.o>
    $<$<PLATFORM_ID:Linux>:${CMAKE_CURRENT_SOURCE_DIR}/libc/fstatat.o>
    $<$<PLATFORM_ID:Linux>:${CMAKE_CURRENT_SOURCE_DIR}/libc/fstatat64.o>
    $<$<PLATFORM_ID:Linux>:${CMAKE_CURRENT_SOURCE_DIR}/libc/errno.o>
    $<$<PLATFORM_ID:Linux>:${CMAKE_CURRENT_SOURCE_DIR}/libc/explicit_bzero.o>
)

# Installation of the kerberos library
INSTALL(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
    DESTINATION include
)

INSTALL(TARGETS octo-kerberos-cpp
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

# Examples
IF(NOT DISABLE_EXAMPLES)
    ADD_SUBDIRECTORY(examples)
ENDIF()

SET(PYTHON_SETUP_ENV_ARGS
    LOGGER_LEVEL=${OCTO_LOGGER_LEVEL}
    OCTO_LOGGER_CPP_ROOT=${OCTO_LOGGER_CPP_ROOT}
    OCTO_ENCRYPTION_CPP_ROOT=${OCTO_ENCRYPTION_CPP_ROOT}
    LIBFMT_ROOT=${LIBFMT_ROOT}
    KRB5_ROOT=${KRB5_ROOT}
    NLOHMANN_JSON_ROOT=${NLOHMANN_JSON_ROOT}
    OPENSSL_ROOT=${OPENSSL_ROOT}
)

ADD_CUSTOM_TARGET(octo-kerberos-setup-bdist_wheel
    COMMAND ${PipEnv} run python setup.py clean --all
    COMMAND ${PYTHON_SETUP_ENV_ARGS} ${PipEnv} run python setup.py bdist_wheel
    DEPENDS Pipfile.lock
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
