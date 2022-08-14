# Executable definition
ADD_EXECUTABLE(tgt-example
    src/tgt-example.cpp
)

# Properties
SET_TARGET_PROPERTIES(tgt-example PROPERTIES CXX_STANDARD 17 POSITION_INDEPENDENT_CODE ON)

TARGET_LINK_LIBRARIES(tgt-example
    # Octo Libraries, all static
    octo-kerberos-cpp
)

# Installation of the example
INSTALL(TARGETS tgt-example
    RUNTIME DESTINATION examples
)
