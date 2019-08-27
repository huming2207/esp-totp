set(COMPONENT_SRCS "otp.cpp" "include/otp.hpp")
set(COMPONENT_ADD_INCLUDEDIRS "" "include")

set(COMPONENT_REQUIRES mbedtls)

register_component()
