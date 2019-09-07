set(COMPONENT_SRCS "otp.cpp" "include/otp.hpp" "otp_key.cpp" "include/otp_key.hpp")
set(COMPONENT_ADD_INCLUDEDIRS "" "include")

set(COMPONENT_REQUIRES mbedtls)

register_component()
