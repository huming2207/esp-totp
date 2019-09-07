set(COMPONENT_SRCS "otp.cpp" "include/otp.hpp" "key_uri.cpp" "include/key_uri.hpp")
set(COMPONENT_ADD_INCLUDEDIRS "" "include")

set(COMPONENT_REQUIRES mbedtls)

register_component()
