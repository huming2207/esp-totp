set(COMPONENT_SRCS "otp.cpp" "include/otp.hpp" "key_uri_parser.cpp" "include/key_uri_parser.hpp")
set(COMPONENT_ADD_INCLUDEDIRS "" "include")

set(COMPONENT_REQUIRES mbedtls)

register_component()
