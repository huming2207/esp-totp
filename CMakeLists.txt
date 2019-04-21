set(COMPONENT_SRCS "otp.c" "include/otp.h")
set(COMPONENT_ADD_INCLUDEDIRS "" "include")

set(COMPONENT_REQUIRES mbedtls)

register_component()
