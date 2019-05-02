include_directories(include)

file(GLOB SOURCES src/*.cpp)

add_library(cast_auth SHARED ${SOURCES})
