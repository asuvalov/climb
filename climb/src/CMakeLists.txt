file(GLOB SOURCES "${CMAKE_SOURCE_DIR}/climb/src/crypto/*.cpp" )

add_library(climb STATIC ${SOURCES})

target_include_directories( climb INTERFACE
  PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries(climb OpenSSL::SSL)
SET(EXECUTABLE_OUTPUT_PATH "${CMAKE_BINARY_DIR}/bin")
