SET(EXECUTABLE_OUTPUT_PATH "${CMAKE_BINARY_DIR}/bin")

# crypto tests

file(GLOB CRYPTO_TESTS "${CMAKE_SOURCE_DIR}/tests/crypto/*.cpp")
add_executable(crypto_test ${CRYPTO_TESTS})
target_link_libraries( crypto_test PRIVATE climb)
target_include_directories( crypto_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/data"
  "${CMAKE_SOURCE_DIR}/src"
)

# elliptic tests

file(GLOB ELLIPTIC_TESTS "${CMAKE_SOURCE_DIR}/tests/elliptic/*.cpp")
add_executable(elliptic_test ${ELLIPTIC_TESTS})
target_link_libraries( elliptic_test PRIVATE climb)
target_include_directories( elliptic_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/data"
  "${CMAKE_SOURCE_DIR}/src"
)
