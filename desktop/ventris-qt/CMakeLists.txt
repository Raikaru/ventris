cmake_minimum_required(VERSION 3.21)
project(ventris-qt VERSION 0.4 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(Qt6 6.4 REQUIRED COMPONENTS Widgets Concurrent)
find_package(Threads REQUIRED)

include(GNUInstallDirs)

find_program(CARGO_EXECUTABLE cargo REQUIRED)

set(VENTRIS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(RUST_TARGET "${VENTRIS_ROOT}/target/release")
set(RUST_BRIDGE_LIB "${RUST_TARGET}/liblre_qt_bridge.a")
if(WIN32)
    set(RUST_BRIDGE_LIB "${RUST_TARGET}/lre_qt_bridge.lib")
endif()
set(CPACK_PACKAGE_NAME "ventris")
set(CPACK_PACKAGE_VENDOR "Ventris")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "JVM-free reverse-engineering workstation")
set(CPACK_PACKAGE_CONTACT "Ventris maintainers")
set(CPACK_RESOURCE_FILE_LICENSE "${VENTRIS_ROOT}/LICENSE")
set(CPACK_GENERATOR "TGZ")
set(CPACK_PACKAGE_FILE_NAME
    "${CPACK_PACKAGE_NAME}-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")

# cxx_build emits the C++ ABI header and the Rust static library together.
# The build dependency runs first, so the generated include tree exists before
# automoc/compilation of the Qt target.
add_custom_target(ventris-rust-bridge ALL
    COMMAND "${CARGO_EXECUTABLE}" build --release -p lre-qt-bridge
    WORKING_DIRECTORY "${VENTRIS_ROOT}"
    BYPRODUCTS "${RUST_BRIDGE_LIB}"
    COMMENT "Building the Rust Core/CXX bridge"
)

add_executable(ventris-qt
    src/main.cpp
    src/core_bridge.h
    src/core_bridge.cpp
    src/function_table_model.h
    src/function_table_model.cpp
    src/json_util.h
    src/listing_canvas.h
    src/listing_canvas.cpp
    src/graph_canvas.h
    src/graph_canvas.cpp
    src/decompiler_view.h
    src/decompiler_view.cpp
)
add_dependencies(ventris-qt ventris-rust-bridge)
target_include_directories(ventris-qt PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/generated"
)
target_link_libraries(ventris-qt PRIVATE
    Qt6::Widgets
    Qt6::Concurrent
    "${RUST_BRIDGE_LIB}"
    Threads::Threads
    "${CMAKE_DL_LIBS}"
)
if(WIN32)
    target_link_libraries(ventris-qt PRIVATE ws2_32 bcrypt userenv advapi32)
endif()
if(APPLE)
    target_link_libraries(ventris-qt PRIVATE "-framework Security")
endif()

install(TARGETS ventris-qt
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    BUNDLE DESTINATION .
    COMPONENT Runtime
)

include(CPack)
