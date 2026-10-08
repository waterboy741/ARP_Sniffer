cmake_minimum_required(VERSION 3.25)
project(ARP_Sniffer VERSION 0.1.0 LANGUAGES CXX)

include(CTest)
find_package(Qt6 6.5 REQUIRED COMPONENTS Widgets Concurrent)
if(BUILD_TESTING)
    find_package(Qt6 6.5 REQUIRED COMPONENTS Test)
endif()
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)
qt_standard_project_setup()

add_library(arp_project_options INTERFACE)
target_compile_features(arp_project_options INTERFACE cxx_std_20)
target_compile_options(arp_project_options INTERFACE
    $<$<CXX_COMPILER_ID:AppleClang,Clang,GNU>:-Wall;-Wextra;-Wpedantic;-Wconversion;-Wshadow>
    $<$<CXX_COMPILER_ID:MSVC>:/W4>)
option(ARP_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
if(ARP_ENABLE_SANITIZERS)
    include(CheckCXXSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-fsanitize=address,undefined")
    set(CMAKE_REQUIRED_LINK_OPTIONS "-fsanitize=address,undefined")
    check_cxx_source_compiles("int main() { return 0; }" ARP_SANITIZERS_SUPPORTED)
    unset(CMAKE_REQUIRED_FLAGS)
    unset(CMAKE_REQUIRED_LINK_OPTIONS)
    if(NOT ARP_SANITIZERS_SUPPORTED)
        message(FATAL_ERROR "This compiler cannot compile and link address/undefined sanitizers")
    endif()
    target_compile_options(arp_project_options INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(arp_project_options INTERFACE -fsanitize=address,undefined)
endif()

add_library(arp_core STATIC src/core/ArpParser.cpp src/core/ArpParser.hpp src/core/ArpRecord.hpp)
set_target_properties(arp_core PROPERTIES AUTOMOC OFF AUTOUIC OFF)
target_include_directories(arp_core PUBLIC src)
target_link_libraries(arp_core PUBLIC arp_project_options)

add_library(arp_storage STATIC src/storage/SessionWriter.cpp src/storage/SessionWriter.hpp
    src/storage/CsvExport.cpp src/storage/CsvExport.hpp)
set_target_properties(arp_storage PROPERTIES AUTOMOC OFF AUTOUIC OFF)
target_include_directories(arp_storage PUBLIC src)
target_link_libraries(arp_storage PUBLIC arp_core PRIVATE PkgConfig::PCAP)

add_library(arp_capture STATIC src/capture/CaptureBackend.cpp src/capture/CaptureBackend.hpp
    src/capture/CaptureService.cpp src/capture/CaptureService.hpp)
target_include_directories(arp_capture PUBLIC src)
target_link_libraries(arp_capture PUBLIC arp_core arp_storage Qt6::Core PRIVATE PkgConfig::PCAP)

add_library(arp_gui STATIC src/gui/MainWindow.cpp src/gui/MainWindow.hpp src/gui/ArpTableModel.cpp src/gui/ArpTableModel.hpp)
target_include_directories(arp_gui PUBLIC src)
target_link_libraries(arp_gui PUBLIC Qt6::Widgets Qt6::Concurrent arp_project_options arp_capture)

qt_add_executable(arp_sniffer src/main.cpp)
target_link_libraries(arp_sniffer PRIVATE arp_gui PkgConfig::PCAP)
set_target_properties(arp_sniffer PROPERTIES MACOSX_BUNDLE TRUE
    MACOSX_BUNDLE_GUI_IDENTIFIER "edu.cpre5300.arp-sniffer"
    MACOSX_BUNDLE_BUNDLE_NAME "ARP Sniffer")
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
