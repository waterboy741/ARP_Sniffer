add_executable(main_window_tests MainWindowTests.cpp)
target_link_libraries(main_window_tests PRIVATE arp_gui Qt6::Test)
add_test(NAME gui_lifecycle COMMAND main_window_tests)
set_tests_properties(gui_lifecycle PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    TIMEOUT 10
)

add_executable(arp_gui_capture_tests CaptureGuiTests.cpp)
target_link_libraries(arp_gui_capture_tests PRIVATE arp_gui arp_capture Qt6::Test)
add_test(NAME gui_capture COMMAND arp_gui_capture_tests)
set_tests_properties(gui_capture PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    TIMEOUT 60
)

add_executable(arp_parser_tests ArpParserTests.cpp)
target_link_libraries(arp_parser_tests PRIVATE arp_core Qt6::Test)
add_test(NAME arp_parser COMMAND arp_parser_tests)
set_tests_properties(arp_parser PROPERTIES TIMEOUT 20)

add_executable(arp_capture_tests CaptureServiceTests.cpp)
target_link_libraries(arp_capture_tests PRIVATE arp_capture Qt6::Test)
add_test(NAME capture_service COMMAND arp_capture_tests)
set_tests_properties(capture_service PROPERTIES TIMEOUT 20)

add_executable(arp_capture_filter_tests CaptureFilterTests.cpp)
target_link_libraries(arp_capture_filter_tests PRIVATE arp_capture PkgConfig::PCAP Qt6::Test)
add_test(NAME capture_filter COMMAND arp_capture_filter_tests)
set_tests_properties(capture_filter PROPERTIES TIMEOUT 20)

add_executable(arp_storage_replay_tests StorageReplayTests.cpp)
target_link_libraries(arp_storage_replay_tests PRIVATE arp_capture PkgConfig::PCAP Qt6::Test)
add_test(NAME storage_replay COMMAND arp_storage_replay_tests)
set_tests_properties(storage_replay PROPERTIES TIMEOUT 30)
