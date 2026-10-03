# Her test dosyasi kendi calistirilabilirini olusturur ve netfalcon_core'a
# (dolayisiyla parser.hpp/rules.hpp'ye) baglanir. Harici bir test framework'u
# kullanilmiyor — bkz. test_parser.cpp basindaki aciklama.

add_executable(test_parser test_parser.cpp)
target_link_libraries(test_parser PRIVATE netfalcon_core)
add_test(NAME parser_tests COMMAND test_parser)

add_executable(test_rules test_rules.cpp)
target_link_libraries(test_rules PRIVATE netfalcon_core)
add_test(NAME rules_tests COMMAND test_rules)
