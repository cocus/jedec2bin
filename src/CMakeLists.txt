
add_executable(jedec2bin jedec2bin.cpp)

target_compile_features(jedec2bin PRIVATE cxx_std_17)


# add_library(MyLibExample simple_lib.cpp simple_lib.hpp)
# target_link_libraries(jedec2bin PRIVATE MyLibExample)