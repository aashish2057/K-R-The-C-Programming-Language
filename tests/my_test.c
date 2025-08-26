// my_test.c
#define TEC_IMPLEMENTATION
#include "../tec.h"          // The testing library

TEC(arithmetic, test_addition) {
    TEC_ASSERT_EQ(2 + 2, 4);
    TEC_ASSERT_NE(2 + 2, 5);
}

TEC(string_test, test_strings) {
    const char* str = "hello";
    TEC_ASSERT_STR_EQ(str, "hello");
}

TEC_MAIN()
