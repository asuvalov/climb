#include <boost/test/unit_test.hpp>
#include <elliptic/exception.hpp>
#include <string>

BOOST_AUTO_TEST_CASE(exception_test)
{
    int x = 1;
    int y = 2;
    int line = 0;
    const char* file = nullptr;

    bool is_throw = false;
    try {
        line = __LINE__; file = __FILE__; CLIMB_THROW_IF(x != y);
    }
    catch (const climb::exception& e) {
        BOOST_CHECK_EQUAL(e.line(), line);
        BOOST_CHECK(strcmp(file, e.file()) == 0);
        BOOST_CHECK(strcmp("x != y", e.msg()) == 0);
        is_throw = true;
    }

    BOOST_CHECK(is_throw);
}
