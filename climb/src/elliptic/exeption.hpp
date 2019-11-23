#pragma once

#include <exception>
#include <iostream>

namespace climb
{

class exception : public std::exception
{
public:
    exception() : _file(nullptr), _line(0), _msg(nullptr) {}
    exception(const char* file, int line, const char* msg) : _file(file), _line(line), _msg(msg) {}

    friend std::ostream& operator<<(std::ostream& os, const exception& e) {
        return os << "climb::exception : " << e._file << "[" << e._line << "] : " << e._msg << std::endl;
    }

    const char* file() const { return _file;}
    int         line() const { return _line;}
    const char*  msg() const { return _msg;}

private:
    const char* _file;
    int _line;
    const char* _msg;
};

#define CLIMB_THROW_IF(condition)   if (condition) { \
                                        climb::exception e(__FILE__, __LINE__, #condition); \
                                        std::cerr << e; \
                                        throw e; \
                                    }

} // climb
