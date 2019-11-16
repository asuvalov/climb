#pragma once
#include <chrono>

class timer
{
    using time_point_t = std::chrono::time_point<std::chrono::system_clock, std::chrono::nanoseconds>;
public:
    void start()
    {
        _start = std::chrono::system_clock::now();
    }
    void end()
    {
        _end = std::chrono::system_clock::now();
    }
    auto duration()
    {
        std::chrono::duration<double> diff = _end - _start;
        return diff.count();
    }
    template <class functor>
    static auto estimate(functor f)
    {
        timer t;
        t.start();
        f();
        t.end();
        return t.duration();
    }
private:
    time_point_t _start;
    time_point_t _end;
};
