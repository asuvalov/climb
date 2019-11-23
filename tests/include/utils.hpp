#pragma once

#include <sys/stat.h>
#include <string>
#include <iostream>
#include <iomanip>

inline bool is_path_exist(const std::string& path)
{
    struct stat buf;
    return stat(path.c_str(), &buf) == 0;
}

inline void create_dir(const std::string& dir)
{
    if (!is_path_exist(dir)) {
        if (mkdir(dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) != 0) {
            std::cerr << "Failed to create dir: " << dir << std::endl;
        }
    }
}

inline void write_result(const std::string& name, double secs)
{
    std::cout << std::setw(15) << std::left << name << " took " << std::setiosflags(std::ios::fixed) << std::setprecision(8) << std::setw(10) << std::right << secs << " s." << std::endl;
}

namespace std
{

inline ostream& operator<<(ostream& os, const vector<char>& vec)
{
    for (auto val : vec) {
        os << std::hex << val;
    }
    return os;
}

} // std
