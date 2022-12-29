#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <Windows.h>
#include <intrin.h>
#include <sstream>


bool compare(const uint8_t* pData, const uint8_t* bMask, const char* szMask) {
    for (; *szMask; ++szMask, ++pData, ++bMask) {
        if (*szMask == 'x' && *pData != *bMask) {
            return 0;
        }
    }
    return (*szMask) == NULL;
}

uintptr_t find_pattern(uintptr_t dwAddress, uintptr_t dwLen, uint8_t* bMask, char* szMask) {
    for (uintptr_t i = 0; i < dwLen; i++) {
        if (compare((uint8_t*)(dwAddress + i), bMask, szMask)) {
            return dwAddress + i;
        }
    }
    return 0;
}

std::vector<std::string> split_str(std::string s, char delim) {
    std::vector<std::string> result;
    std::istringstream string_stream;
    string_stream.clear();
    string_stream.str(s);
    std::string temp;
    while (std::getline(string_stream, temp, delim))
        result.push_back(temp);
    return result;
}

uintptr_t scan_ida(std::string ida_pattern, uintptr_t start_address, size_t length) {
    std::vector<std::string> bytes = split_str(ida_pattern, ' ');
    std::string pattern = "", mask = "";

    for (auto& it : bytes) {
        if (it.size() && it[0] == '?') {
            mask += '?';
            pattern += '\0';
        }
        else {
            mask += 'x';
            pattern += (unsigned char)std::strtol(it.c_str(), NULL, 16);
        }
    }

    return find_pattern(start_address, length, (uint8_t*)pattern.c_str(), const_cast<char*>(mask.c_str()));
}

void patchBuffer(DWORD start, std::string patch) {
    std::vector<std::string> bytes = split_str(patch, ' ');
    std::string norm_patch = "";

    for (std::string stuff : bytes) {
        norm_patch += static_cast<char>(std::strtol(stuff.c_str(), NULL, 16));
    }

    for (int i = 0; i < norm_patch.length(); i++) {
        *reinterpret_cast<char*>(start + i) = norm_patch[i];
    }

}




int main(int argc, char* argv[])
{
    //std::cout << std::get<1>(GetSigMask("0F 84 ? ? ? ? F3 0F 10 0D"));

    if (argc == 2) {
        std::ifstream infile(argv[1], std::ios::binary);

        if (infile.good()) {
            // copies all data into buffer
            std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(infile), {});
            infile.close();

            DWORD func_call = scan_ida("E8 ? ? ? ? 80 7B 19 00", reinterpret_cast<uintptr_t>(&buffer[0]), buffer.size());
            DWORD func_ptr = func_call + 0x5 + *(DWORD*)(func_call + 1);
            
            patchBuffer(func_ptr + 0x5FE, "0F 85");
            func_ptr = scan_ida("89 91 ?? ?? ?? ?? 33 C0 C3 CC CC CC CC CC CC CC 48 89 74 24 ??", reinterpret_cast<uintptr_t>(&buffer[0]), buffer.size());
            patchBuffer(func_ptr, "90 90 90 90 90 90");


            std::ofstream outfile;
            outfile.open("Gr2D_DX9patch.dll", std::ios::trunc | std::ios::binary);
            outfile.write(reinterpret_cast<char*>(&buffer[0]), buffer.size());
            outfile.close();

        }
        else {
            std::cout << "fail to load file\n";

        }

    }
    else {
        std::cout << "lack of args\n";
    }


}

//0F 84 ? ? ? ? F3 0F 10 0D ? ? ? ?


