// VirtualMemory.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#define NOMINMAX
#include <iostream>
#include<Windows.h>
#include<Psapi.h>
#include <fstream>
#include <vector>

#define _100_GB_    (1024*1024*1024*1024)
#define _1_GB_      (1024*1024*1024)
#define _100_MB_      (100*1024*1024)
#define _128_KB_    (1024*1024*128)
#define _4_KB_      (4096)


void PrintMemoryUsage()
{
    PROCESS_MEMORY_COUNTERS_EX pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc)))
    {
        std::cout << "[RAM] Working Set Size: " << pmc.WorkingSetSize / 1024 << " KB\n";
        std::cout << "[Virtual Memory] Private Usage: " << pmc.PrivateUsage / 1024 << " KB\n";
        std::cout << "[Total Commit] Pagefile Usage: " << pmc.PagefileUsage / 1024 << " KB\n";
    }
}

int main()
{
    std::cout << "BEFORE MEMORY PAGING" << std::endl;
    PrintMemoryUsage();

    const SIZE_T totalVirtualMemory = _100_GB_;
    const SIZE_T chunkSize = _1_GB_;

    // Reserve Virtual Memory (not committed yet)
    LPVOID baseAddress = VirtualAlloc(nullptr, totalVirtualMemory, MEM_RESERVE, PAGE_READWRITE);
    if (baseAddress == nullptr) 
    {
        std::cerr << "Fail to reserve virtual memory." << std::endl;
        return -1;
    }

    // Open the large file
    std::ifstream file("large_file.dat", std::ios::binary);
    if (!file.is_open()) 
    {
        std::cerr << "Failed to open the file." << std::endl;
        return -1;
    }

    // Offset inside the file
    SIZE_T offset = 0;

    while (offset < totalVirtualMemory) 
    {
        // Determine size of the current chunk
        SIZE_T currentChunkSize = std::min(chunkSize, totalVirtualMemory - offset);

        // Commit memory for this chunk
        LPVOID chunkAddress = static_cast<LPBYTE>(baseAddress) + offset;
        if (VirtualAlloc(chunkAddress, currentChunkSize, MEM_COMMIT, PAGE_READWRITE) == nullptr) 
        {
            std::cerr << "Failed to commit memory at offset " << offset << std::endl;
            return -1;
        }

        // Read data from file into the committed memory
        file.read(static_cast<char*>(chunkAddress), currentChunkSize);

        // Process the chunk (example: print the first byte)
        std::cout << "Processing chunk at address: " << chunkAddress << std::endl;
        std::cout << "First byte of the chunk: " << *static_cast<BYTE*>(chunkAddress) << std::endl;

        // Free the committed memory after processing
        VirtualFree(chunkAddress, 0, MEM_RELEASE);

        // Move to the next chunk
        offset += currentChunkSize;
    }

    std::cout << "AFTER MEMORY PAGING" << std::endl;
    PrintMemoryUsage();

    file.close();

    // Free the entire reserved memory region
    VirtualFree(baseAddress, 0, MEM_RELEASE);

    std::cout << "File processed successfully." << std::endl;

    system("pause");
    return 0;
}