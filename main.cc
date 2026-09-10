#include <iostream>
#include <fstream>
#include <filesystem>

#include "ProcessMemory.hpp"
#include "CSchemaSystem.hpp"

int main() {
    SetConsoleTitleA("CS2 SchemaDumper");

    std::cout << "[ ~ ] Waiting for cs2.exe..." << std::endl;

    while (!ProcessMemory::Attach("cs2.exe")) {
        Sleep(500);
    }

    std::cout << "[ + ] Attached to cs2.exe (PID: " << ProcessMemory::GetProcessId() << ")" << std::endl;

    uintptr_t schemaSystemModule = ProcessMemory::GetModuleBase("schemasystem.dll");
    if (!schemaSystemModule) {
        std::cout << "[ - ] Failed to find schemasystem.dll module." << std::endl;
        system("pause");
        return 1;
    }

    std::cout << "[ + ] Found schemasystem.dll at 0x" << std::hex << schemaSystemModule << std::dec << std::endl;

    // Load local module to resolve exported CreateInterface entrypoint reliably
    HMODULE hLocalSchema = LoadLibraryA("schemasystem.dll");
    uintptr_t schemaSystemPtr = 0;

    if (hLocalSchema) {
        typedef void* (*CreateInterfaceFn)(const char* pName, int* pReturnCode);
        CreateInterfaceFn CreateInterface = (CreateInterfaceFn)GetProcAddress(hLocalSchema, "CreateInterface");
        
        if (CreateInterface) {
            // Find signature pattern for SchemaSystem global pointer from CreateInterface export
            schemaSystemPtr = ProcessMemory::Scan("schemasystem.dll", "48 8D 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 48 89 5C 24");
            if (schemaSystemPtr) {
                schemaSystemPtr = ProcessMemory::RelativeDisplacement(schemaSystemPtr, 0x3, 0x7);
            }
        }
        FreeLibrary(hLocalSchema);
    }

    // Fallback pattern scan if export address resolution fails
    if (!schemaSystemPtr) {
        schemaSystemPtr = ProcessMemory::Scan("schemasystem.dll", "48 89 05 ? ? ? ? 48 8D 0D ? ? ? ? 48 8B 01");
        if (schemaSystemPtr) {
            schemaSystemPtr = ProcessMemory::RelativeDisplacement(schemaSystemPtr, 0x3, 0x7);
        }
    }

    if (!schemaSystemPtr) {
        std::cout << "[ - ] Signature scan failed. Make sure CS2 is running and at the main menu." << std::endl;
        system("pause");
        return 1;
    }

    uintptr_t pSchemaSystem = ProcessMemory::Read<uintptr_t>(schemaSystemPtr);
    if (!pSchemaSystem) {
        std::cout << "[ - ] Invalid SchemaSystem pointer." << std::endl;
        system("pause");
        return 1;
    }

    std::cout << "[ + ] SchemaSystem instance found at 0x" << std::hex << pSchemaSystem << std::dec << std::endl;

    CSchemaSystem schemaSystem(pSchemaSystem);
    
    std::filesystem::create_directory("output");

    std::cout << "[ ~ ] Dumping schema type scopes..." << std::endl;
    schemaSystem.DumpTypeScopes("output");

    std::cout << "[ + ] Dump completed successfully! Files saved to 'output' folder." << std::endl;

    system("pause");
    return 0;
}
