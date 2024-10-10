#include "module_view.hpp"
#include <windows.h>
#include <fstream>

namespace GUARD
{
    // Commits any local module changes back to the target process.
    //
    bool module_view::commit() const
    {
        bool result = false;

        // Try to open the process.
        //
        HANDLE process_handle = OpenProcess( PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, process_id );
        if ( !process_handle )
            return false;

        // Get RWX permissions.
        //
        DWORD new_protect = PAGE_EXECUTE_READWRITE;
        DWORD old_protect;
        if ( !VirtualProtectEx( process_handle, ( LPVOID )module_base, module_size, new_protect, &old_protect ) )
            goto cleanup;

        // Write the memory.
        //
        ULONG_PTR num_written;
        if ( WriteProcessMemory( process_handle, ( LPVOID )module_base, local_module.cdata(), local_module.size(), &num_written ) && num_written == module_size )
            result = true;
        // Restore old memory permissions.
        //
        if ( !VirtualProtectEx( process_handle, ( LPVOID )module_base, module_size, old_protect, &new_protect ) )
            result = false;
        // On function exit, close the handle.
        //
    cleanup:
        CloseHandle( process_handle );
        return result;
    }

    // Fetches any remote module changes back to the local module buffer.
    //
    bool module_view::fetch()
    {
        bool result = false;
        // Try to open the process.
        //
        HANDLE process_handle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, process_id );
        if ( !process_handle )
            return false;

        // Resize the local module in case it's not allocated yet.
        //
        local_module.raw_bytes.resize( module_size );
        
        // Read the memory.
        //
        SIZE_T num_written;

        //unsigned __int64 temp_local_module;
        //DWORD oldProtect = 0;

        //VirtualProtectEx(process_handle, (LPVOID)module_base, local_module.size(), PAGE_EXECUTE_READWRITE, (PDWORD)oldProtect);
        /*
        if (ReadProcessMemory(process_handle, (LPVOID)module_base, local_module.data(), 0x1000, &num_written))
            result = true;
        printf("$$$$$$$$$$$$$$$$$$$$$$$$$ fetch is called : %d in %s\n", result, module_name);
        printf("error num is %d", GetLastError());
        printf("module_base is %x and local_module.size is %x and num_written is %x", module_base, local_module.size(), num_written);
        */



        
        if ( ReadProcessMemory( process_handle, (LPVOID)module_base, local_module.data(), local_module.size(), &num_written ) && num_written == local_module.size() )
            result = true;
        
        //VirtualProtectEx(process_handle, (LPVOID)module_base, local_module.size(), (DWORD)oldProtect, NULL);
        /*
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)local_module.data();
        IMAGE_NT_HEADERS pNT = { 0 };
        if (!ReadProcessMemory(process_handle, (void*)((unsigned long)module_base + pDos->e_lfanew), &pNT, sizeof(IMAGE_NT_HEADERS), 0))
            printf("##################################fail.....");
        
        if (pNT.Signature == IMAGE_NT_SIGNATURE) // this condition returns TRUE
        {
            printf("NT Header Signature is valid\n");
            printf("Timestamp: %d\n", pNT.FileHeader.TimeDateStamp);
            // TimeDateStamp returns me 0 - why ?
        }*/
        // On function exit, close the handle.
        //
    cleanup:
        CloseHandle( process_handle );
        return result;
    }

    // Returns the export name (if available) and ordinal.
    //
    std::optional<export_id_t> module_view::get_export( remote_ea_t ea )
    {
        using namespace win;
        printf("ea is %x and base is %x\n", ea, module_base);
        uint32_t new_ea = ea;
        uint32_t rva = new_ea - module_base;
        printf("rva? :%x\n", rva);
     

        std::string system32_string = "system32";
        std::string lower_case_path = module_path;
        printf("module path : %s\n ", module_path.c_str());
        // Convert the string to all lowercase using a loop
        for (std::size_t i = 0; i < module_path.length(); ++i) {
            lower_case_path[i] = std::tolower(module_path[i]);
        }
        printf("lowecase module path : %s\n ", lower_case_path.c_str());
        // Check if the word is present in the string

        
        std::string module32_full_path;
        if (lower_case_path.find(system32_string) != std::string::npos) {
            std::string wow_path = "C:\\Windows\\SysWOW64\\";
            module32_full_path = wow_path + module_name;
        }
        else {
            module32_full_path = module_path;
        }


        
        

        // Check if ea is in module bounds.
        //
        
        if ( !within_bounds(new_ea) )
            return {};
        
        std::fstream org_file(module32_full_path, std::ios::in | std::ios::binary);

        if (!org_file.is_open()) {
            printf("error during open file\n");
            return {};
        }

        // infile ���� ���� ũ�� ����
        org_file.seekg(0, std::ifstream::end);
        long size = org_file.tellg();
        org_file.seekg(0);
        

        char* buf = new char[size];

        org_file.read(buf, size);

        org_file.seekp(0, std::ios::beg);
        PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)buf;
        
        PIMAGE_NT_HEADERS32 pINH = (PIMAGE_NT_HEADERS32)((size_t)dos_header + dos_header->e_lfanew); // IMAGE_NT_HEADER�� �������� ����
        /*
        printf("dos header address : %x\n", dos_header);
        printf("OH magic : %x", pINH->OptionalHeader.Magic);
        */
        PIMAGE_FILE_HEADER FH = (PIMAGE_FILE_HEADER) & (pINH->FileHeader);
        PIMAGE_OPTIONAL_HEADER32 OH = (PIMAGE_OPTIONAL_HEADER32) & (pINH->OptionalHeader);
        PIMAGE_SECTION_HEADER SH = (PIMAGE_SECTION_HEADER)(buf + dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS32));

        unsigned int export_data_dir_va = OH->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        unsigned int taget_sec_idx = -1;

        //printf("to find : %x \n", OH->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        for (int i = 0; i < FH->NumberOfSections; i++) {
            if (SH[i].VirtualAddress <= export_data_dir_va && export_data_dir_va <= SH[i].VirtualAddress + SH[i].SizeOfRawData) {
                taget_sec_idx = i;
                break;
            }
        }
        /*
        if (taget_sec_idx == -1) {
            printf("failed to find sections\n");
        }
        printf("taget_sec_idx : %x\n", taget_sec_idx);
        */
        PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)(buf + OH->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
            - SH[taget_sec_idx].VirtualAddress + SH[taget_sec_idx].PointerToRawData);
        /*
        printf("file header? : %x\n", FH->SizeOfOptionalHeader);
        printf("SH? : %x\n");

        printf("number of func : %x\n", export_dir->NumberOfFunctions);
        printf("AddressOfFunctions : %x\n", export_dir->AddressOfFunctions);*/
        uint32_t* eat = (uint32_t*)(buf + export_dir->AddressOfFunctions - SH[taget_sec_idx].VirtualAddress + SH[taget_sec_idx].PointerToRawData);
        uint32_t* names = (uint32_t*)(buf + export_dir->AddressOfNames - SH[taget_sec_idx].VirtualAddress + SH[taget_sec_idx].PointerToRawData);
        uint16_t* name_ordinals = (uint16_t*)(buf + export_dir->AddressOfNameOrdinals - SH[taget_sec_idx].VirtualAddress + SH[taget_sec_idx].PointerToRawData);
        /*
        auto image = local_module.get_image();
        printf("image isze is %x\n", local_module.size());
        auto export_dir_header = image->get_directory( directory_id::directory_entry_export );
        printf("got directory\n");
        if (export_dir_header == NULL)
            printf("null sibl\n");

        HMODULE mod = GetModuleHandle(module_name.c_str());

        DWORD EATA, OP;
        IMAGE_DOS_HEADER* DOSH = (IMAGE_DOS_HEADER*)mod;
        dos_header_t* DOSH2 = (dos_header_t*)mod;
        IMAGE_NT_HEADERS* NTH = NULL;
        IMAGE_NT_HEADERS* NTH2 = NULL;

        printf("DOSH : %x\n", DOSH);

        if (DOSH->e_magic != IMAGE_DOS_SIGNATURE) printf("fail\n");

        NTH = ((PIMAGE_NT_HEADERS)((ULONG_PTR)(DOSH)+(ULONG_PTR)(DOSH->e_lfanew)));

        if (NTH->Signature != IMAGE_NT_SIGNATURE) printf("fail\n");
        printf("NTH->Signature : %x\n", NTH->Signature);

        EATA = NTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        IMAGE_EXPORT_DIRECTORY* EATP = (IMAGE_EXPORT_DIRECTORY*)((size_t)EATA + (size_t)mod);

        printf("number of func : %x\n", EATP->NumberOfFunctions);

        uint32_t* eat = (uint32_t*)((size_t)mod + EATP->AddressOfFunctions);
        uint32_t* names = (uint32_t*)((size_t)mod + EATP->AddressOfNames);
        uint16_t* name_ordinals = (uint16_t*)((size_t)mod + EATP->AddressOfNameOrdinals);
        */
        uint32_t function_ordinal = -1;
        for (int i = 0;i < export_dir->NumberOfFunctions;i++)
        {
            if (eat[i] == rva) {
                function_ordinal = i;
                printf("function_ordinal is %d\n", i);
            }

        }

        // Verify function was found.
//
        if (function_ordinal == -1)
            return {};

        uint32_t name_ordinal = -1;

        // Resolve effective addresses of each export table.
       
        // Resolve name ordinal.
        //
        for (uint32_t i = 0; i < export_dir->NumberOfNames; i++) {
            //printf("Export: %x : %s\n", i, (size_t)mod + (size_t)names[i]);
            if (name_ordinals[i] == function_ordinal)
                name_ordinal = i;
        }

        uint32_t ordinal = export_dir->Base + function_ordinal;
        printf("EATP->Base : %x and function_ordinal : %x, ordinal? : %x\n", export_dir->Base, function_ordinal, ordinal);
        // If no name ordinal found, return function ordinal.
        //
        if ( name_ordinal == -1 )
            return { { { "" }, ordinal } };

        // Return function name.
        //
        return { { std::string( ( const char* )((size_t)buf + names[ name_ordinal ] - SH[taget_sec_idx].VirtualAddress + SH[taget_sec_idx].PointerToRawData) ), ordinal } };
    }
}