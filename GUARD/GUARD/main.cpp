#include "GUARD.hpp"
#include "tables.hpp"
#include <map>
#include "pe_constructor.hpp"
#include <fstream>
#include "winpe/image.hpp"
#include <sstream>
#include <filesystem>
#include <windows.h>
#include <iostream>
#include <string>
#include <cstdio>

#define CON_RED FOREGROUND_RED
#define CON_GRN FOREGROUND_GREEN
#define CON_YLW FOREGROUND_RED | FOREGROUND_GREEN
#define CON_CYN FOREGROUND_BLUE | FOREGROUND_GREEN
#define CON_RESET 0

#ifdef _MSC_VER
#pragma comment(linker, "/STACK:34359738368")
#endif

namespace GUARD
{
    // User-provided settings.
    //
    struct GUARD_settings
    {
        uint32_t target_pid;
        std::string module_name;
        std::optional<uint32_t> ep_rva;
        bool disable_relocation;
    };

    // Attempts to parse the given argument list into GUARD settings.
    //
    std::optional<GUARD_settings> parse_settings( const std::vector<std::string>& arguments )
    {
        // Ensure required argument count.
        //
        if ( arguments.size() < 3 )
            return {};

        // Fetch target PID.
        //
        uint32_t pid = 0;
        ( std::stringstream( arguments[ 1 ] ) ) >> pid;

        // Try to parse hex.
        if ( pid == 0 )
            ( std::stringstream( arguments[ 1 ] ) ) >> std::hex >> pid;

        // Ensure PID validity.
        //
        if ( pid == 0 )
            return {};

        // Fetch target module name.
        //
        std::string target_module_name = arguments[ 2 ];

        std::optional<uint32_t> ep_rva = {};
        bool disable_relocation = false;

        // Fetch any other arguments.
        //
        for ( const std::string& arg : arguments )
        {
            // Should we overwrite the entry point with the user-provided EP?
            //
            if ( arg.find( "-ep=" ) == 0 )
            {
                uint32_t ep;
                ( std::stringstream( arg.substr( 4 ) ) ) >> std::hex >> ep;

                ep_rva = ep;
                continue;
            }

            // Should we mark in the dumped module that relocs have been stripped?
            //
            if ( arg.find( "-disable-reloc" ) )
            {
                disable_relocation = true;
                continue;
            }
        }

        return GUARD_settings { pid, target_module_name, ep_rva, disable_relocation };
    }

    extern "C" int main(int argc, char* argv[])
    {
        std::optional<GUARD_settings> settings = {};

#ifndef _DEBUG
        // Convert C-Style array to C++ vector.
        //
        std::vector<std::string> arguments;
        for (int i = 0; i < argc; i++)
            arguments.push_back({ argv[i] });

        // Try to parse arguments.
        //
        settings = parse_settings(arguments);
#else
        settings = { 0x1244, "", { 0x1D420 }, true };
#endif

        if (!settings)
        {
            printf("** Failed to parse provided arguments\r\n");
            return 0;
        }

        std::unique_ptr<GUARD> instance = GUARD::from_pid(settings->target_pid, settings->module_name);

        if (!instance)
        {
            printf("** Failed to open process 0x%lx\r\n", settings->target_pid);
            return 0;
        }

        printf("** Successfully opened process %s, PID 0x%lx\r\n", instance->target_module_view->module_name, instance->process_id);
        printf("** Selected module: %s\r\n", instance->module_full_path);

        std::map<uint64_t, resolved_import> resolved_imports = {};
        std::vector<import_call> import_calls = {};
        std::map<uint32_t, uint32_t> rdata_export_rva = {};

        instance->scan_for_rdata_imports(resolved_imports, import_calls, *settings->ep_rva, rdata_export_rva);
        instance->scan_for_imports(resolved_imports, import_calls, *settings->ep_rva);
        printf("\n");
        printf("** Found %i calls to %i imports\r\n", import_calls.size(), resolved_imports.size());
        printf("\nStart Constructing IAT using EAT\n");
        //getchar();
        // Define helper structures to organize retrieved data.
        //
        struct export_info
        {
            export_id_t id;
            uint32_t rva;
        };
        struct module_info
        {
            module_view view;
            std::vector<export_info> exports;
        };
        // Resolve exports for all found imports.
        //
        std::map<remote_ea_t, module_info> module_views;
        for (auto& [thunk_rva, import] : resolved_imports)
        {
            // Resolve imported module base.
            //
            std::optional<remote_ea_t> import_module_base = instance->base_from_ea(import.target_ea);
            printf("###############target ea is %x and base is %x and thunk_rva is %x\n", import.target_ea, *import_module_base, thunk_rva);
            if (!import_module_base)
            {
                printf("\t** Failed to resolve import module of function 0x%p\r\n", import.target_ea);
                continue;
            }

            // If module view already exists, fetch it.
            //
            auto it = module_views.find(*import_module_base);
            if (it == module_views.end())
            {
                // Otherwise create the module view.
                //
                std::optional<module_view> import_module_view = instance->view_from_base(*import_module_base);
                printf("module name : %s and base : %x\n", import_module_view->module_name, import_module_view->module_size);
                if (!import_module_view)
                {
                    printf("\t** Failed to construct module view from base 0x%p\r\n", *import_module_base);
                    continue;
                }

                // And insert it into the map.
                //
                it = module_views.insert({ *import_module_base, { *import_module_view, {} } }).first;
            }
            // Convert the import target remote ea to an export identifier for the target module.
            //
            std::optional<export_id_t> export_id = it->second.view.get_export(import.target_ea);
            if (!export_id)
            {
                printf("\t** Failed to resolve export for export 0x%p in module %s\r\n", import.target_ea, it->second.view.module_name);
                continue;
            }
            // Add the resolved export to the module's vector of exports.
            //
            it->second.exports.push_back({ *export_id, (uint32_t)(import.target_ea - it->second.view.module_base) });
            // Notify the user that the export was resolved.
            //
            if (!export_id->first.empty())
            {
                printf("\t** Successfully resolved export ", export_id->first, it->second.view.module_name);
                printf("%s ", export_id->first);
                printf("in module ");
                printf("%s\r\n", it->second.view.module_name);
            }
            else
            {
                printf("\t** Successfully resolved export ", export_id->first, it->second.view.module_name);
                printf("0x%lx ", export_id->second);
                printf("in module ");
                printf("%s\r\n", it->second.view.module_name);
            }
        }
        // Build named imports.
        // These must be built seperately so that they are in the correct order.
        //
        std::vector<import_named_import> named_imports; {}
        std::vector<import_named_import> rdata_named_imports; {}

        for (auto it = module_views.begin(); it != module_views.end(); ) {
            auto& [module_base, module_info] = *it;

            if (module_info.exports.empty()) {
                printf("Removing module with empty exports: module_base=%x module_name=%s\n", module_base, module_info.view.module_name);
                it = module_views.erase(it);
            }
            else {
                for (auto& [export_info, export_rva] : module_info.exports)
                    if (!export_info.first.empty()) {
                        auto rdata_result = rdata_export_rva.find(export_rva);

                        if (rdata_result != rdata_export_rva.end()) {
                            std::cout << std::hex << "rdata Value " << export_info.first << " found : " << export_info.second << std::endl;
                            rdata_named_imports.push_back({ (uint16_t)export_info.second, export_info.first });
                            continue;
                        }
                        named_imports.push_back({ (uint16_t)export_info.second, export_info.first });
                    }
                ++it;
            }
        }
        win::image_t<false>* target_image = instance->target_module_view->local_module.get_image();
        win::nt_headers_x86_t* nt = target_image->get_nt_headers();
        
        // Serialize import names.
        //
        uint64_t import_section_begin_rva = pe_constructor::get_sections_end( instance->target_module_view->local_module );
        auto [named_imports_serialized, named_imports_rvas, named_imports_end] = pe_constructor::serialize_table( named_imports, import_section_begin_rva );
        auto [rdata_named_imports_serialized, rdata_named_imports_rvas, rdata_named_imports_end] = pe_constructor::serialize_table(rdata_named_imports, named_imports_end);
        printf("rdata_named_imports_end : %x\n", rdata_named_imports_end);
        std::cout << "rdata_named_imports size : " << rdata_named_imports.size() << rdata_named_imports_rvas.size() << " named org size : " << named_imports_rvas.size() << std::endl;

        for (auto it = rdata_named_imports_rvas.begin(); it != rdata_named_imports_rvas.end(); ++it) {
            std::cout << *it << std::endl;
        }
        for (auto it = rdata_named_imports_serialized.begin(); it != rdata_named_imports_serialized.end(); ++it) {
            std::cout << *it << std::endl;
        }
        // Build import thunks and import module names.
        //
        std::map<remote_ea_t, uint32_t> module_first_thunk_indices;
        std::vector<embedded_string> module_names;
        std::vector<image_thunk_data_x86> import_thunks;

        std::vector<uint32_t> rdata_import_thunks_rvas;
        std::vector<image_thunk_data_x86> rdata_import_thunks;
        std::vector < std::pair<remote_ea_t, uint32_t>> rdata_module_first_thunk_indices;
        std::vector<uint32_t> rdata_module_names;
        std::map<uint32_t, std::tuple<uint32_t, uint32_t>> rdata_modulename_map;
        std::vector<std::pair<uint32_t, std::tuple<uint32_t, uint32_t>>> insertion_order;


        int name_index = 0;
        int module_name_index = 0; // for rdata
        for ( auto& [module_base, module_info] : module_views )
        {
            printf("For module base : %s : %x\n", module_info.view.module_name, module_base);
            module_first_thunk_indices.insert( { module_base, import_thunks.size() } );
            printf("import_thunks.size() is %x\n", import_thunks.size());
            module_names.push_back( { module_info.view.module_name } );
            
            for ( auto& [export_info, export_rva] : module_info.exports ) 
            {
                std::string& export_name = export_info.first;
                uint32_t export_ordinal = export_info.second;
                
                //auto result = std::find(rdata_export_rva.begin(), rdata_export_rva.end(), export_rva);
                auto it = rdata_export_rva.find(export_rva);

                if (it != rdata_export_rva.end()) {
                    std::cout << std::hex <<  "rdata Value " << export_name << " found : " << it->second << std::endl;
                    if (export_name.empty())
                        continue;
                    //rdata_import_thunks.push_back(image_thunk_data_x86{ .address = named_imports_rvas[name_index++] });
                    //rdata_import_thunks_rvas.push_back(it->second);
                    rdata_modulename_map.insert({ it->second , {module_base, module_name_index} });
                    
                    insertion_order.emplace_back(it->second, std::make_tuple(module_base, module_name_index));
                    //rdata_module_names.push_back({ module_info.view.module_name });
                    continue;                    
                }
                
                // If not named import, import by ordinal.
                //
                if ( export_name.empty() )
                {
                    // Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                    //
                    image_thunk_data_x86 thunk = {};
                    thunk.is_ordinal = true;
                    thunk.ordinal = export_ordinal;
                    printf("its thunk : %s : %x\n", thunk.ordinal);
                    import_thunks.push_back( thunk );
                }
                // Otherwise, import by name RVA.
                //
                else
                {
                    uint32_t named_import_rva = named_imports_rvas[ name_index ];
                    name_index++;

                    printf("its rva : %s, %x\n", export_name, named_import_rva);
                    import_thunks.push_back( image_thunk_data_x86{ .address = named_import_rva } );
                }
            }
            printf("reuslt : %x\n", import_thunks.size());
            module_name_index++;
            // Add an empty thunk to indicate module end.
            //
            import_thunks.push_back( {} );
            
        }

        std::cout << "rdata iter : " << std::endl;
        uint32_t previous_addr, previous_size, previous_module_base = 0;
        uint32_t previous_module_names;
        previous_size = 0;
        if (!insertion_order.empty()) {
            previous_addr = insertion_order.begin()->first;
            previous_module_names = std::get<1>(insertion_order.begin()->second);
        }
        else {
            previous_addr = 0;
            previous_module_names = 0;
        }
        
        int rdata_name_index = 0;
        //import_thunks.insert(import_thunks.end(), rdata_import_thunks.begin(), rdata_import_thunks.end());
        //rdata_import_thunks.push_back({});
        std::cout << "start : " << previous_addr << " previous_module_names " << previous_module_names << std::endl;
        for (const auto& [thunk_rva, module_tuple] : insertion_order) {
                        
            if (thunk_rva - previous_addr > 4) {
                rdata_module_first_thunk_indices.push_back({ previous_addr, previous_size });
                rdata_module_names.push_back({ previous_module_names });
                if (rdata_name_index != 0) {
                    rdata_import_thunks.push_back({});
                    rdata_import_thunks_rvas.push_back({});
                }
                //rdata_import_thunks.clear();
                previous_addr = thunk_rva;
                
                previous_module_names = std::get<1>(module_tuple);
                previous_size = rdata_import_thunks.size();
                std::cout << "rdata added,  import_thunks.size(): " << rdata_import_thunks.size() << " to " << thunk_rva << std::endl;
                std::cout << "previous_addr,  previous_size: " << previous_addr << " & " << previous_size << std::endl;
            } 
            previous_module_base = std::get<0>(module_tuple);
            std::cout << "loop thunk :  " << thunk_rva << " bool: " << (thunk_rva - previous_addr > 4 && previous_module_base != 0) << std::endl;

            uint32_t named_import_rva = rdata_named_imports_rvas[rdata_name_index];
            rdata_name_index++;
            
            printf("its rva : %x\n", named_import_rva);
            rdata_import_thunks.push_back( image_thunk_data_x86{ .address = named_import_rva } );
            //rdata_import_thunks.push_back(image_thunk_data_x86{ .address = thunk_rva });
            rdata_import_thunks_rvas.push_back(thunk_rva);
            std::cout << thunk_rva << " : " << std::get<0>(module_tuple) << std::get<1>(module_tuple) << std::endl;
            
            //module_first_thunk_indices.insert({ module_base, import_thunks.size() });
            //module_names.push_back({ module_info.view.module_name });
            //import_thunks.insert(import_thunks.end(), rdata_import_thunks.begin(), rdata_import_thunks.end());
            //import_thunks.push_back({});            
        }
        std::cout <<  " last addr : " << rdata_modulename_map.end()->first << std::endl;
        if (rdata_modulename_map.end()->first - previous_addr > 4) {
            rdata_module_first_thunk_indices.push_back({ previous_addr, previous_size });
            rdata_module_names.push_back({ previous_module_names });
            //import_thunks.insert(import_thunks.end(), rdata_import_thunks.begin(), rdata_import_thunks.end());
            rdata_import_thunks.push_back({});
            //import_thunks.insert(import_thunks.end(), rdata_import_thunks.begin(), rdata_import_thunks.end());
            //rdata_import_thunks.clear();
            rdata_import_thunks_rvas.push_back({});
            std::cout << "rdata added,  import_thunks.size(), previous_size : " << rdata_import_thunks.size() << " & " << previous_size << std::endl;
        }
        
        
        import_thunks.insert(import_thunks.end(), rdata_import_thunks.begin(), rdata_import_thunks.end());
        int k = 0;
        for (auto [module_base, first_thunk_index] : rdata_module_first_thunk_indices)
        {
            printf("rdata mid module base : %x and first chunk : %x\n", module_base, first_thunk_index);
            printf("import_thunks_rvas[first_thunk_index] : %x\n", rdata_import_thunks_rvas[first_thunk_index]);
        }

        // Serialize module names and import thunks.
        //
        printf("Serialize module names : %x and import thunks : %x\n", module_names.size(), named_imports_end);
        auto [module_names_serialized, module_names_rvas, module_names_end] = pe_constructor::serialize_table( module_names, rdata_named_imports_end);
        printf("\nmodule_names_end : %x\n", module_names_end);
        // Unlike the import table, we aren't gonna create a new IAT; we are going to append the existing one instead.
        // This is because we want to make sure that the existing, non-obfuscated imports are still valid, and it's easier
        // to just append to the existing IAT rather than scanning for all existing imports and relocating them.
        //
        // TODO: Check if the IAT actually exists before using it.
        //
        //uint32_t appended_import_thunks_rva = nt->optional_header.data_directories.iat_directory.rva + nt->optional_header.data_directories.iat_directory.size;
        

        // Parse & transfer existing import directories.
        // As we are creating a new import table, we must preserve the current one by copying it.
        //
        
        std::vector<import_directory> import_directories;
        uint8_t* existing_imports_base = instance->target_module_view->local_module.raw_bytes.data() + nt->optional_header.data_directories.import_directory.rva;
        size_t import_table_offset = 0;
        std::vector<DWORD> func_list;
        /*
        while ( true )
        {
            // Verify we have enough space left for another iteration.
            //
            if (import_table_offset + sizeof(win::import_directory_t) >= nt->optional_header.data_directories.import_directory.size) {
                printf("We don't have enough space lesft for iteration\n");
                break;
            }

            win::import_directory_t* import_dir = ( win::import_directory_t* )( existing_imports_base + import_table_offset );

            import_directories.push_back(
                {
                    .rva_original_first_thunk = import_dir->rva_original_first_thunk,
                    .timedate_stamp = import_dir->timedate_stamp,
                    .forwarder_chain = import_dir->forwarder_chain,
                    .rva_name = import_dir->rva_name,
                    .rva_first_thunk = import_dir->rva_first_thunk
                } );

            // Increment the import table offset by the table size.
            //
            
            BYTE* lib_name = (BYTE*)instance->target_module_view->local_module.raw_bytes.data() + import_dir->rva_name;
            if (import_dir->rva_original_first_thunk == 0) {
                break;
            }
            PIMAGE_THUNK_DATA32 pOriginalIAT = (PIMAGE_THUNK_DATA32)((BYTE*)instance->target_module_view->local_module.raw_bytes.data() + import_dir->rva_original_first_thunk);
            PIMAGE_THUNK_DATA32 pFirstThunk = (PIMAGE_THUNK_DATA32)((BYTE*)instance->target_module_view->local_module.raw_bytes.data() + import_dir->rva_first_thunk);
            while (pOriginalIAT->u1.AddressOfData != 0)
            {
                // Check if the function is imported by ordinal or by name
                if (IMAGE_SNAP_BY_ORDINAL(pOriginalIAT->u1.Ordinal))
                {
                    // Function is imported by ordinal
                    DWORD dwOrdinal = IMAGE_ORDINAL(pOriginalIAT->u1.Ordinal);
                    printf("Imported function by ordinal: %lu\n", dwOrdinal);
                }
                else
                {
                    // Function is imported by name
                    PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)((BYTE*)instance->target_module_view->local_module.raw_bytes.data() + pOriginalIAT->u1.AddressOfData);
                    printf("Imported function by name: (%s)%s : %x & %x\n", lib_name, pImport->Name, pOriginalIAT->u1.AddressOfData, pFirstThunk->u1.Function);
                    func_list.push_back(pFirstThunk->u1.Function);
                }

                // Move to the next function
                ++pOriginalIAT;
                ++pFirstThunk;
            }

            printf("added import_directory_t : %x\n", import_dir->rva_original_first_thunk);
            import_table_offset += sizeof( win::import_directory_t );
        }*/
        //vector, vector, uint32_t
        auto [import_thunks_serialized, import_thunks_rvas, import_thunks_end] = pe_constructor::serialize_table(import_thunks, module_names_end);
        auto [rdata_import_thunks_serialized, dumps, rdata_import_thunks_end] = pe_constructor::serialize_table(rdata_import_thunks, import_thunks_end);
        printf("\import_thunks_end : %x\n", import_thunks_end);
        printf("rdata_import_thunks : %x\n", rdata_import_thunks_end);

        for (auto it = dumps.begin(); it != dumps.end(); ++it) {
            std::cout << *it << " " << std::endl;
        }

        // Create map of {export remote ea, thunk rva} for easy future thunk lookup.
        //
        std::map<uint32_t, uint32_t> export_thunk_rvas;
        std::map<uint32_t, uint32_t> rdata_export_thunk_rvas;
        int thunk_index = 0;
        int rdata_thunk_index = 0;
        bool section_flag = 0;

        for (auto& [module_base, module_info] : module_views)
        {
            printf("module_base : %x and module_info : %s\n", module_base, module_info.view.module_name);

            for (auto& [export_info, export_rva] : module_info.exports)
            {
                printf("export_info : %x and export_rva : %x and import_thunks_rvas : %x \n", export_info, export_rva, module_base + export_rva);
                
                auto it = rdata_export_rva.find(export_rva);

                if (it != rdata_export_rva.end()) {
                    printf("found export_info : %x and export_rva : %x\n", export_info, export_rva);
                    export_thunk_rvas.insert({ module_base + export_rva, rdata_export_rva[export_rva] });
                    printf("for : %x,  : %x\n", module_base + export_rva, rdata_export_rva[export_rva]);
                    /* rdata does not needs to patch
                    rdata_export_thunk_rvas.insert({ module_base + export_rva, rdata_import_thunks_rvas[rdata_thunk_index] });
                    rdata_thunk_index++;*/
                    continue;
                }
                export_thunk_rvas.insert({ module_base + export_rva, import_thunks_rvas[thunk_index] });
                thunk_index++;
            }
            thunk_index++;
        }

        // Now that we have built and serialized the new import thunks, we can fix the calls to said thunks.
        //
        printf("\n");
        printf("** Start Converting %i Calls in %x\r\n", import_calls.size(), resolved_imports.size());
        //getchar();
        for (auto& import_call : import_calls)
        {

            printf("thunk before func call is %x and import_call.import->target_ea is %x and import_call.mov_reg_val is %x and import_call.mov_idx is %x\n",
                export_thunk_rvas[import_call.import->target_ea], import_call.import->target_ea, import_call.mov_reg_val, export_thunk_rvas[import_call.mov_reg_val]);
            if (import_call.mov_reg_val == 0x1000 || import_call.mov_reg_val == 0x2000) {
                printf("\t** mov val 0x1000\n");
                continue;
            }
            else if (import_call.mov_reg_val != 0) {
                printf("\t** mov val not zero\n");
                continue;
            }
            else if (instance->convert_local_call(import_call, instance->target_module_view->module_base + export_thunk_rvas[import_call.import->target_ea],
                instance->target_module_view->module_base + export_thunk_rvas[import_call.mov_reg_val]))
                printf("\t** Successfully converted call @ RVA 0x%lx to thunk @ RVA 0x%lx\r\n", import_call.call_rva, export_thunk_rvas[import_call.import->target_ea]);
            else
                printf("\t** Failed to convert call @ RVA 0x%lx\r\n", import_call.call_rva);
        }
        printf("** after %i Calls in %x\r\n", import_calls.size(), resolved_imports.size());
        // Build import directories.
        //
        int i = 0;
        uint32_t previous_base = 0;
        for ( auto [module_base, first_thunk_index] : module_first_thunk_indices )
        {
            printf("module base : %x and first chunk : %x\n", module_base, first_thunk_index);
            printf("import_thunks_rvas[first_thunk_index] : %x\n", import_thunks_rvas[first_thunk_index]);
           
            import_directories.push_back(
                {
                    .rva_original_first_thunk = import_thunks_rvas[ first_thunk_index ],
                    .timedate_stamp = 0,
                    .forwarder_chain = 0,
                    .rva_name = module_names_rvas[ i ],
                    .rva_first_thunk = import_thunks_rvas[ first_thunk_index ]
                } );
            i++;
        }
        i = 0;
        for (auto [module_base, first_thunk_index] : rdata_module_first_thunk_indices)
        {
            printf("rdata module base : %x and first chunk : %x\n", module_base, first_thunk_index);
            printf("import_thunks_rvas[first_thunk_index] : %x\n", rdata_import_thunks_rvas[first_thunk_index]);
            
            import_directories.push_back(
                {
                    .rva_original_first_thunk = dumps[first_thunk_index],
                    .timedate_stamp = 0,
                    .forwarder_chain = 0,
                    .rva_name = module_names_rvas[rdata_module_names[i]],
                    .rva_first_thunk = rdata_import_thunks_rvas[first_thunk_index]
                });
            i++;
            previous_base = 0;
        }

        printf("import_directories size : %d", import_directories.size());
        // Serialize import directories.
        //
        auto [import_directories_serialized, import_directories_rvas, import_directories_end] = pe_constructor::serialize_table( import_directories, rdata_import_thunks_end);
        printf("\import_directories_end : %x\n", import_directories_end);
        // Concat each serialized buffer to build the new import table section.
        //
        std::vector<uint8_t> import_section;
        import_section.insert( import_section.end(), named_imports_serialized.begin(), named_imports_serialized.end() );
        import_section.insert( import_section.end(), rdata_named_imports_serialized.begin(), rdata_named_imports_serialized.end());
        printf("place to inject named_imports_serialized : %x\n", named_imports_serialized.end() - named_imports_serialized.begin());
        import_section.insert( import_section.end(), module_names_serialized.begin(), module_names_serialized.end() );
        printf("place to inject module_names_serialized : %x\n", module_names_serialized.end() - module_names_serialized.begin());
        import_section.insert(import_section.end(), import_thunks_serialized.begin(), import_thunks_serialized.end());
        import_section.insert(import_section.end(), rdata_import_thunks_serialized.begin(), rdata_import_thunks_serialized.end());
        printf("place to inject import_thunks_serialized : %x\n", import_thunks_serialized.end() - import_thunks_serialized.begin());
        import_section.insert( import_section.end(), import_directories_serialized.begin(), import_directories_serialized.end() );
        printf("place to inject import_directories_serialized : %x\n", import_directories_serialized.end() - import_directories_serialized.begin());
        // Convert the virtual pe image to a raw pe image.
        //
        pe_image raw_module = pe_constructor::virtual_to_raw_image( instance->target_module_view->local_module );

        // Add the new sec tion to the raw module.
        //
        pe_constructor::add_section( raw_module, import_section, import_section_begin_rva, ".newiat", { 0x40000040 } );

        // Set new import data directory.
        //
        auto raw_nt = raw_module.get_image()->get_nt_headers();
        //auto nt_hdrs = get_nt_headers();
        auto last_section = raw_nt->get_section(raw_nt->file_header.num_sections - 2);
        printf("last section raw size : %x and last section virtual size : %x \n", last_section->size_raw_data, last_section->Misc.virtual_size);
        if (last_section->size_raw_data != last_section->Misc.virtual_size)
            last_section->Misc.virtual_size = last_section->size_raw_data;
        raw_nt->optional_header.data_directories.import_directory.rva = rdata_import_thunks_end;
        raw_nt->optional_header.data_directories.import_directory.size = import_directories_end - rdata_import_thunks_end;
        raw_nt->optional_header.data_directories.iat_directory.rva = module_names_end;
        raw_nt->optional_header.data_directories.iat_directory.size = import_thunks_serialized.size();
        printf("import directory rva : %x and size : %x\n", import_thunks_end, import_directories_end - import_thunks_end);
        // Add our new import thunks to the pre-existing IAT.
        // TODO: verify we have enough space left in the section!
        //
        //memcpy( raw_module.get_image()->rva_to_ptr(module_names_end), import_thunks_serialized.data(), import_thunks_serialized.size() );
        //raw_nt->optional_header.data_directories.iat_directory.size += import_thunks_serialized.size();



        std::string module32_full_path = instance->module_full_path;

        printf("module full path : %s\n", module32_full_path.c_str());
        std::fstream org_file(module32_full_path, std::ios::in | std::ios::binary);

        if (!org_file.is_open()) {
            printf("error during open file\n");
        }
        // infile 용의 파일 크기 구함
        org_file.seekg(0, std::ifstream::end);
        long size = org_file.tellg();
        org_file.seekg(0);


        char* buf = new char[size];

        org_file.read(buf, size);

        org_file.seekp(0, std::ios::beg);
        PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)buf;

        PIMAGE_NT_HEADERS32 pINH = (PIMAGE_NT_HEADERS32)((size_t)dos_header + dos_header->e_lfanew); // IMAGE_NT_HEADER를 공식으로 구함
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
            //raw_nt->get_section(i)->characteristics. = SH[i].Characteristics;
            //memcpy(raw_nt->get_section(i)->characteristics, SH[i].Characteristics);
            //IMAGE_SCN_MEM_EXECUTE                0x20000000  // Section is executable.
            //IMAGE_SCN_MEM_READ                   0x40000000  // Section is readable.
            //IMAGE_SCN_MEM_WRITE                  0x80000000  // Section is writeable.
            if (SH[i].Characteristics & 0x20000000)
                raw_nt->get_section(i)->characteristics.mem_execute = 1;
            if (SH[i].Characteristics & 0x40000000)
                raw_nt->get_section(i)->characteristics.mem_read = 1;
            if (SH[i].Characteristics & 0x80000000)
                raw_nt->get_section(i)->characteristics.mem_write= 1;
            //printf("char : %x\n", raw_nt->get_section(i)->characteristics.mem_write);


        }

        // Get the TLS directory
        PIMAGE_TLS_DIRECTORY pTlsDirectory = (PIMAGE_TLS_DIRECTORY)((DWORD_PTR)dos_header + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        
        if (pTlsDirectory == NULL) {
            printf("Error finding TLS directory\n");
        }
        else {
            printf("TLS test : %x\n", raw_nt->optional_header.data_directories.tls_directory.rva);
            raw_nt->optional_header.data_directories.tls_directory.rva = 0;
            raw_nt->optional_header.data_directories.tls_directory.size = 0;
        }



        // Update EP if provided.
        //
        if ( settings->ep_rva )
            raw_nt->optional_header.entry_point = *settings->ep_rva;

        // Disable relocation if requested.
        //
        if ( settings->disable_relocation )
            raw_nt->file_header.characteristics.relocs_stripped = true;

        // Remove any integrity flags.
        //
        raw_nt->optional_header.characteristics.force_integrity = false;

        printf( "** New ImageBase: 0x%llx, SizeOfImage: 0x%lx\r\n", raw_nt->optional_header.image_base, raw_nt->optional_header.size_image );

        // Save module.
        //
        std::filesystem::path module_path = { instance->module_full_path };
        module_path.remove_filename();
        module_path /= instance->target_module_view->module_name;

        module_path.replace_extension( "Restored" + module_path.extension().string() );
        std::ofstream outfile( module_path.string(), std::ios::out | std::ios::binary );
        outfile.write( ( const char* )raw_module.raw_bytes.data(), raw_module.raw_bytes.size() );

        std::cout << "** File written to: " << module_path.string() << std::endl;

        return 0;
    }
}