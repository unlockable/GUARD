#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <optional>
#include <memory>
#include <vector>
#include <map>
#include "imports.hpp"
#include "module_view.hpp"

namespace GUARD
{
    // The master class allowing for easy access to all dumper and import reconstruction functionality.
    //
    class GUARD
    {
    public:
        // The target process' id.
        //
        const uint32_t process_id;
        
        // A map of { module base, { module name, module size> }.
        //
        const std::map<remote_ea_t, std::pair<std::string, size_t>> process_modules;
        const std::map<std::string, std::string> process_dll_paths;

        // A view to the target module for dumping.
        //
        std::unique_ptr<module_view> const target_module_view;

        // The full path to the target module.
        //
        const std::string module_full_path;

        typedef struct iat_info {
            uint64_t thunk_rva;
            uint64_t dest_op;
            int32_t stack_adjustment;
            bool padded;
            bool is_jmp;
        } iat_info;
        // Disallow construction + copy.
        //
        GUARD() = delete;
        GUARD( const GUARD& ) = delete;
        GUARD& operator=( const GUARD& ) = delete;
        
        // Allow move.
        //
        GUARD( GUARD&& ) = default;
        GUARD& operator=( GUARD&& ) = default;

        bool check_section_range(uint64_t current_rva, uint64_t _test_section_rva, size_t sec_size);
        // Scans the specified code range for any import calls and imports.
        // resolved_imports is a map of { import thunk rva, import structure }.
        //
        bool scan_for_imports( uint64_t rva, size_t code_size, std::map<uint64_t, resolved_import>& resolved_imports, std::vector<import_call>& import_calls, uint32_t flags = 0 );
        
        // Scans all executable sections of the image for any import calls and imports.
        //
        bool scan_for_imports( std::map<uint64_t, resolved_import>& resolved_imports, std::vector<import_call>& import_calls, uint32_t ep_rva, uint32_t flags = 0 );
        bool scan_for_rdata_imports(std::map<uint64_t, resolved_import>& resolved_imports, std::vector<import_call>& import_calls, uint32_t ep_rva, std::map<uint32_t, uint32_t>& rdata_export_rva, uint32_t flags = 0);

        // Attempts to generate a stub in a code cave in the section of the call rva which jmps to the given thunk.
        // Returns the stub rva.
        //
        std::optional<uint32_t> generate_stub( uint32_t rva, remote_ea_t thunk );

        // Attempts to convert the provided call to the VMP import stub to a direct import thunk call to the specified remote thunk ea.
        //
        bool convert_local_call( const import_call& call, remote_ea_t thunk, remote_ea_t reg_val);

        // Constructs a module_view from the given remote module base.
        //
        std::optional<module_view> view_from_base( remote_ea_t base ) const;

        // Retrieves the module base from the given remote ea.
        //
        std::optional<remote_ea_t> base_from_ea( remote_ea_t ea ) const;

        // Creates a GUARD class from the given process id and target module name.
        // If module_name is empty "", the process module is used.
        // If the process cannot be opened for some reason or the module cannot be found, returns empty {}.
        //
        static std::unique_ptr<GUARD> from_pid( uint32_t process_id, const std::string& module_name = "" );
        // Constructor.
        //
        GUARD( uint32_t process_id, const std::map<remote_ea_t, std::pair<std::string, size_t>>& process_modules, std::map<std::string, std::string>&process_dll_paths, std::unique_ptr<module_view> target_module_view, const std::string& module_full_path )
            : process_id( process_id ), process_modules( process_modules ), process_dll_paths(process_dll_paths), target_module_view( std::move( target_module_view ) ), module_full_path( module_full_path )
        {}
    };
}