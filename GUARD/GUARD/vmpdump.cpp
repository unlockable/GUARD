#include "GUARD.hpp"
#include <psapi.h>
#include <Shlwapi.h>
#include "disassembler.hpp"
#include <map>
#include <cstdint>
#include <vtil/compiler>
#include <vtil/common>
#include <vtil/symex>
#include <lifters/core>
#include <lifters/amd64>
#include <vector>
#include <unicorn/unicorn.h>
#include <keystone/keystone.h>

#define X86_CODE32 "\xe8\x6\xfd\xff\xff"
namespace GUARD
{
    uint32_t api_addr = 0;
    uint64_t last_ret_addr = 0;
    // Structure used to return raw import stub analysis information.
    //
    struct import_stub_analysis
    {
        uintptr_t thunk_rva;
        uintptr_t dest_offset;
        uint32_t mov_reg;
        uint32_t mov_thunk;
        int32_t stack_adjustment;
        bool padding;
        bool is_jmp;
    };
    int bitoffset = 4; //32 4 64 8
    uint32_t next_address_offset_global;

    // Attempts to generate structures from the provided call EA and instruction_stream of a VMP import stub.
    // Returns empty {} if the import stub failed analysis (and therefore is an invalid stub).
    //
    
    void uc_perror(const char* func, uc_err err)
    {
        fprintf(stderr, "Error in %s(): %s\n", func, uc_strerror(err));
    }

    void hook_other_ins(uc_engine* uc, void* user_data)
    {
        uint32_t eip;
        if (uc_reg_read(uc, X86_REG_EIP, &eip)) {
            printf("Failed to read emulation code1 to memory, quit!\n");
        }
        if (eip == next_address_offset_global) {
            printf("other ins_found\n");
            uc_emu_stop(uc);
        }
    }
    /*
    void hook_debug(uc_engine* uc, int32_t* user_data)
    {
        uint32_t eip;
        if (uc_reg_read(uc, X86_REG_EIP, &eip)) {
            printf("Failed to read emulation code1 to memory, quit!\n");
        }
        printf("tested eip is %x\n", eip);
        //printf("%X : hook called~~\n\n", eip);

    }*/

    void hook_syscall(uc_engine* uc, int32_t* user_data)
    {
        uint32_t eip;
        if (uc_reg_read(uc, X86_REG_EIP, &eip)) {
            printf("Failed to read emulation code1 to memory, quit!\n");
        }
        //printf("tested eip is %x\n", (user_data));
        //printf("%X : hook called~~\n\n", eip);
        api_addr = eip;
    }

    void hook_ret(uc_engine* uc, void* user_data)
    {
        uint32_t eip;
        if (uc_reg_read(uc, X86_REG_EIP, &eip)) {
            printf("Failed to read emulation code1 to memory, quit!\n");
        }
        //printf("tested eip is %x\n", (user_data));
        //printf("%X : hook read called\n\n", eip);
        last_ret_addr = eip;
        /*
        if (!cs_disasm_iter(disassembler::get().get_handle(), (const uint8_t**)&eip, &module_size, &last_ret_addr, disassembler::get().get_insn()))
        {
            printf("fail to fetch ret\n");
            return{ 0 };
        }
        instruction ret_ins = { disassembler::get().get_insn() };*/        
    }

    import_stub_analysis get_api_info(uc_engine* uc, auto start_address_offset, auto next_address_offset, auto esp_addr, auto module_start_address,
        auto module_size, auto local_module_bytes)
    {
        byte zero_bytes[0x20000] = { 0 };
        uc_err err;
        uint32_t mov_reg_idx = 0, mov_thunk = 0;
        if (uc_mem_write(uc, esp_addr, zero_bytes, sizeof(zero_bytes))) { // stack value initialization
            printf("Failed to write emulation code to memory, quit!\n");
        }
        esp_addr += 0x10000;

        if (uc_reg_write(uc, X86_REG_ESP, &esp_addr)) {
            printf("Failed to write emulation code1 to memory, quit!\n");
        }
        int syscall_abi[] = {
                    UC_X86_REG_EAX, UC_X86_REG_EDI, UC_X86_REG_ESI, UC_X86_REG_EDX,
                    UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EBP
        };
        void* ptrs[7];
        uint32_t vals[7] = { 0, 0, 0, 0, 0, 0, 0 };

        for (int i = 0; i < 7; i++) {
            ptrs[i] = &vals[i];
        }

        uc_reg_write_batch(uc, syscall_abi, ptrs, 7);

        uc_hook sys_hook;
        api_addr = 0;
        
        printf("hook range address : from %x to %x\n", module_start_address, module_start_address + module_size);
        if ((err = uc_hook_add(uc, &sys_hook, UC_HOOK_CODE, hook_other_ins, NULL, module_start_address, module_start_address + module_size))) {
            uc_perror("uc_hook_add", err);
            //return 1;
        }
        /*
        if ((err = uc_hook_add(uc, &sys_hook, UC_HOOK_CODE, hook_debug, NULL, 0x0, 0x7fffffff))) {
            uc_perror("uc_hook_add", err);
            //return 1;
        }*/
        if ((err = uc_hook_add(uc, &sys_hook, UC_HOOK_MEM_FETCH_UNMAPPED, hook_syscall, NULL, 1, 0))) {
            uc_perror("uc_hook_add", err);
            //return 1;
        }
        if ((err = uc_hook_add(uc, &sys_hook, UC_HOOK_MEM_READ, hook_ret, NULL, 1, 0))) {
            uc_perror("uc_hook_add", err);
            //return 1;
        }
        
        printf("last_ret_addr : %x\n", last_ret_addr);
        /*
        uint8_t* ret_addr = local_module_bytes + last_ret_addr;

        if (!cs_disasm_iter(disassembler::get().get_handle(), (const uint8_t**)&ret_addr, &module_size, &last_ret_addr, disassembler::get().get_insn()))
        {
            printf("fail to fetch ret\n");
            return{0};
        }
        instruction ret_ins = { disassembler::get().get_insn() };*/
        next_address_offset_global = next_address_offset;
        err = uc_emu_start(uc, start_address_offset, 0, 0, 500);
  
        if (err) {
            if (api_addr != 0) {
                printf("sucessfully found : %x\n", api_addr);
            }
            else {
                uint32_t r_eip;
                if (uc_reg_read(uc, X86_REG_EIP, &r_eip)) {
                    printf("Failed to write emulation code to memory, quit!\n");
                }
                printf("error with failed... : %x\n", r_eip);
                return import_stub_analysis{ 0 };
            }
        }
        else if (api_addr == 0) {

            for (int i = 0; i < 7; i++) {
                ptrs[i] = &vals[i];
            }

            uc_reg_read_batch(uc, syscall_abi, ptrs, 7);
            printf("other ins : ");
            for (int i = 0; i < 7; i++) {
                if (vals[i] != 0) {
                    printf("%x\n", vals[i]);
                    mov_reg_idx = i;
                    mov_thunk = vals[i];
                }
            }
        }

        uint32_t return_address_in_stack, return_address_in_stack_above;
        uint32_t r_esp, bitoffset = 4;
        bool padded = 0, is_jmp = 0;
        int32_t stack_adjustment = 0;
        if (uc_reg_read(uc, X86_REG_ESP, &r_esp)) {
            printf("Failed to write emulation code to memory, quit!\n");
        }

        if (uc_mem_read(uc, (r_esp), &return_address_in_stack, sizeof(return_address_in_stack))) {
            printf("Failed to write emulation code to memory, quit!\n");
        }
        printf("return_address_in_stack is %x\n", return_address_in_stack);
        printf("r_esp is %x and org esp_addr is %x\n", r_esp, esp_addr);

        // jmp는 API 진입 시 esp 위치와 진입 전 esp 위치가 동일
        // stackadjust로 인해 esp 위치와 진입 전 esp 위치가 동일한 케이스가 존재
        // 하지만 이는 next address가 다른 것으로 구분 가능 
        // 그런데 jmp도 e8 call로 변형된 것이으로 adjustment된 케이스가 있을 수 있지 않을까? => 그래도 next address 가 다르므로 구분 가능
        // stack adjustment는 stack의 위치를 비교해보는 것이 필요
        // 
        // padded는 next address가 + 1일경우
        // 정상적인 case => return address가 next address offset과 일치하는 경우 (call에 해당)

        //바로 위에 push가 있는 경우를 생각 가능 이럴경우에 +4와 일치하여야함
        //jump일 경우 마찬가지로 위에 push가 있어서 조정되었는지를 확인해야함

        if (return_address_in_stack != next_address_offset) { // stack is adjusted or padded
            if (return_address_in_stack == next_address_offset + 1) { // padded case
                padded = 1;
            }
            else {
                if (uc_mem_read(uc, (r_esp - bitoffset), &return_address_in_stack_above, sizeof(return_address_in_stack_above))) {
                    printf("Failed to write emulation code to memory, quit!\n");
                }
                /*
                if ((r_esp) == esp_addr && return_address_in_stack_above == next_address_offset) {
                    printf("1\n");
                    stack_adjustment = bitoffset;
                }*/
                else {
                    if ((r_esp) == esp_addr) {
                        is_jmp = 1;
                    }
                    else {
                        is_jmp = 1;
                        stack_adjustment = r_esp - esp_addr;
                    }
                }

            }
        }
        else { // consider call with push
            stack_adjustment = bitoffset;
        }
        return import_stub_analysis{ 0, 0, mov_reg_idx, mov_thunk, stack_adjustment, padded, is_jmp };
    }
    // Scans the specified code range for any import calls and imports.
    // resolved_imports is a map of { import thunk rva, import structure }.
    //

    bool GUARD::check_section_range(uint64_t current_rva, uint64_t test_section_rva, size_t sec_size)
    {
        //printf("current rva is %x and test_section_rva : %x and test_section_rva + sec_size : %x\n", current_rva, test_section_rva, test_section_rva + sec_size);
        //printf("current_rva : %x and 1: %x and 2 : %x\n", current_rva, current_rva >= test_section_rva, current_rva <= test_section_rva + sec_size);
        return (current_rva >= test_section_rva && current_rva <= test_section_rva + sec_size) ? false : true;
    }

    bool GUARD::scan_for_imports( uint64_t rva, size_t code_size, std::map<uint64_t, resolved_import>& resolved_imports, std::vector<import_call>& import_calls, uint32_t flags )
    {
        uint8_t* local_module_bytes = ( uint8_t* )target_module_view->local_module.data();
        size_t size = code_size;

        uint8_t* code_start = local_module_bytes + rva;
        uint64_t start_offset = rva;
        uint64_t offset = start_offset;
        std::vector <uint64_t> jmp_call;
        std::map<uint64_t, bool> call_visited;

        auto raw_nt = target_module_view->local_module.get_image()->get_nt_headers();
        uint32_t image_base = raw_nt->optional_header.image_base;
        
        // Retain the previously disassembled instruction for future use.
        //
        std::optional<instruction> previous_instruction = {};

        win::nt_headers_t<false>* nt = target_module_view->local_module.get_image()->get_nt_headers();

        uc_engine* uc;
        uc_err err;

        std::vector<std::unique_ptr<instruction>> instructions;

        // While iterative disassembly is successful.
        //
        
        int copied_ins_num = 0;
        
        int map_result;
        err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
        if (err != UC_ERR_OK) {
            printf("Failed on uc_open() with error returned: %u\n", err);
        }
        
        printf("image_base is %x\n", image_base);
        map_result = uc_mem_map(uc, 0, 16 * 1024 * 1024, UC_PROT_ALL);

        int sec_idx;
        for (sec_idx = 0; sec_idx < nt->file_header.num_sections; sec_idx++)
        {
            byte* ea = local_module_bytes + nt->get_section(sec_idx)->virtual_address;
            printf("ea value test : %x %x", *(ea + 0x883), *(ea + 0x884));
            printf("ea : %x write memory from %x to %x\n", ea, nt->get_section(sec_idx)->virtual_address, nt->get_section(sec_idx)->virtual_address + nt->get_section(sec_idx)->Misc.virtual_size);
            if (uc_mem_write(uc, image_base + nt->get_section(sec_idx)->virtual_address, ea, nt->get_section(sec_idx)->Misc.virtual_size)) {
                printf("Failed to write emulation code to memory, quit!\n");
            } else{
                printf("success\n");
            }
        }
        uint32_t esp_addr = image_base + nt->get_section(sec_idx - 1)->virtual_address + nt->get_section(sec_idx - 1)->Misc.virtual_size + 0x10000;
        uint32_t return_address = 0x10000;
        
        printf("esp addre is %x\n", esp_addr);
        byte zero_bytes[0x20000] = {0};
        if (uc_mem_write(uc, esp_addr, zero_bytes, sizeof(zero_bytes))) { // stack value initialization
            printf("Failed to write emulation code to memory, quit!\n");
        }
        esp_addr += 0x10000;
        
        if (uc_reg_write(uc, X86_REG_ESP, &esp_addr)) {
            printf("Failed to write emulation code1 to memory, quit!\n");
        }
        
        printf("Start Memory Search To Find APIs\n");
        int test_cnt = 0;
        while ( true )
        {
            // Check if we're within bounds.
            //
            if (offset >= start_offset + code_size) {
                printf("offset is over\n");
                break;
            }
            
            // In case disassembly failed (due to invalid instructions), try to continue by incrementing offset.
            //
            if ( !cs_disasm_iter( disassembler::get().get_handle(), ( const uint8_t** )&code_start, &size, &offset, disassembler::get().get_insn() ) )
            {
                offset++;
                code_start++;

                continue;
            }
            instruction ins = { disassembler::get().get_insn() };
            // In order to scan mutated code without failing, we are following 1 and 2 byte absolute jumps.
            //
            
            if ( ins.ins.id == X86_INS_JMP )
            {
                auto section = target_module_view->local_module.get_image()->rva_to_section(ins.operand(0).imm);
                if (section->name != NULL) {

                    jmp_call.push_back(ins.operand(0).imm);

                }
                uint32_t jump_offset = ins.operand( 0 ).imm - ( ins.ins.address + ins.ins.size );
                
                if ( (jump_offset == 1 || jump_offset == 2)
                    && ins.operand_type(0) == X86_OP_IMM)
                {
                    offset += jump_offset;
                    code_start += jump_offset;

                    previous_instruction = ins;

                    continue;
                }
            }
            else if (ins.ins.id == X86_INS_PUSH && ins.operand_type(0) == X86_OP_IMM) {
                //printf("ssss %x : %s %s : %x\n", ins.ins.address, ins.ins.mnemonic, ins.ins.op_str, ins.operand(0).imm); // should solve duplication problem easily
                auto section = target_module_view->local_module.get_image()->rva_to_section(ins.operand(0).imm - image_base); // push opcodes include image bases
                if (section->name != NULL) {                    
                    jmp_call.push_back(ins.operand(0).imm - image_base);
                }
            } else if (ins.ins.id == X86_INS_MOV) {
                if (ins.operand(1).type == X86_OP_MEM) {
                    if (ins.operand(1).mem.base == 0) { // no reg
                        /*
                        printf("address : %x\n", ins.ins.address);
                        printf("local module size : %x\n", code_size);
                        printf("reg idx : %x\n", ins.operand(1).mem.base);

                        */
                        uint64_t mov_target_offset = ins.operand(1).mem.disp - image_base;

                        //printf("offset is : %x\n ", mov_target_offset);
                        if (mov_target_offset > code_size) {
                            continue;
                        }
                        uint8_t* mov_target = local_module_bytes + mov_target_offset;
                        //printf("it reference : %x\n ", *(uint32_t*)mov_target);
                        auto referenced_value = base_from_ea(*(uint32_t*)mov_target);
                        if (referenced_value.has_value() && referenced_value.value() != image_base) {
                            //printf("target reg is %x\n", ins.operand(0).reg);
                            import_stub_analysis api_info;

                            api_info.stack_adjustment = 0;
                            api_info.padding = 0;
                            api_info.is_jmp = 0;
                            api_info.mov_reg = ins.operand(0).reg;
                            api_info.mov_thunk = *(uint32_t*)mov_target;
                            
                            uintptr_t target_ea = *(uint32_t*)mov_target;

                            //printf("target ea is %x\n", target_ea);

                            const resolved_import* referenced_import = &resolved_imports.insert({ target_ea, {target_ea, target_ea } }).first->second;
                            // Record the call to the import.
                            printf("Target mov API is successfully found\n");
                            //printf("its result is stack_adjustment : %d and padded %d and is_jmp %d and thunk is %x\n", iat_struct_info.stack_adjustment, iat_struct_info.padded, iat_struct_info.is_jmp, iat_struct_info.thunk_rva);
                            import_calls.push_back({ ins.ins.address, referenced_import, api_info.mov_reg, api_info.mov_thunk, api_info.stack_adjustment,
                                api_info.padding, api_info.is_jmp, previous_instruction });
                        }
                    }
                   
                }
            }
            // If the instruction is a relative ( E8 ) call.
            //
            uint64_t call_target_offset = ins.operand(0).imm; // if imm = 0 it is mem
            bool is_mem_address = false;
            if ((ins.ins.id == X86_INS_CALL || ins.ins.id == X86_INS_JMP) && call_target_offset == 0) {//base + index*scale + disp                
                call_target_offset = ins.operand(0).mem.index * ins.operand(0).mem.scale + ins.operand(0).mem.disp - image_base;
                is_mem_address = true;
            }
            auto section = target_module_view->local_module.get_image()->rva_to_section(call_target_offset);
            if (section->name != NULL && ins.ins.id == X86_INS_CALL && (check_section_range(call_target_offset, rva, code_size))) {
                call_visited.insert({ ins.ins.address, true });
                printf("\n\n*****target ins address is %x\n\n", ins.ins.address);
             
                uint8_t* call_target = local_module_bytes + call_target_offset;
                //printf("call target?????? : %x\n", *(uint32_t*)call_target);
                // Ensure that the call destination is valid memory in the first place.
                //

                if (!IsBadReadPtr(call_target, 1))
                {
                    if (is_mem_address) {
                        if (check_section_range(*(uint32_t*)call_target - image_base, rva, code_size)) {
                            printf("target offset is %x \n", call_target_offset);

                            uint64_t next_address_offset = ins.ins.address + ins.ins.size;
                            printf("next_address_offset is %x\n", next_address_offset);
                            //uint64_t next_address_offset, uint64_t  esp_addr, ins.ins.address
                            esp_addr = image_base + nt->get_section(sec_idx - 1)->virtual_address + nt->get_section(sec_idx - 1)->Misc.virtual_size + 0x10000; // stack initialization
                            printf("befre call size : %x\n", code_size);
                            import_stub_analysis api_info = get_api_info(uc, image_base + ins.ins.address, image_base + next_address_offset, esp_addr, image_base + start_offset,
                                code_size, local_module_bytes);

                            api_info.stack_adjustment = 0;
                            api_info.padding = 0;
                            api_info.is_jmp = 0;
                            api_info.mov_reg = 0;
                            api_info.mov_thunk = 0;
                            printf("its result is stack_adjustment : %d and padded %d and is_jmp %d and thunk is %x and mov_reg %x and mov_thunk %x\n",
                                api_info.stack_adjustment, api_info.padding, api_info.is_jmp, api_info.thunk_rva, api_info.mov_reg, api_info.mov_thunk);

                            uintptr_t target_ea = api_addr;

                            printf("target ea is %x\n", target_ea);

                            const resolved_import* referenced_import = &resolved_imports.insert({ target_ea, {target_ea, target_ea } }).first->second;
                            // Record the call to the import.
                            printf("Target API is successfully found\n");
                            //printf("its result is stack_adjustment : %d and padded %d and is_jmp %d and thunk is %x\n", iat_struct_info.stack_adjustment, iat_struct_info.padded, iat_struct_info.is_jmp, iat_struct_info.thunk_rva);
                            import_calls.push_back({ ins.ins.address, referenced_import, api_info.mov_reg, api_info.mov_thunk, api_info.stack_adjustment,
                                api_info.padding, api_info.is_jmp, previous_instruction });
                        }
                    }
                    else {
                        // Disassemble at the call target.
                        // Max 25 instructions, in order to filter out invalid calls.
                        //
                        printf("target offset is %x \n", call_target_offset);

                        uint64_t next_address_offset = ins.ins.address + ins.ins.size;
                        printf("next_address_offset is %x\n", next_address_offset);
                        //uint64_t next_address_offset, uint64_t  esp_addr, ins.ins.address
                        esp_addr = image_base + nt->get_section(sec_idx - 1)->virtual_address + nt->get_section(sec_idx - 1)->Misc.virtual_size + 0x10000; // stack initialization
                        printf("befre call size : %x\n", code_size);
                        import_stub_analysis api_info = get_api_info(uc, image_base + ins.ins.address, image_base + next_address_offset, esp_addr, image_base + start_offset,
                            code_size, local_module_bytes);

                        printf("its result is stack_adjustment : %d and padded %d and is_jmp %d and thunk is %x and mov_reg %x and mov_thunk %x\n",
                            api_info.stack_adjustment, api_info.padding, api_info.is_jmp, api_info.thunk_rva, api_info.mov_reg, api_info.mov_thunk);

                        uintptr_t target_ea = api_addr;

                        printf("target ea is %x\n", target_ea);

                        const resolved_import* referenced_import = &resolved_imports.insert({ target_ea, {target_ea, target_ea } }).first->second;
                        // Record the call to the import.
                        printf("Target API is successfully found\n");
                        //printf("its result is stack_adjustment : %d and padded %d and is_jmp %d and thunk is %x\n", iat_struct_info.stack_adjustment, iat_struct_info.padded, iat_struct_info.is_jmp, iat_struct_info.thunk_rva);
                        import_calls.push_back({ ins.ins.address, referenced_import, api_info.mov_reg, api_info.mov_thunk, api_info.stack_adjustment,
                            api_info.padding, api_info.is_jmp, previous_instruction });

                        // If the call is a jump, and has no backwards (push) padding, it must be padded after the stub.
                        // Because jumps don't return, this information won't be provided to us by the analysis, so we have
                        // to skip the next byte to prevent potentially invalid disassembly.
                    }
                }
            }
            else if (section->name != NULL && ins.ins.id == X86_INS_JMP && (check_section_range(call_target_offset, rva, code_size))) { // themida jmp case
                call_visited.insert({ ins.ins.address, true });
                printf("\n\n*****target ins address is %x\n\n", ins.ins.address);
             
                uint8_t* call_target = local_module_bytes + call_target_offset;
                //printf("call target?????? : %x\n", *(uint32_t*)call_target);
                // Ensure that the call destination is valid memory in the first place.
                //

                if (!IsBadReadPtr(call_target, 1))
                {
                    if (is_mem_address) {
                        if (check_section_range(*(uint32_t*)call_target - image_base, rva, code_size)) {
                            printf("target offset is %x \n", call_target_offset);

                            uint64_t next_address_offset = ins.ins.address + ins.ins.size;
                            printf("next_address_offset is %x\n", next_address_offset);
                            //uint64_t next_address_offset, uint64_t  esp_addr, ins.ins.address
                            esp_addr = image_base + nt->get_section(sec_idx - 1)->virtual_address + nt->get_section(sec_idx - 1)->Misc.virtual_size + 0x10000; // stack initialization
                            printf("befre call size : %x\n", code_size);
                            import_stub_analysis api_info = get_api_info(uc, image_base + ins.ins.address, image_base + next_address_offset, esp_addr, image_base + start_offset,
                                code_size, local_module_bytes);

                            api_info.stack_adjustment = 0;
                            api_info.padding = 0;
                            api_info.is_jmp = 1;
                            api_info.mov_reg = 0;
                            api_info.mov_thunk = 0;
                            printf("its result is stack_adjustment : %d and padded %d and is_jmp %d and thunk is %x and mov_reg %x and mov_thunk %x\n",
                                api_info.stack_adjustment, api_info.padding, api_info.is_jmp, api_info.thunk_rva, api_info.mov_reg, api_info.mov_thunk);

                            uintptr_t target_ea = api_addr;

                            printf("target ea is %x\n", target_ea);

                            const resolved_import* referenced_import = &resolved_imports.insert({ target_ea, {target_ea, target_ea } }).first->second;
                            // Record the call to the import.
                            printf("Target API is successfully found\n");
                            //printf("its result is stack_adjustment : %d and padded %d and is_jmp %d and thunk is %x\n", iat_struct_info.stack_adjustment, iat_struct_info.padded, iat_struct_info.is_jmp, iat_struct_info.thunk_rva);
                            import_calls.push_back({ ins.ins.address, referenced_import, api_info.mov_reg, api_info.mov_thunk, api_info.stack_adjustment,
                                api_info.padding, api_info.is_jmp, previous_instruction });
                        }
                    }
                }
            } 
            else if (section->name != NULL && is_mem_address && ins.ins.id == X86_INS_CALL) { //pecompact case
                uint8_t* call_target = local_module_bytes + call_target_offset;
                uint32_t module_addr = *base_from_ea(*(uint32_t*)call_target);
                printf("\n\n*****target ins address is %x pecompact\n\n", ins.ins.address);
                if (module_addr != 0 && module_addr != image_base) {
                    import_stub_analysis api_info;

                    api_info.stack_adjustment = 0;
                    api_info.padding = 0;
                    api_info.is_jmp = 0;
                    api_info.mov_reg = 0;
                    api_info.mov_thunk = 0;
                    printf("its result is stack_adjustment : %d and padded %d and is_jmp %d and thunk is %x and mov_reg %x and mov_thunk %x\n",
                        api_info.stack_adjustment, api_info.padding, api_info.is_jmp, api_info.thunk_rva, api_info.mov_reg, api_info.mov_thunk);

                    remote_ea_t target_ea = *(uint32_t*)call_target;

                    printf("target ea is %x\n", target_ea);

                    const resolved_import* referenced_import = &resolved_imports.insert({ target_ea, {target_ea, target_ea } }).first->second;
                    // Record the call to the import.
                    printf("Target API is successfully found\n");
                    //printf("its result is stack_adjustment : %d and padded %d and is_jmp %d and thunk is %x\n", iat_struct_info.stack_adjustment, iat_struct_info.padded, iat_struct_info.is_jmp, iat_struct_info.thunk_rva);
                    import_calls.push_back({ ins.ins.address, referenced_import, api_info.mov_reg, api_info.mov_thunk, api_info.stack_adjustment,
                        api_info.padding, api_info.is_jmp, previous_instruction });
                }
            }
            else if (section->name != NULL && is_mem_address && ins.ins.id == X86_INS_JMP) { //pecompact case
            uint8_t* call_target = local_module_bytes + call_target_offset;
            uint32_t module_addr = *base_from_ea(*(uint32_t*)call_target);
            printf("\n\n*****target ins address is %x pecompact\n\n", ins.ins.address);
            if (module_addr != 0 && module_addr != image_base) {
                import_stub_analysis api_info;

                api_info.stack_adjustment = 0;
                api_info.padding = 0;
                api_info.is_jmp = 1;
                api_info.mov_reg = 0;
                api_info.mov_thunk = 0;
                printf("its result is stack_adjustment : %d and padded %d and is_jmp %d and thunk is %x and mov_reg %x and mov_thunk %x\n",
                    api_info.stack_adjustment, api_info.padding, api_info.is_jmp, api_info.thunk_rva, api_info.mov_reg, api_info.mov_thunk);

                remote_ea_t target_ea = *(uint32_t*)call_target;

                printf("target ea is %x\n", target_ea);

                const resolved_import* referenced_import = &resolved_imports.insert({ target_ea, {target_ea, target_ea } }).first->second;
                // Record the call to the import.
                printf("Target API is successfully found\n");
                //printf("its result is stack_adjustment : %d and padded %d and is_jmp %d and thunk is %x\n", iat_struct_info.stack_adjustment, iat_struct_info.padded, iat_struct_info.is_jmp, iat_struct_info.thunk_rva);
                import_calls.push_back({ ins.ins.address, referenced_import, api_info.mov_reg, api_info.mov_thunk, api_info.stack_adjustment,
                    api_info.padding, api_info.is_jmp, previous_instruction });
            }
            }
            
            previous_instruction = ins;
        }        
        
        int i = 0;
        
        printf("start");
        printf("JMP size is %d\n", jmp_call.size());

        //return true;
        while (i < jmp_call.size()) {     
            uint8_t* ea = jmp_call[i] + local_module_bytes;
            size_t size = 0xFFFFFFFFFFFFFFFFull;
            if (!cs_disasm_iter(disassembler::get().get_handle(), (const uint8_t**)&ea, &size, &jmp_call[i], disassembler::get().get_insn()))
            {
                i++;
                continue;
            }
            instruction ins = { disassembler::get().get_insn() };
            //printf("jmp target is %x : %s %s\n", ins.ins.address, ins.ins.mnemonic, ins.ins.op_str);
            //auto section = target_module_view->local_module.get_image()->rva_to_section(ins.ins.address);
            //printf("jump saved : %x\n", ins.ins.address);
            if (ins.ins.id == X86_INS_CALL && call_visited.find(ins.ins.address) == call_visited.end()) {
                uint64_t call_target_offset = ins.operand(0).imm;
                printf("\n\n*****target ins address is %x\n", call_target_offset, ins.ins.address);
                bool is_mem_address = false;
                if (ins.ins.id == X86_INS_CALL && call_target_offset == 0) {//base + index*scale + disp           
                    //printf("memory target jmp : %x\n ", ins.ins.address);
                    call_target_offset = ins.operand(0).mem.index * ins.operand(0).mem.scale + ins.operand(0).mem.disp - image_base;
                    is_mem_address = true;
                }
                auto section = target_module_view->local_module.get_image()->rva_to_section(call_target_offset);

                if (section->name != NULL && ins.ins.id == X86_INS_CALL && (check_section_range(call_target_offset, rva, code_size))) {

                    uint64_t next_address_offset = ins.ins.address + ins.ins.size;
                    //printf("next_address_offset is %x\n", next_address_offset);

                    esp_addr = image_base + nt->get_section(sec_idx - 1)->virtual_address + nt->get_section(sec_idx - 1)->Misc.virtual_size + 0x10000; // stack initialization
                    printf("befre call size : %x\n", code_size);
                    import_stub_analysis api_info = get_api_info(uc, image_base + ins.ins.address, image_base + next_address_offset, esp_addr, image_base +  start_offset,
                        code_size, local_module_bytes);
                    uintptr_t target_ea = api_addr;

                    // If it doesn't already exist within the map, insert the import.
                    // 
                    printf("target ea is %x\n", target_ea);

                    if (is_mem_address) {
                        api_info.stack_adjustment = 0;
                        api_info.padding = 0;
                        api_info.is_jmp = 0;
                        api_info.mov_reg = 0;
                        api_info.mov_thunk = 0;
                    }
                    const resolved_import* referenced_import = &resolved_imports.insert({ target_ea, { target_ea, target_ea } }).first->second;
                    // Record the call to the import.
                    printf("its result is stack_adjustment : %d and padded %d and is_jmp %d and thunk is %x and mov_reg %x and mov_thunk %x\n",
                        api_info.stack_adjustment, api_info.padding, api_info.is_jmp, api_info.thunk_rva, api_info.mov_reg, api_info.mov_thunk);
                    import_calls.push_back({ ins.ins.address, referenced_import, api_info.mov_reg, api_info.mov_thunk, api_info.stack_adjustment, api_info.padding, api_info.is_jmp, previous_instruction });
                }
            }
            else if (ins.ins.id == X86_INS_PUSH && ins.ins.size == 1) { // stack alignment 상황 고려 다음 address parse
                uint8_t* push_next_ea = ins.ins.address + local_module_bytes + 1;
                uint64_t push_next_address = ins.ins.address + 1;
                if (!cs_disasm_iter(disassembler::get().get_handle(), (const uint8_t**)&push_next_ea, &size, &push_next_address, disassembler::get().get_insn()))
                {
                    i++;
                    continue;
                }
                instruction push_next_ins = { disassembler::get().get_insn() };
                if (push_next_ins.ins.id == X86_INS_CALL && push_next_ins.ins.bytes[0] == 0xE8 && call_visited.find(push_next_ins.ins.address) == call_visited.end()) {
                    uint64_t push_next_call_target_offset = push_next_ins.operand(0).imm;
                    bool is_mem_address = false;
                    if (ins.ins.id == X86_INS_CALL && push_next_call_target_offset == 0) {//base + index*scale + disp                
                        push_next_call_target_offset = ins.operand(0).mem.index * ins.operand(0).mem.scale + ins.operand(0).mem.disp - image_base;
                        is_mem_address = true;
                    }
                    auto section = target_module_view->local_module.get_image()->rva_to_section(push_next_call_target_offset);

                    if (section->name != NULL && push_next_ins.ins.id == X86_INS_CALL && (check_section_range(push_next_call_target_offset, rva, code_size))
                         && push_next_ins.ins.bytes[0] == 0xE8) {

                        printf("\n\n*****target ins address is %x\n", push_next_call_target_offset);

                        uint64_t push_next_address_offset = push_next_ins.ins.address + push_next_ins.ins.size;
                        //printf("next_address_offset is %x\n", push_next_address_offset);

                        esp_addr = image_base + nt->get_section(sec_idx - 1)->virtual_address + nt->get_section(sec_idx - 1)->Misc.virtual_size + 0x10000; // stack initialization
                        printf("befre call size : %x\n", code_size);
                        import_stub_analysis api_info = get_api_info(uc, image_base + push_next_ins.ins.address, image_base + push_next_address_offset, esp_addr, 
                            image_base + start_offset, code_size, local_module_bytes);
                        uintptr_t push_next_target_ea = api_addr;

                        // If it doesn't already exist within the map, insert the import.
                        // 
                        printf("target ea is %x\n", push_next_target_ea);
                        if (is_mem_address) {
                            api_info.stack_adjustment = 0;
                            api_info.padding = 0;
                            api_info.is_jmp = 0;
                            api_info.mov_reg = 0;
                            api_info.mov_thunk = 0;
                        }
                        const resolved_import* referenced_import = &resolved_imports.insert({ push_next_target_ea, { push_next_target_ea, push_next_target_ea } }).first->second;
                        // Record the call to the import.
                        printf("its result is stack_adjustment : %d and padded %d and is_jmp %d and thunk is %x and mov_reg %x and mov_thunk %x\n",
                            api_info.stack_adjustment, api_info.padding, api_info.is_jmp, api_info.thunk_rva, api_info.mov_reg, api_info.mov_thunk);
                        import_calls.push_back({ push_next_ins.ins.address, referenced_import, api_info.mov_reg, api_info.mov_thunk, api_info.stack_adjustment, api_info.padding, api_info.is_jmp, ins });
                    }
                }
            }
            previous_instruction = ins;
            
            i++;
        }

        return true;
    }

    // Scans all executable sections of the image for any import calls and imports.
    //
    bool GUARD::scan_for_imports( std::map<uint64_t, resolved_import>& resolved_imports, std::vector<import_call>& import_calls, uint32_t ep_rva, uint32_t flags)
    {
        using namespace win;

        bool failed = false;

        nt_headers_t<false>* nt = target_module_view->local_module.get_image()->get_nt_headers();

        // Enumerate image sections.
        //
        for ( int i = 0; i < nt->file_header.num_sections; i++ )
        {
            section_header_t* section = nt->get_section( i );
            if (section->characteristics.mem_read && section->characteristics.mem_execute) {
                if (ep_rva >= section->virtual_address && ep_rva <= section->virtual_address + section->Misc.virtual_size) {
                    printf("start scan start address :%x and size is %x\n", section->virtual_address, section->Misc.virtual_size);
                    failed |= !scan_for_imports(section->virtual_address, section->Misc.virtual_size, resolved_imports, import_calls, flags);
                }
            }
        }

        return !failed;
    }

    bool GUARD::scan_for_rdata_imports(std::map<uint64_t, resolved_import>& resolved_imports, std::vector<import_call>& import_calls, uint32_t ep_rva, std::map<uint32_t, uint32_t>& rdata_export_rva, uint32_t flags)
    {
        using namespace win;

        bool failed = false;

        nt_headers_t<false>* nt = target_module_view->local_module.get_image()->get_nt_headers();

        // Enumerate image sections.
        //
        section_header_t*  first_section = nt->get_section(0); // start        
        section_header_t* last_section = nt->get_section(nt->file_header.num_sections - 1);
        /*PIMAGE_IMPORT_DESCRIPTOR pImportDesc =
            (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)target_module_view->local_module.raw_bytes.data() + 
                nt->optional_header.data_directories.iat_directory.rva);*/
        printf("%x is import\n", nt->optional_header.data_directories.iat_directory.rva);
            
        for (int i = 0; i < nt->file_header.num_sections; i++)
        {
            section_header_t* section = nt->get_section(i);
            /*
            if (section->characteristics.mem_execute)
                continue;
            */
            
            if (!section->characteristics.mem_write)
                continue;
            if (nt->optional_header.data_directories.iat_directory.rva >= section->virtual_address &&
                nt->optional_header.data_directories.iat_directory.rva <= section->virtual_address + section->Misc.virtual_size)
                continue;

            printf("rdata scan start :%x and size is %x\n", section->virtual_address, section->Misc.virtual_size);
            
            uint8_t* local_module_bytes = (uint8_t*)target_module_view->local_module.data();
            size_t size = section->Misc.virtual_size;
            uint8_t* code_start = local_module_bytes + section->virtual_address;
            auto raw_nt = target_module_view->local_module.get_image()->get_nt_headers();
            uint32_t image_base = raw_nt->optional_header.image_base;
            printf("range check : %x to %x \n", first_section->virtual_address, (last_section->virtual_address + last_section->Misc.virtual_size));
            for (int offset = 0; offset < size; offset +=4) {                    
                auto rdata_referenced_value = *(uint32_t*)(code_start + offset);
                //printf("debug : %x & %x\n", section->virtual_address + offset, rdata_referenced_value);
                if (rdata_referenced_value < 0x10000000)
                    continue;
                auto rdata_referenced = base_from_ea(rdata_referenced_value);
                if (rdata_referenced.has_value() && rdata_referenced.value() != image_base) {
                    printf("Target mov API is successfully found : %x (%x)\n", rdata_referenced_value, section->virtual_address + offset + image_base);
                    const resolved_import* referenced_import = &resolved_imports.insert({ rdata_referenced_value, {rdata_referenced_value, rdata_referenced_value } }).first->second;
                    rdata_export_rva.insert({ (uint32_t)(rdata_referenced_value - rdata_referenced.value()), section->virtual_address + offset });
                    import_calls.push_back({ (uint32_t)(section->virtual_address + offset), referenced_import, 0, 0x1000, 0,
                            0, 0, std::optional<instruction>{} });
                }
                
            }
                

                //failed |= !scan_for_imports(section->virtual_address, section->Misc.virtual_size, resolved_imports, import_calls, flags);
            
            
        }

        return !failed;
    }

    // Attempts to generate a stub in a code cave which jmps to the given thunk.
    // Returns the stub rva.
    //
    std::optional<uint32_t> GUARD::generate_stub( uint32_t rva, remote_ea_t thunk )
    {
        // Save all stubs so we don't re-create them on each call.
        //
        static std::map<remote_ea_t, uint32_t> stubs;

        // If the stub was already created, just return its rva.
        //
        auto it = stubs.find( thunk );
        if ( it != stubs.end() )
            return it->second;

        // We need 6 bytes for a thunk call.
        //
        const uint32_t req_len = 6;

        // Increase the section size.
        //
        auto section = target_module_view->local_module.get_image()->rva_to_section( rva );
        uint32_t stub_rva = section->virtual_address + section->Misc.virtual_size;
        section->Misc.virtual_size += req_len;
        //printf("stub rva is %x\n", stub_rva);
        // TODO: Handle if there is no more padding left in the section to overwrite.....
        //
        // ...

        // If no code-cave found, return empty {}.
        //
        if ( !stub_rva )
            return {};

        // Assemble a jump.
        //
        std::vector<uint8_t> jump = vtil::amd64::assemble( vtil::format::str( "jmp [0x%p]", thunk ), target_module_view->module_base + stub_rva );

        // Sanity-check the size.
        //
        if ( jump.size() > 6 )
            return {};

        // Copy the assembled jump to the code-cave.
        //
        memcpy( target_module_view->local_module.data() + stub_rva, jump.data(), jump.size() );

        // Add the generated stub to the list for future use.
        //
        stubs.insert( { thunk, stub_rva } );

        return stub_rva;
    }


    // Attempts to convert the provided call to the VMP import stub to a direct import thunk call to the specified remote thunk ea.
    //
    bool GUARD::convert_local_call( const import_call& call, remote_ea_t thunk, remote_ea_t reg_val )
    {
        uint8_t* local_module_bytes = ( uint8_t* )target_module_view->local_module.data();

        uint32_t fill_rva = 0;
        size_t fill_size = 0;
        printf("execute memcpy for test : %x, %x, %x\n", thunk, reg_val, sizeof(thunk));
        if (reg_val == 0x1000) {
            printf("execute memcpy for rdata : %x, %x, %x\n", thunk, reg_val, sizeof(thunk));
            fill_rva = bitoffset;
            auto thunk_relative_addr = thunk - target_module_view->module_base;
            memset(local_module_bytes + call.call_rva, 0x0, sizeof(uint32_t));
            memcpy(local_module_bytes + call.call_rva, reinterpret_cast<char*>(&thunk_relative_addr), sizeof(uint32_t));
            return true;
        }
        else if (reg_val == 0x2000) {
            printf("execute memcpy for rdata tri : %x, %x, %x\n", thunk, reg_val, sizeof(thunk));
            fill_rva = bitoffset;
            auto thunk_relative_addr = thunk; // do not sub
            memset(local_module_bytes + call.call_rva, 0x0, sizeof(uint32_t));
            memcpy(local_module_bytes + call.call_rva, reinterpret_cast<char*>(&thunk_relative_addr), sizeof(uint32_t));
            return true;
        }
        // If the import stub call inline adjusts the stack, we must verify that the instruction
        // before the stub call is indeed a PUSH.
        //
        // In VMP3, the stack is only ever adjusted by a single 64-bit PUSH.
        //
        if ( call.stack_adjustment == bitoffset )
        {
            if ( call.prev_instruction && call.prev_instruction->ins.id == X86_INS_PUSH && call.prev_instruction->operand_type( 0 ) == X86_OP_REG && call.prev_instruction->ins.size == 1)
            {
                // It is indeed a valid VMP-injected push.
                // We can NOP it later, and mark it as the starting point for our fill address.
                //
                fill_rva = call.prev_instruction->ins.address;
                fill_size += call.prev_instruction->ins.size;
            } 
            else if (call.prev_instruction->ins.size >= 2) { // vmp3.6 >
                //printf("fill rva is %x\n", call.prev_instruction->ins.address + 1);
                fill_rva = call.prev_instruction->ins.address + call.prev_instruction->ins.size - 1;
                fill_size += 1;//call.prev_instruction->ins.size;
            }
            else
            {                
                vtil::logger::log<vtil::logger::CON_RED>( "!! Stack adjustment failed1 for call @ RVA 0x%llx for thunk @ 0x%llx\r\n", call.call_rva, thunk );
                return false;
            }
        } 
        else if (call.stack_adjustment == -4)
        {
            if (call.prev_instruction && call.prev_instruction->ins.id == X86_INS_POP && call.prev_instruction->operand_type(0) == X86_OP_REG && call.prev_instruction->ins.size == 1)
            {
                // It is indeed a valid VMP-injected push.
                // We can NOP it later, and mark it as the starting point for our fill address.
                //
                fill_rva = call.prev_instruction->ins.address;
                fill_size += call.prev_instruction->ins.size;
            }
            else
            {
                vtil::logger::log<vtil::logger::CON_RED>("!! Stack adjustment failed2 for call @ RVA 0x%llx for thunk @ 0x%llx\r\n", call.call_rva, thunk);
                return false;
            }
        }
        else if (call.stack_adjustment != 0) {
            vtil::logger::log<vtil::logger::CON_RED>("!! Stack adjustment failed3 for call @ RVA 0x%llx for thunk @ 0x%llx\r\n", call.call_rva, thunk);
            return false;
        }

        //printf("call prev ins size is %d and fill_rva is %x and call.call_rva is %x \n", call.prev_instruction->ins.size, fill_rva, call.call_rva);
        uint8_t* call_ea = local_module_bytes + call.call_rva;

        // Disassemble instruction at the call rva.
        //
        //printf("call ea is %x and call rVa is %x\n");
        auto instructions = vtil::amd64::disasm( call_ea, call.call_rva );

        // Ensure disassembly succeeded.
        //
        if ( instructions.empty() )
        {
            vtil::logger::log<vtil::logger::CON_RED>( "!! Disassembly failed for call @ RVA 0x%llx for thunk @ 0x%llx\r\n", call.call_rva, thunk );
            return false;
        }

        // If it's a jump, we can increase fill size by 1, if we haven't already filled using a PUSH.
        // This is because thunk jumps must be 5 bytes, so VMP can insert a junk pad byte after its 4 byte stub.
        //
        if ( fill_size == 0 && call.is_jmp )
            fill_size++;

        // If there's no fill rva selected, set it as the beginning of the disassembled instructions.
        //
        if ( fill_rva == 0 )
            fill_rva = instructions[ 0 ].address;
        
        // Account for these instructions for the fill size.
        //
        for ( auto instruction : instructions )
            fill_size += instruction.bytes.size();

        // If padded, increase fill size by 1.
        //
        fill_size += call.padded ? 1 : 0;
        fill_size = 6;
        // Now we must inject a call to the newly-fixed thunk.
        //
        // We assemble this call as if we're in the target process address-space.
        // This is because we want to give the assembler the freedom to potentially make a non-relative call if it desires.
        //
        printf("fill_rva is %x and target_module_view->module_base is %x\n", target_module_view->module_base, fill_rva);
        printf("converted_data thunk is %x and va is %x\n", thunk, target_module_view->module_base + fill_rva);


        //std::vector<uint8_t> converted_call = vtil::amd64::assemble( vtil::format::str( "%s [0x%p]", call.is_jmp ? "jmp" : "call", thunk ), target_module_view->module_base + fill_rva );
        std::vector<uint8_t> converted_call;
        ks_engine* ks;
        ks_err err;
        size_t count;
        unsigned char* encode;
        size_t size;
        char buffer[200];
        err = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);
        if (err != KS_ERR_OK) {
            printf("ERROR: failed on ks_open(), quit\n");
            return -1;
        }
        if (call.mov_reg_idx != 0) {
            char syscall_abi[][242] = {
                "INVALID = 0",
    "AH", "AL", "AX", "BH", "BL",
    "BP", "BPL", "BX", "CH", "CL",
    "CS", "CX", "DH", "DI", "DIL",
    "DL", "DS", "DX", "EAX", "EBP",
    "EBX", "ECX", "EDI", "EDX", "EFLAGS",
    "EIP", "EIZ", "ES", "ESI", "ESP",
    "FPSW", "FS", "GS", "IP", "RAX",
    "RBP", "RBX", "RCX", "RDI", "RDX",
    "RIP", "RIZ", "RSI", "RSP", "SI",
    "SIL", "SP", "SPL", "SS", "CR0",
    "CR1", "CR2", "CR3", "CR4", "CR5",
    "CR6", "CR7", "CR8", "CR9", "CR10",
    "CR11", "CR12", "CR13", "CR14", "CR15",
    "DR0", "DR1", "DR2", "DR3", "DR4",
    "DR5", "DR6", "DR7", "DR8", "DR9",
    "DR10", "DR11", "DR12", "DR13", "DR14",
    "DR15", "FP0", "FP1", "FP2", "FP3",
    "FP4", "FP5", "FP6", "FP7",
    "K0", "K1", "K2", "K3", "K4",
    "K5", "K6", "K7", "MM0", "MM1",
    "MM2", "MM3", "MM4", "MM5", "MM6",
    "MM7", "R8", "R9", "R10", "R11",
    "R12", "R13", "R14", "R15",
    "ST0", "ST1", "ST2", "ST3",
    "ST4", "ST5", "ST6", "ST7",
    "XMM0", "XMM1", "XMM2", "XMM3", "XMM4",
    "XMM5", "XMM6", "XMM7", "XMM8", "XMM9",
    "XMM10", "XMM11", "XMM12", "XMM13", "XMM14",
    "XMM15", "XMM16", "XMM17", "XMM18", "XMM19",
    "XMM20", "XMM21", "XMM22", "XMM23", "XMM24",
    "XMM25", "XMM26", "XMM27", "XMM28", "XMM29",
    "XMM30", "XMM31", "YMM0", "YMM1", "YMM2",
    "YMM3", "YMM4", "YMM5", "YMM6", "YMM7",
    "YMM8", "YMM9", "YMM10", "YMM11", "YMM12",
    "YMM13", "YMM14", "YMM15", "YMM16", "YMM17",
    "YMM18", "YMM19", "YMM20", "YMM21", "YMM22",
    "YMM23", "YMM24", "YMM25", "YMM26", "YMM27",
    "YMM28", "YMM29", "YMM30", "YMM31", "ZMM0",
    "ZMM1", "ZMM2", "ZMM3", "ZMM4", "ZMM5",
    "ZMM6", "ZMM7", "ZMM8", "ZMM9", "ZMM10",
    "ZMM11", "ZMM12", "ZMM13", "ZMM14", "ZMM15",
    "ZMM16", "ZMM17", "ZMM18", "ZMM19", "ZMM20",
    "ZMM21", "ZMM22", "ZMM23", "ZMM24", "ZMM25",
    "ZMM26", "ZMM27", "ZMM28", "ZMM29", "ZMM30",
    "ZMM31", "R8B", "R9B", "R10B", "R11B",
    "R12B", "R13B", "R14B", "R15B", "R8D",
    "R9D", "R10D", "R11D", "R12D", "R13D",
    "R14D", "R15D", "R8W", "R9W", "R10W",
    "R11W", "R12W", "R13W", "R14W", "R15W"
            };
            sprintf(buffer, "mov %s, [0x%p] ", syscall_abi[call.mov_reg_idx], reg_val);
            printf("reg_val? : %x\n", reg_val);
            printf("buffer : %s\n", buffer);

            if (reg_val == target_module_view->module_base)
                return false;
        }
        else {
            if (thunk == target_module_view->module_base) {
                vtil::logger::log<vtil::logger::CON_RED>("!! Stack adjustment failed4 for call @ RVA 0x%llx for thunk @ 0x%llx\r\n", call.call_rva, thunk);
                return false;
            }
            sprintf(buffer, "%s [0x%p]", call.is_jmp ? "jmp" : "call", thunk);
        }

        if (ks_asm(ks, buffer, 0, &encode, &size, &count) != KS_ERR_OK) {
            printf("ERROR: ks_asm() failed & count = %lu, error = %u\n",
                count, ks_errno(ks));
        }
        else {
            size_t i;

            printf("%s = ", buffer);
            for (i = 0; i < size; i++) {
                printf("%02x ", encode[i]);
            }
            printf("\n");
            printf("Compiled: %lu bytes, statements: %lu\n", size, count);
            fill_size = size;
        }

        // NOTE: free encode after usage to avoid leaking memory
        ks_free(encode);

        // close Keystone instance when done
        ks_close(ks);


        // Ensure assembly succeeded.
        //
        /*
        if ( converted_call.empty() )
        {
            vtil::logger::log<vtil::logger::CON_RED>( "!! Assembly failed for call @ RVA 0x%llx for thunk @ 0x%llx\r\n", call.call_rva, thunk );
            return false;
        }*/

        // Ensure we have enough bytes to fill.
        //
        /*
        if ( converted_call.size() > fill_size )
        {
            // If we don't have enough bytes, we can try to dispatch the call via a stub.
            // Try to generate this stub in a codecave.
            //
            if ( std::optional<uint32_t> stub_rva = generate_stub( fill_rva, thunk ) )
            {
                // Successful, we found a suitable code-cave and generated a stub.
                // Now replace the call with a dispatched call (or jmp) to the stub.
                //
                printf("%s dword ptr ds: 0x%p", call.is_jmp ? "jmp" : "call", thunk);
                converted_call = vtil::amd64::assemble( vtil::format::str( "%s dword ptr ds: [0x%p]", call.is_jmp ? "jmp" : "call", thunk ), target_module_view->module_base + thunk );
            }
        }*/

        // Ensure again we have enough bytes to fill.
        //
        /*
        if ( converted_call.size() > fill_size )
        {
            vtil::logger::log<vtil::logger::CON_RED>( "!! Insufficient bytes [have %d, need %d] for call @ RVA 0x%llx for thunk @ 0x%llx\r\n", fill_size, converted_call.size(), call.call_rva, thunk );
            return false;
        }*/

        // NOP the fill bytes and copy the converted call in.
        
        printf("convered call data is %x\n", converted_call.data());
        BYTE* bytepointer = converted_call.data();
        
        for (int i = 0; i < converted_call.size(); i++) {
            printf("%x ", bytepointer[i]);
        }
        printf("\n");
        memset( local_module_bytes + fill_rva, 0x90, fill_size );
        memcpy( local_module_bytes + fill_rva, encode, size);

        return true;
    }

    // Searches for a module where the provided remote ea is within the module's address space, then returns a module_view of that module.
    //
    std::optional<module_view> GUARD::view_from_base( remote_ea_t base ) const
    {
        // Find the module by base.
        //
        auto it = process_modules.find( base );
        // Return empty {} if not found.
        //

        if ( it == process_modules.end() )
            return {};
        // Construct module_view.
        //
        auto dll_path = process_dll_paths.at(it->second.first);
        return { { process_id, it->second.first, dll_path, base, it->second.second}};
    }

    // Retrieves the module base from the given remote ea.
    //
    std::optional<remote_ea_t> GUARD::base_from_ea( remote_ea_t ea ) const
    {
        // Enumerate process modules.
        //
        for ( auto& [base, info] : process_modules )
        {
            // If within bounds, return module base.
            //
            unsigned int size = (unsigned int)info.second;
            unsigned int new_ea = (unsigned int)ea;
            unsigned int new_base = (unsigned int)base;
            unsigned int upperbound = new_base + size;
            //printf("target ea is %x and current base is %x and info.second is %x and result is %x\n", (unsigned int)ea, (unsigned int)base, (unsigned int)info.second, (unsigned int)base + (unsigned int)info.second);
            //printf("#### boolean 1 : %d and boolean 2 : %d\n", ea >= base, ea < base + info.second);
            if (new_ea >= new_base && new_ea < new_base + size) {
                return base;
            }
        }

        // If none found, return empty {}.
        //
        return {};
    }

    // Creates a GUARD class from the given process id and target module name.
    // If module_name is empty "", the process module is used.
    // If the process cannot be opened for some reason or the module cannot be found, returns empty {}.
    //
    std::unique_ptr<GUARD> GUARD::from_pid( uint32_t process_id, const std::string& module_name )
    {
        std::unique_ptr<GUARD> result = {};

        HMODULE process_modules[ 1024 ] = {};

        // TODO: replace PROCESS_ALL_ACCESS with something more specific.
        //
        HANDLE process_handle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, process_id );
        if ( process_handle == NULL )
            return {};

        // Retrieves the module base address and size, in that order, in a pair.
        //
        auto get_module_info = [&]( HMODULE target_module ) -> std::pair<uintptr_t, size_t>
        {
            MODULEINFO info = {};
            if ( !GetModuleInformation( process_handle, target_module, &info, sizeof( info ) ) )
                return { 0, 0 };

            printf("module successfully loaded and address is %x and size of image is %x\n", info.lpBaseOfDll, info.SizeOfImage);
            return { ( uintptr_t )info.lpBaseOfDll, info.SizeOfImage };
        };

        // Do ... While( 0 ) "loop" for easy error wrapping.
        //
        do
        {
            // Try to get the process image file name.
            //
            char process_image_path[ MAX_PATH ] = {};
            DWORD process_image_path_size = sizeof( process_image_path );
            if ( !QueryFullProcessImageNameA( process_handle, 0, process_image_path, &process_image_path_size ) )
                break;

            const char* process_image_name = PathFindFileNameA( process_image_path );

            // Map of process modules, for later class construction.
            //
            std::map<remote_ea_t, std::pair<std::string, size_t>> process_modules_map;
            std::map<std::string, std::string> process_path_map;
            // Info of the target module.
            //
            std::string target_module_name;
            std::string target_path_name;
            std::pair<uintptr_t, size_t> target_module_info = {};
            bool target_module_found = false;

            // Enumerate through the process modules list.
            //
            DWORD process_modules_size;
            if ( EnumProcessModulesEx( process_handle, process_modules, sizeof( process_modules ), &process_modules_size, LIST_MODULES_ALL) )
            {
                // Loop through each module.
                //
                for ( int i = 0; i < ( process_modules_size / sizeof( HMODULE ) ); i++ )
                {
                    HMODULE curr_module = process_modules[ i ];

                    // Get the module base address and size.
                    //
                    
                    std::pair<uintptr_t, size_t> curr_module_info = get_module_info( curr_module );
                    // Get the module name.
                    //
                    char module_base_name[ 128 ] = {};
                    char module_path_name[MAX_PATH] = {};
                    if ( GetModuleBaseNameA( process_handle, curr_module, module_base_name, sizeof( module_base_name ) ) )
                    {
                        // Add the module to the map.
                        //
                        //IMAGE_DOS_HEADER* DOSH = (IMAGE_DOS_HEADER*)process_modules[i];
                        //PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);
                        //strcpy(module_base_name, path);
                        process_modules_map.insert( { curr_module_info.first, { module_base_name, curr_module_info.second } } );
                        
                        if (GetModuleFileNameExA(process_handle, process_modules[i], module_path_name, sizeof(module_path_name)) == 0)
                        {
                            int ret = GetLastError();
                            fprintf(stderr, "GetModuleFileName failed, error = %d\n", ret);
                            // Return or however you want to handle an error.
                        }
                        else {
                            printf("module path is %s\n", module_path_name);
                        }

                        process_path_map.insert({ module_base_name , std::string(module_path_name) });
                        //printf("&&&&&&&&&&&&&&&&&module name : %s and %s\n", module_base_name, module_path_name);
                        // If we're looking for the process module, compare module name to image base name.
                        // Otherwise, compare the module name to the provided target module name in the argument.
                        //
                        
                        if ( !target_module_found
                            && ( module_name.empty() && _stricmp( module_base_name, process_image_name ) == 0 )
                            || ( std::string( module_base_name ) == module_name ) )
                        {
                            target_module_info = curr_module_info;
                            target_module_name = module_base_name;
                            target_path_name = module_path_name;
                            target_module_found = true;
                        }
                    }
                }
            }

            // Verify that we actually found the module.
            //
            if ( !target_module_found )
                break;

            // Construct the object.
            //
            result = std::make_unique<GUARD>( process_id, process_modules_map, process_path_map, std::make_unique<module_view>( process_id, target_module_name, target_path_name, target_module_info.first, target_module_info.second ), std::string { process_image_path } );
            
        } while ( 0 );

        // Close handle and return the constructed object.
        //
        CloseHandle( process_handle );
        return result;
    }
}
