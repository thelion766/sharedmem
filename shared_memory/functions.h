#pragma once
#include "ia32.h"
#include "tools.h"
#ifndef FUNCTIONS_H
#define FUNCTIONS_H

namespace functions
{
    typedef handle_table_entry_t*(exp_lookup_handle_table_entry_t)(std::uint64_t*, long long);
    handle_table_entry_t* exp_lookup_handle_table_entry(std::uint64_t* handle_table, long long handle) {
        
        if (!handle_table)
            return nullptr;

        void* ntos_base = reinterpret_cast<void*>(tools::get_nt_base());
        if (!ntos_base)
            return nullptr;

        size_t ntos_size = tools::get_module_size(ntos_base);
        //signature for win 10 22h2
        void* function_pointer = tools::find_pattern(reinterpret_cast<unsigned char*>(ntos_base), ntos_size, skCrypt("? ? 48 83 E2 ? 48 3B D0 73 ? 4C 8B 41 ? 41 8B C0 83 E0 ? 83 F8 ? 75 ? 48 8B C2 48 C1 E8 ? 81 E2 ? ? ? ? 49 8B 44 C0"));
        if (!function_pointer)
            return nullptr;

        exp_lookup_handle_table_entry_t* function = reinterpret_cast<exp_lookup_handle_table_entry_t*>(function_pointer);
        return function(handle_table, handle);
    }
    //PspReferenceCidTableEntry moves PspCidTable to rax
    //PAGE:0000000140625E8A                 mov     rax, cs:PspCidTable
    //sigscan this func, use function pointer as base and sigscan for mov     rax, cs:PspCidTable
    //
    handle_table_t* get_psp_cid_table()
    {
        void* ntos_base = reinterpret_cast<void*>(tools::get_nt_base());
        if (!ntos_base)
            return nullptr;

        size_t ntos_size = tools::get_module_size(ntos_base);
        //sig for win 10 22h2
        void* function_pointer = tools::find_pattern(reinterpret_cast<unsigned char*>(ntos_base), ntos_size, skCrypt("48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 41 56 48 83 EC ? 48 8B 05 ? ? ? ? 0F B6 EA"));

        if (!function_pointer)
            return nullptr;

        void* mov_instruction = tools::find_pattern(reinterpret_cast<unsigned char*>(function_pointer), 4096, skCrypt("48 8B 05 ? ? ? ?"));
        
        if (!mov_instruction)
            return nullptr;

        //rip stuff

        unsigned char* instruction_ptr = reinterpret_cast<unsigned char*>(mov_instruction);

        std::int32_t offset = *reinterpret_cast<std::int32_t*>(instruction_ptr + 3);

        unsigned char* rip = instruction_ptr + 7;

        void** psp_cid_table_ptr = reinterpret_cast<void**>(rip + offset);

        return reinterpret_cast<handle_table_t*>(*psp_cid_table_ptr);

    }

    typedef NTSTATUS(ExDestroyHandle)(handle_table_t*, void*, handle_table_entry_t*);

    NTSTATUS ex_destroy_handle(handle_table_t* handle_table, void* handle, handle_table_entry_t* entry)
    {
        //handle may be 0 sometimes so we dont check if !handle
        if (!handle_table || !entry)
            return nt_status_t::unsuccessful;

        void* nt_base = reinterpret_cast<void*>(tools::get_nt_base());
        if (!nt_base)
            return nt_status_t::unsuccessful;

        size_t nt_size = tools::get_module_size(nt_base);

        //signature for win 10 22h2

        void* ex_destroy_handle = tools::find_pattern(reinterpret_cast<unsigned char*>(nt_base), nt_size, "48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 83 79 ? 00 49 8B E8 48 8B F2 48 8B F9 0F 85");
        if (!ex_destroy_handle)
            return nt_status_t::unsuccessful;

        ExDestroyHandle* func = reinterpret_cast<ExDestroyHandle*>(ex_destroy_handle);

        if (!func)
            return nt_status_t::unsuccessful;

        return func(handle_table, handle, entry);

    }
    //IoWriteCrashDump moves MmPfnDatabase into rax
    //sigscan this function, and sigscan the mov rax, cs:MmPfnDatabase instruction inside the function
    //address:.text:0000000140502BC6  
    //and also non skid way of getting it. usually people get it from kecapturepersistentthreadstate 
    mmpfn_t* get_mmpfn_database()
    {
        void* nt_base = reinterpret_cast<void*>(tools::get_nt_base());
        if (!nt_base)
            return nullptr;

        std::size_t nt_size = tools::get_module_size(nt_base);
        //sig for win 10 22h2
        void* io_write_crash_dump_pointer = tools::find_pattern(reinterpret_cast<unsigned char*>(nt_base), nt_size, skCrypt("48 33 C4 48 89 45 ? 4C 8B B5 ? ? ? ? 33 DB"));

        if (!io_write_crash_dump_pointer)
            return nullptr;

        void* mov_instruction = tools::find_pattern(reinterpret_cast<unsigned char*>(io_write_crash_dump_pointer), 4096, skCrypt("48 8B 05 ? ? ? ?"));

        if (!mov_instruction)
            return nullptr;

        unsigned char* instruction_ptr = reinterpret_cast<unsigned char*>(mov_instruction);

        std::int32_t offset = *reinterpret_cast<std::int32_t*>(instruction_ptr + 3);

        unsigned char* rip = instruction_ptr + 7;

        void** pfn_database_pointer = reinterpret_cast<void**>(rip + offset);

        return reinterpret_cast<mmpfn_t*>(*pfn_database_pointer);
    }

}

#endif // !FUNCTIONS_H
