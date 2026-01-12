#pragma once
#include "structures.h"
#ifndef TOOLS_H
#define TOOLS_H
#include "crt.h"
#include "function_signatures.h"
#include "skcrypt.h"

namespace tools
{
	inline std::uintptr_t m_nt_base = 0;
	extern "C" std::uintptr_t get_nt_base();

	unsigned char* get_system_routine(const char* export_name) {
		auto dos_header{ reinterpret_cast<dos_header_t*> (m_nt_base) };
		auto nt_headers{ reinterpret_cast<nt_headers_t*> (m_nt_base + dos_header->m_lfanew) };
		if (!dos_header->is_valid() || !nt_headers->is_valid())
			return {};

		auto exp_dir{ nt_headers->m_export_table.as_rva< export_directory_t* >(m_nt_base) };
		if (!exp_dir->m_address_of_functions || !exp_dir->m_address_of_names || !exp_dir->m_address_of_names_ordinals)
			return {};

		auto name{ reinterpret_cast<std::int32_t*> (m_nt_base + exp_dir->m_address_of_names) };
		auto func{ reinterpret_cast<std::int32_t*> (m_nt_base + exp_dir->m_address_of_functions) };
		auto ords{ reinterpret_cast<std::int16_t*> (m_nt_base + exp_dir->m_address_of_names_ordinals) };

		for (std::int32_t i{}; i < exp_dir->m_number_of_names; i++) {
			auto cur_name{ m_nt_base + name[i] };
			auto cur_func{ m_nt_base + func[ords[i]] };
			if (!cur_name || !cur_func) continue;
			if (crt::strcmp(export_name, reinterpret_cast<char*>(cur_name)) == 0)
				return reinterpret_cast<unsigned char*>(cur_func);
		}
		return {};
	}

    static int hex_char_to_int(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    }

    static int parse_hex_byte(const char* str) {
        int high = hex_char_to_int(str[0]);
        int low = hex_char_to_int(str[1]);
        if (high == -1 || low == -1) return -1;
        return (high << 4) | low;
    }

    unsigned char* find_pattern(unsigned char* base, size_t size, const char* pattern) {
        size_t pattern_len = 0;
        const char* p = pattern;
        while (*p) {
            while (*p == ' ') p++;
            if (*p == '\0') break;
            pattern_len++;
            if (*p == '?') {
                p++;
                if (*p == '?') p++;
            }
            else {
                p += 2;
            }
        }

        if (pattern_len == 0 || size < pattern_len)
            return nullptr;

        for (size_t i = 0; i <= size - pattern_len; i++) {
            bool found = true;
            const char* sig = pattern;
            size_t byte_idx = 0;

            while (*sig && byte_idx < pattern_len) {
                while (*sig == ' ') sig++;
                if (*sig == '\0') break;

                if (*sig == '?') {
                    sig++;
                    if (*sig == '?') sig++;
                }
                else {
                    int byte_val = parse_hex_byte(sig);
                    if (byte_val != base[i + byte_idx]) {
                        found = false;
                        break;
                    }
                    sig += 2;
                }
                byte_idx++;
            }

            if (found)
                return &base[i];
        }

        return nullptr;
    }

    size_t get_module_size(void* base) {
        auto dos_header = reinterpret_cast<dos_header_t*>(base);
        auto nt_headers = reinterpret_cast<nt_headers_t*>((unsigned char*)base + dos_header->m_lfanew);
        return nt_headers->m_size_of_image;
    }


    void* get_kmodule(LPCWSTR module_name) {
        const char* name = skCrypt("PsLoadedModuleList");

        PLIST_ENTRY module_list = reinterpret_cast<PLIST_ENTRY>(tools::get_system_routine(name));
        if (!module_list)
            return nullptr;
        for (PLIST_ENTRY link = module_list; link != module_list->Blink; link = link->Flink) {
            LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            UNICODE_STRING name;
            func_ptrs.RtlInitUnicodeString(&name, module_name);
            if (func_ptrs.RtlEqualUnicodeString(&entry->BaseDllName, &name, TRUE)) {
                return entry->DllBase;
            }
        }
        return nullptr;
    }

    PEPROCESS get_eprocess_by_name(const char* name)
    {
        if (!name)
        {
            return 0;
        }

        PEPROCESS currentProcess = 0;

        for (ULONG i = 4; i < 262144; i += 4)
        {
            NTSTATUS status = func_ptrs.PsLookupProcessByProcessId((HANDLE)i, &currentProcess);

            if (NT_SUCCESS(status) && currentProcess)
            {
                PCHAR processName = (PCHAR)((ULONG_PTR)currentProcess + 0x5a8);

                if (processName && crt::strcmp(processName, name) == 0)
                {
                    return currentProcess;
                }

                func_ptrs.ObDereferenceObject(currentProcess);
            }
        }

        return 0;
    }

}






#endif // !TOOLS_H

