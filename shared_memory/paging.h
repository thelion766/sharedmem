#pragma once
#ifndef PAGING_H
#define PAGING_H
#include "functions.h"
#include "memory_manager.h"
namespace paging
{
	std::uint64_t get_cr3_implement_soon(void* pid); //bruteforce (dont attach)


	bool copy_memory_physical(std::uint64_t src, void* dst, std::size_t size)
	{
		if (!src || !dst || !size)
			return false;

		MM_COPY_ADDRESS copy_address;
		copy_address.PhysicalAddress.QuadPart = src;

		std::size_t transfer = 0;
		func_ptrs.MmCopyMemory(dst, copy_address, size, MM_COPY_MEMORY_PHYSICAL, &transfer);

		return true;
	}

	std::uintptr_t get_cr3(void* pid)
	{
		if (!pid)
			return 0;

		PEPROCESS pProcess = 0;
		func_ptrs.PsLookupProcessByProcessId(pid, &pProcess);

		PUCHAR process = (PUCHAR)pProcess;
		ULONG_PTR process_dirbase = *(PULONG_PTR)(process + 0x28); //dirbase x64, 32bit is 0x18
		if (process_dirbase == 0)
		{
			DWORD64 UserDirOffset = 0x0388;
			ULONG_PTR process_userdirbase = *(PULONG_PTR)(process + UserDirOffset);
			return process_userdirbase;
		}
		return process_dirbase;
	}
	std::uint64_t virtual_to_physical(std::uint64_t virtual_address, std::uint64_t cr3)
	{
		if (!virtual_address || !cr3)
			return 0;

		std::uint64_t pml4_idx = (virtual_address >> 39) & 0x1FF;
		std::uint64_t pdpt_idx = (virtual_address >> 30) & 0x1FF;
		std::uint64_t pd_idx = (virtual_address >> 21) & 0x1FF;
		std::uint64_t pt_idx = (virtual_address >> 12) & 0x1FF;
		std::uint64_t page_offset = virtual_address & 0xFFF;

		std::uint64_t pml4_base = cr3 & page_mask_4kib;
		std::uint64_t pml4e_raw = pml4_base + (pml4_idx * 8);
		std::uint64_t pml4e = 0;
		copy_memory_physical(pml4e_raw, &pml4e, sizeof(std::uint64_t));

		if (!(pml4e & 1))
			return 0;

		std::uint64_t pdpt_base = pml4e & page_mask_4kib;
		std::uint64_t pdpte_raw = pdpt_base + (pdpt_idx * 8);
		std::uint64_t pdpte = 0;
		copy_memory_physical(pdpte_raw, &pdpte, sizeof(std::uint64_t));

		if (!(pdpte & 1))
			return 0;

		if (pdpte & (1ULL << 7))
		{
			std::uint64_t physical = (pdpte & page_mask_1gib) | (virtual_address & page_offset_1gib);
			return physical;
		}

		std::uint64_t pd_base = pdpte & page_mask_4kib;
		std::uint64_t pde_raw = pd_base + (pd_idx * 8);
		std::uint64_t pde = 0;
		copy_memory_physical(pde_raw, &pde, sizeof(std::uint64_t));

		if (!(pde & 1))
			return 0;

		if (pde & (1ULL << 7))
		{
			std::uint64_t physical = (pde & page_mask_2mib) | (virtual_address & page_offset_2mib);
			return physical;
		}

		std::uint64_t pt_base = pde & page_mask_4kib;
		std::uint64_t pte_raw = pt_base + (pt_idx * 8);
		std::uint64_t pte = 0;
		copy_memory_physical(pte_raw, &pte, sizeof(std::uint64_t));

		if (!(pte & 1))
			return 0;

		std::uint64_t physical = (pte & page_mask_4kib) | (virtual_address & page_offset_4kib);
		return physical;
	}
}

#endif // !PAGING_H

