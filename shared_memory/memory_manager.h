#pragma once
#ifndef MEMORY_MANAGER_H
#define MEMORY_MANAGER_H

#include "tools.h"
#include "structures.h"
#include "ia32.h"
#include "paging.h"
namespace memory_manager
{
	void* allocate_usermode_memory(void* pid, std::size_t size, void* base)
	{
		if (!pid || !size)
			return nullptr;

		void* process_handle = 0;
		eprocess_t* process = 0;
		NTSTATUS status = func_ptrs.PsLookupProcessByProcessId(pid, reinterpret_cast<PEPROCESS*>(&process));
		if (!NT_SUCCESS(status))
			return nullptr;

		status = func_ptrs.ObOpenObjectByPointer(process, obj_kernel_handle, 0, process_all_access, *PsProcessType, KernelMode, &process_handle);
		if (!NT_SUCCESS(status))
		{
			func_ptrs.ObfDereferenceObject(process);
			return nullptr;
		}
		if (!base)
		{
			void* base_1 = 0;
			status = func_ptrs.ZwAllocateVirtualMemory(process_handle, &base_1, 0, &size, mem_reserve | mem_commit, page_execute_readwrite);
			if (!NT_SUCCESS(status))
			{
				func_ptrs.ObfDereferenceObject(process);
				func_ptrs.ZwClose(process_handle);
				return nullptr;
			}
			func_ptrs.ObfDereferenceObject(process);
			func_ptrs.ZwClose(process_handle);
			return base_1;
		}
		else
		{
			status = func_ptrs.ZwAllocateVirtualMemory(process_handle, &base, 0, &size, mem_reserve | mem_commit, page_execute_readwrite);
			if (!NT_SUCCESS(status))
			{
				func_ptrs.ObfDereferenceObject(process);
				func_ptrs.ZwClose(process_handle);
				return nullptr;
			}
			func_ptrs.ObfDereferenceObject(process);
			func_ptrs.ZwClose(process_handle);
			return base;
		}
	}




	void* get_process_base(void* pid)
	{
		if (!pid)
			return nullptr;
		PEPROCESS eprocess = nullptr;
		if (!NT_SUCCESS(func_ptrs.PsLookupProcessByProcessId(pid, &eprocess)))
			return nullptr;
		
		void* value = *reinterpret_cast<void**>(reinterpret_cast<unsigned char*>(eprocess) + 0x520);

		return value;
	}

	bool read_physical(void* pid, std::size_t size, void* address, void* ubuffer)
	{
		if (!pid || !size || !address || !ubuffer)
			return false;
		

		std::uint64_t cr3 = paging::get_cr3(pid);
		if (!cr3)
			return false;

		std::uint64_t physical = paging::virtual_to_physical(reinterpret_cast<std::uint64_t>(address), cr3);
		if (!physical)
			return false;

		MM_COPY_ADDRESS copy;
		copy.PhysicalAddress.QuadPart = physical;
		size_t transfer = 0;
		func_ptrs.MmCopyMemory(ubuffer, copy, size, MM_COPY_MEMORY_PHYSICAL, &transfer);
		return true;
	}

	bool write_physical(void* pid, std::size_t size, void* address, void* value)
	{
		if (!pid || !size || !address || !value)
			return false;


		std::uint64_t cr3 = paging::get_cr3(pid);
		if (!cr3)
			return false;

		std::uint64_t physical = paging::virtual_to_physical(reinterpret_cast<std::uint64_t>(address), cr3);
		if (!physical)
			return false;

		PHYSICAL_ADDRESS phys;
		phys.QuadPart = physical;
		void* mapped_phys = func_ptrs.MmMapIoSpace(phys, size, MmCached);

		crt::memcpy(mapped_phys, value, size);

		func_ptrs.MmUnmapIoSpace(mapped_phys, size);

		return true;
	}

}


#endif // !MEMORY_MANAGER_H
