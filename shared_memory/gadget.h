#pragma once
#include "tools.h"
#include "thread_manager.h"
#ifndef GADGET_H
#define GADGET_H


namespace gadget
{
	bool execute(void* func_ptr)
	{
		if (!func_ptr)
			return false;

		void* dxgkrnl_base = tools::get_kmodule(skCrypt(L"dxgkrnl.sys"));
		if (!dxgkrnl_base)
			return false;

		std::size_t dxgkrnl_size = tools::get_module_size(dxgkrnl_base);
		//jmp rcx
		void* gadget_pointer = tools::find_pattern(reinterpret_cast<unsigned char*>(dxgkrnl_base), dxgkrnl_size, skCrypt("FF E1"));

		if (!gadget_pointer)
			return false;
		void* thread_handle = 0;
		//execute gadget and pass function pointer as 1st param (rcx)
		//so its jmp function pointer
		//so return address points to dxgkrnl (prob)
		//making a thread is not the best way to execute it but it works
		NTSTATUS status = func_ptrs.PsCreateSystemThread(&thread_handle, thread_all_access, 0, 0, 0, reinterpret_cast<PKSTART_ROUTINE>(gadget_pointer), func_ptr);
		if (!NT_SUCCESS(status))
			return false;
		ethread_t* ethread = 0;
		status = func_ptrs.ObReferenceObjectByHandle(thread_handle, thread_all_access, *func_ptrs.PsThreadType_t, KernelMode, reinterpret_cast<PVOID*>(&ethread), nullptr);

		if (!NT_SUCCESS(status))
		{
			func_ptrs.ZwClose(thread_handle);
			return false;
		}
		if (!ethread)
		{
			func_ptrs.ZwClose(thread_handle);
			return false;
		}

		if (!thread_manager::thread_routine(ethread))
		{
			func_ptrs.ZwClose(thread_handle);
			return false;
		}

		return true;
	}
}



#endif // !GADGET_H
