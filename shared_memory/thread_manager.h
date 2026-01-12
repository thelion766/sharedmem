#pragma once
#ifndef THREAD_MANAGER_H
#define THREAD_MANAGER_H
#include "structures.h"
#include "ia32.h"
#include "function_signatures.h"
#include "tools.h"
#include "functions.h"
namespace thread_manager
{
	ethread_t* get_legit_thread()
	{
		void* func_pointer = tools::get_system_routine(skCrypt("PsIsSystemThread"));
		if (!func_pointer) {
			return nullptr;
		}

		typedef BOOLEAN(*ps_is_system_thread)(PETHREAD);
		ps_is_system_thread is_system_thread = reinterpret_cast<ps_is_system_thread>(func_pointer);

		int found_count = 0;
		int system_count = 0;
		//yea what the fuh
		for (int tid = 4; tid < 0xffff; tid += 4)
		{
			ethread_t* current_thread = nullptr;

			NTSTATUS status = func_ptrs.PsLookupThreadByThreadId(
				reinterpret_cast<HANDLE>(tid),
				reinterpret_cast<PETHREAD*>(&current_thread)
			);

			if (NT_SUCCESS(status) && current_thread)
			{
				found_count++;

				BOOLEAN is_system = is_system_thread(reinterpret_cast<PETHREAD>(current_thread));

				if (is_system) {
					system_count++;
				}


				if (is_system && system_count == 1) {
					return current_thread;
				}
			}

			if (current_thread != nullptr)
				func_ptrs.ObDereferenceObject(current_thread);


		}

		return nullptr;
	}

	bool make_legit(ethread_t* sussy_thread) 
	{
		if (!sussy_thread)
			return false;

		ethread_t* legit_thread = get_legit_thread();
		if (!legit_thread)
			return false;


		sussy_thread->StartAddress = legit_thread->StartAddress;
		sussy_thread->Win32StartAddress = legit_thread->Win32StartAddress;
		sussy_thread->HideFromDebugger = true;
		sussy_thread->CrossThreadFlags |= (1 << 2);

		sussy_thread->Tcb.ThreadFlags = legit_thread->Tcb.ThreadFlags;
		sussy_thread->Tcb.Tag = legit_thread->Tcb.Tag;
		sussy_thread->Tcb.KernelApcDisable = legit_thread->Tcb.KernelApcDisable;

		sussy_thread->Tcb.MiscFlags &= ~(1UL << 10);
		sussy_thread->Tcb.MiscFlags &= ~(1UL << 4);
		sussy_thread->Tcb.MiscFlags &= ~(1UL << 14);

		sussy_thread->Tcb.KernelStack = legit_thread->Tcb.KernelStack;
		sussy_thread->Tcb.StackBase = legit_thread->Tcb.StackBase;
		sussy_thread->Tcb.SavedApcState = legit_thread->Tcb.SavedApcState;
		sussy_thread->Tcb.InitialStack = legit_thread->Tcb.InitialStack;

		sussy_thread->Tcb.PreviousMode = 1; //previous mode 1 = usermode
		sussy_thread->Tcb.Priority = legit_thread->Tcb.Priority;
		sussy_thread->Tcb.BasePriority = legit_thread->Tcb.BasePriority;
		sussy_thread->Tcb.QuantumTarget = legit_thread->Tcb.QuantumTarget;
		sussy_thread->Tcb.Process = legit_thread->Tcb.Process;

		sussy_thread->ActiveImpersonationInfo = 0;

		return true;

	}
	//ud thread dkom (not reccomended to use this)
	bool unlink_thread_list_entry(ethread_t* sussy_thread) 
	{
		if (!sussy_thread)
			return false;

		list_entry_t* entry = &sussy_thread->ThreadListEntry;
		if (!entry)
			return false;

		entry->m_blink->m_flink = entry->m_flink;
		entry->m_flink->m_blink = entry->m_blink;

		entry->m_flink = entry;
		entry->m_blink = entry;
		return true;
	}

	bool cid_table_unlink(kthread_t* sussy_thread) //very danger
	{
		if (!sussy_thread)
			return false;

		auto cid_table = functions::get_psp_cid_table();
		if (!cid_table)
			return false;

		auto ethread = reinterpret_cast<ethread_t*>(sussy_thread);
		if (!ethread)
			return false;

		auto tid = func_ptrs.PsGetThreadId(reinterpret_cast<PETHREAD>(ethread));
		if (!tid)
			return false;
		
		auto ce = functions::exp_lookup_handle_table_entry(reinterpret_cast<std::uint64_t*>(cid_table), reinterpret_cast<long long>(tid));
		
		if (!ce)
			return false;


		if (NT_SUCCESS(functions::ex_destroy_handle(cid_table, tid, ce)))
		{			
			if (ce->ObjectPointerBits == 0)
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		else
		{
			return false;
		}

	}

	bool thread_routine(ethread_t* sussy_thread)
	{
		if (!sussy_thread)
			return false;

		if (!make_legit(sussy_thread))
			return false;

		if (!cid_table_unlink(reinterpret_cast<kthread_t*>(sussy_thread)))
			return false;

		return true;
	}

}



#endif // !THREAD_MANAGER_H
