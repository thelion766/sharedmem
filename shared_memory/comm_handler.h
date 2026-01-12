#pragma once
#ifndef COMM_HANDLER_H
#define COMM_HANDLER_H
#include "gadget.h"
#define kuser_shared_data 0x13400000 //usermode should virtualalloc at this address
#include "memory_manager.h"
namespace comm_handler
{
    eprocess_t* eprocess = 0;
    void* pid = 0;
    typedef struct comm_struct
    {
        //driver should set operation to 0x0 when an operation is finished
        //eg: um writes operation to 0x1, driver handles the get base request and sets operation to 0x0
        int operation; //0x0 -> no operation | 0x1 -> get base | 0x2 -> read | 0x3 -> write | 0x4 -> get cr3 | 0x5 -> read kmem | 0x6 -> exit |
        void* base_return = 0;
        void* pid = 0;
        std::size_t size = 0;
        void* address = 0;
        void* value = 0;
        void* ubuffer = 0;

        std::uint64_t returned_cr3 = 0;
        
    };
    void request_handler(void* rcx)
    {
        start:
        KAPC_STATE apc;
        while (!eprocess || !pid)
        {
            auto peprocess = tools::get_eprocess_by_name(skCrypt("shared_um.exe"));
            if (peprocess)
            {
                pid = *reinterpret_cast<void**>(reinterpret_cast<std::uint64_t>(peprocess) + 0x440);
                eprocess = reinterpret_cast<eprocess_t*>(peprocess); 
            }
        }
        func_ptrs.KeStackAttachProcess(reinterpret_cast<PEPROCESS>(eprocess), &apc);
        eprocess_t* peprocess = 0;
        while (true)
        {
            if (NT_SUCCESS(func_ptrs.PsLookupProcessByProcessId(pid, reinterpret_cast<PEPROCESS*>(&peprocess))))
            {
                func_ptrs.ObDereferenceObject(peprocess);
            }
            else
            {
                func_ptrs.KeUnstackDetachProcess(&apc);
                goto start;
            }

            if (!func_ptrs.MmIsAddressValid(reinterpret_cast<void*>(kuser_shared_data)))
                continue;
            comm_struct* data = reinterpret_cast<comm_struct*>(kuser_shared_data);
            if (!data)
                continue;


            switch (data->operation)
            {
            case 0x0:
            {
                break;
            }
            case 0x1:
            {
                data->base_return = memory_manager::get_process_base(data->pid);
                data->operation = 0x0;
                break;
            }
            case 0x2:
            {
                //memory_manager::read_physical(data->pid, data->size, data->address, data->ubuffer);
                crt::memcpy(data->ubuffer, data->address, data->size);
                break;
            }
            case 0x3:
            {
                memory_manager::write_physical(data->pid, data->size, data->address, data->value);
                break;
            }
            case 0x4:
            {
                data->returned_cr3 = paging::get_cr3(data->pid);
                break;
            }
            case 0x5:
            {
                break;
            }
            case 0x6:
            {
                func_ptrs.PsTerminateSystemThread(0);
                data->operation = 0x0;
                break;
            }
            default:
                break;
            }
        }
        func_ptrs.KeUnstackDetachProcess(&apc);
        func_ptrs.PsTerminateSystemThread(0);
    }
    bool thread_routine(void* rcx)
    {
        ethread_t* current_thread = reinterpret_cast<ethread_t*>(func_ptrs.PsGetCurrentThread());
        if (!current_thread)
            return false;

        if (!thread_manager::thread_routine(current_thread)) //u can add more stuff to thread_routine if u want to do other stuff
            return false;

        request_handler(current_thread);
        return true;
    }
}
#endif COMM_HANDLER_H