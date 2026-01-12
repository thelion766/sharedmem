#pragma once
#include "function_signatures.h"
#include "tools.h"
#ifndef RESOLVER_H
#define RESOLVER_H

namespace resolver
{
	bool setup()
	{
		tools::m_nt_base = tools::get_nt_base();
		if (!tools::m_nt_base) return false;
		func_ptrs.PsThreadType_t = (POBJECT_TYPE*)tools::get_system_routine(skCrypt("PsThreadType"));
		func_ptrs.PsTerminateSystemThread = (PsTerminateSystemThread_t)tools::get_system_routine(skCrypt("PsTerminateSystemThread"));
		func_ptrs.PsCreateSystemThread = (PsCreateSystemThread_t)tools::get_system_routine(skCrypt("PsCreateSystemThread"));
		func_ptrs.IoGetCurrentProcess = (IoGetCurrentProcess_t)tools::get_system_routine(skCrypt("IoGetCurrentProcess"));
		func_ptrs.RtlInitUnicodeString = (RtlInitUnicodeString_t)tools::get_system_routine(skCrypt("RtlInitUnicodeString"));
		func_ptrs.RtlEqualUnicodeString = (RtlEqualUnicodeString_t)tools::get_system_routine(skCrypt("RtlEqualUnicodeString"));
		func_ptrs.RtlCompareUnicodeString = (RtlCompareUnicodeString_t)tools::get_system_routine(skCrypt("RtlCompareUnicodeString"));
		func_ptrs.RtlCopyUnicodeString = (RtlCopyUnicodeString_t)tools::get_system_routine(skCrypt("RtlCopyUnicodeString"));
		func_ptrs.RtlAppendUnicodeStringToString = (RtlAppendUnicodeStringToString_t)tools::get_system_routine(skCrypt("RtlAppendUnicodeStringToString"));
		func_ptrs.RtlAppendUnicodeToString = (RtlAppendUnicodeToString_t)tools::get_system_routine(skCrypt("RtlAppendUnicodeToString"));
		func_ptrs.RtlFreeUnicodeString = (RtlFreeUnicodeString_t)tools::get_system_routine(skCrypt("RtlFreeUnicodeString"));
		func_ptrs.RtlUnicodeStringToAnsiString = (RtlUnicodeStringToAnsiString_t)tools::get_system_routine(skCrypt("RtlUnicodeStringToAnsiString"));
		func_ptrs.RtlAnsiStringToUnicodeString = (RtlAnsiStringToUnicodeString_t)tools::get_system_routine(skCrypt("RtlAnsiStringToUnicodeString"));
		func_ptrs.RtlInitAnsiString = (RtlInitAnsiString_t)tools::get_system_routine(skCrypt("RtlInitAnsiString"));
		func_ptrs.RtlCompareMemory = (RtlCompareMemory_t)tools::get_system_routine(skCrypt("RtlCompareMemory"));
		func_ptrs.RtlCopyMemory = (RtlCopyMemory_t)tools::get_system_routine(skCrypt("RtlCopyMemory"));
		func_ptrs.RtlZeroMemory = (RtlZeroMemory_t)tools::get_system_routine(skCrypt("RtlZeroMemory"));
		func_ptrs.RtlFillMemory = (RtlFillMemory_t)tools::get_system_routine(skCrypt("RtlFillMemory"));

		func_ptrs.PsLookupProcessByProcessId = (PsLookupProcessByProcessId_t)tools::get_system_routine(skCrypt("PsLookupProcessByProcessId"));
		func_ptrs.PsGetCurrentProcess_ = (PsGetCurrentProcess_t)tools::get_system_routine(skCrypt("PsGetCurrentProcess"));
		func_ptrs.PsGetCurrentProcessId = (PsGetCurrentProcessId_t)tools::get_system_routine(skCrypt("PsGetCurrentProcessId"));
		func_ptrs.PsGetProcessId = (PsGetProcessId_t)tools::get_system_routine(skCrypt("PsGetProcessId"));
		func_ptrs.PsGetProcessImageFileName = (PsGetProcessImageFileName_t)tools::get_system_routine(skCrypt("PsGetProcessImageFileName"));
		func_ptrs.PsGetProcessSectionBaseAddress = (PsGetProcessSectionBaseAddress_t)tools::get_system_routine(skCrypt("PsGetProcessSectionBaseAddress"));
		func_ptrs.PsIsProtectedProcess = (PsIsProtectedProcess_t)tools::get_system_routine(skCrypt("PsIsProtectedProcess"));
		func_ptrs.PsGetProcessPeb = (PsGetProcessPeb_t)tools::get_system_routine(skCrypt("PsGetProcessPeb"));
		func_ptrs.PsGetProcessWow64Process = (PsGetProcessWow64Process_t)tools::get_system_routine(skCrypt("PsGetProcessWow64Process"));
		func_ptrs.PsGetProcessCreateTimeQuadPart = (PsGetProcessCreateTimeQuadPart_t)tools::get_system_routine(skCrypt("PsGetProcessCreateTimeQuadPart"));
		func_ptrs.PsTerminateProcess = (PsTerminateProcess_t)tools::get_system_routine(skCrypt("PsTerminateProcess"));
		func_ptrs.PsSuspendProcess = (PsSuspendProcess_t)tools::get_system_routine(skCrypt("PsSuspendProcess"));
		func_ptrs.PsResumeProcess = (PsResumeProcess_t)tools::get_system_routine(skCrypt("PsResumeProcess"));

		func_ptrs.PsGetCurrentThread = (PsGetCurrentThread_t)tools::get_system_routine(skCrypt("PsGetCurrentThread"));
		func_ptrs.PsGetCurrentThreadId = (PsGetCurrentThreadId_t)tools::get_system_routine(skCrypt("PsGetCurrentThreadId"));
		func_ptrs.PsLookupThreadByThreadId = (PsLookupThreadByThreadId_t)tools::get_system_routine(skCrypt("PsLookupThreadByThreadId"));
		func_ptrs.PsGetThreadId = (PsGetThreadId_t)tools::get_system_routine(skCrypt("PsGetThreadId"));
		func_ptrs.KeStackAttachProcess = (KeStackAttachProcess_t)tools::get_system_routine(skCrypt("KeStackAttachProcess"));
		func_ptrs.KeUnstackDetachProcess = (KeUnstackDetachProcess_t)tools::get_system_routine(skCrypt("KeUnstackDetachProcess"));

		func_ptrs.MmCopyMemory = (MmCopyMemory_t)tools::get_system_routine(skCrypt("MmCopyMemory"));
		func_ptrs.MmIsAddressValid = (MmIsAddressValid_t)tools::get_system_routine(skCrypt("MmIsAddressValid"));
		func_ptrs.MmCopyVirtualMemory = (MmCopyVirtualMemory_t)tools::get_system_routine(skCrypt("MmCopyVirtualMemory"));
		func_ptrs.MmAllocateContiguousMemory = (MmAllocateContiguousMemory_t)tools::get_system_routine(skCrypt("MmAllocateContiguousMemory"));
		func_ptrs.MmAllocateContiguousMemorySpecifyCache = (MmAllocateContiguousMemorySpecifyCache_t)tools::get_system_routine(skCrypt("MmAllocateContiguousMemorySpecifyCache"));
		func_ptrs.MmFreeContiguousMemory = (MmFreeContiguousMemory_t)tools::get_system_routine(skCrypt("MmFreeContiguousMemory"));
		func_ptrs.MmAllocatePagesForMdl = (MmAllocatePagesForMdl_t)tools::get_system_routine(skCrypt("MmAllocatePagesForMdl"));
		func_ptrs.MmFreePagesFromMdl = (MmFreePagesFromMdl_t)tools::get_system_routine(skCrypt("MmFreePagesFromMdl"));
		func_ptrs.MmGetPhysicalAddress = (MmGetPhysicalAddress_t)tools::get_system_routine(skCrypt("MmGetPhysicalAddress"));
		func_ptrs.MmGetVirtualForPhysical = (MmGetVirtualForPhysical_t)tools::get_system_routine(skCrypt("MmGetVirtualForPhysical"));
		func_ptrs.MmGetPhysicalMemoryRanges = (MmGetPhysicalMemoryRanges_t)tools::get_system_routine(skCrypt("MmGetPhysicalMemoryRanges"));
		func_ptrs.MmMapIoSpace = (MmMapIoSpace_t)tools::get_system_routine(skCrypt("MmMapIoSpace"));
		func_ptrs.MmMapIoSpaceEx = (MmMapIoSpaceEx_t)tools::get_system_routine(skCrypt("MmMapIoSpaceEx"));
		func_ptrs.MmUnmapIoSpace = (MmUnmapIoSpace_t)tools::get_system_routine(skCrypt("MmUnmapIoSpace"));
		func_ptrs.MmSecureVirtualMemory = (MmSecureVirtualMemory_t)tools::get_system_routine(skCrypt("MmSecureVirtualMemory"));
		func_ptrs.MmUnsecureVirtualMemory = (MmUnsecureVirtualMemory_t)tools::get_system_routine(skCrypt("MmUnsecureVirtualMemory"));
		func_ptrs.MmGetSystemRoutineAddress = (MmGetSystemRoutineAddress_t)tools::get_system_routine(skCrypt("MmGetSystemRoutineAddress"));

		func_ptrs.IoAllocateMdl = (IoAllocateMdl_t)tools::get_system_routine(skCrypt("IoAllocateMdl"));
		func_ptrs.IoFreeMdl = (IoFreeMdl_t)tools::get_system_routine(skCrypt("IoFreeMdl"));
		func_ptrs.MmProbeAndLockPages = (MmProbeAndLockPages_t)tools::get_system_routine(skCrypt("MmProbeAndLockPages"));
		func_ptrs.MmUnlockPages = (MmUnlockPages_t)tools::get_system_routine(skCrypt("MmUnlockPages"));
		func_ptrs.MmGetMdlPfnArray = (MmGetMdlPfnArray_t)tools::get_system_routine(skCrypt("MmGetMdlPfnArray"));
		func_ptrs.MmMapLockedPages = (MmMapLockedPages_t)tools::get_system_routine(skCrypt("MmMapLockedPages"));
		func_ptrs.MmMapLockedPagesSpecifyCache = (PMM_MAP_LOCKED_PAGES_SPECIFY_CACHE)tools::get_system_routine(skCrypt("MmMapLockedPagesSpecifyCache"));
		func_ptrs.MmUnmapLockedPages = (PMM_UNMAP_LOCKED_PAGES)tools::get_system_routine(skCrypt("MmUnmapLockedPages"));
		func_ptrs.MmProtectMdlSystemAddress = (PMM_PROTECT_MDL_SYSTEM_ADDRESS)tools::get_system_routine(skCrypt("MmProtectMdlSystemAddress"));
		func_ptrs.MmBuildMdlForNonPagedPool = (MmBuildMdlForNonPagedPool_t)tools::get_system_routine(skCrypt("MmBuildMdlForNonPagedPool"));

		func_ptrs.ExAllocatePool = (ExAllocatePool_t)tools::get_system_routine(skCrypt("ExAllocatePool"));
		func_ptrs.ExFreePool = (ExFreePool_t)tools::get_system_routine(skCrypt("ExFreePool"));
		func_ptrs.ExFreePoolWithTag = (ExFreePoolWithTag_t)tools::get_system_routine(skCrypt("ExFreePoolWithTag"));

		func_ptrs.ZwAllocateVirtualMemory = (ZwAllocateVirtualMemory_t)tools::get_system_routine(skCrypt("ZwAllocateVirtualMemory"));
		func_ptrs.ZwFreeVirtualMemory = (ZwFreeVirtualMemory_t)tools::get_system_routine(skCrypt("ZwFreeVirtualMemory"));
		func_ptrs.ZwProtectVirtualMemory = (ZwProtectVirtualMemory_t)tools::get_system_routine(skCrypt("ZwProtectVirtualMemory"));
		func_ptrs.ZwReadVirtualMemory = (ZwReadVirtualMemory_t)tools::get_system_routine(skCrypt("ZwReadVirtualMemory"));
		func_ptrs.ZwWriteVirtualMemory = (ZwWriteVirtualMemory_t)tools::get_system_routine(skCrypt("ZwWriteVirtualMemory"));
		func_ptrs.ZwQueryVirtualMemory = (ZwQueryVirtualMemory_t)tools::get_system_routine(skCrypt("ZwQueryVirtualMemory"));
		func_ptrs.ZwLockVirtualMemory = (ZwLockVirtualMemory_t)tools::get_system_routine(skCrypt("ZwLockVirtualMemory"));
		func_ptrs.ZwUnlockVirtualMemory = (ZwUnlockVirtualMemory_t)tools::get_system_routine(skCrypt("ZwUnlockVirtualMemory"));

		func_ptrs.ObReferenceObjectByHandle = (ObReferenceObjectByHandle_t)tools::get_system_routine(skCrypt("ObReferenceObjectByHandle"));
		func_ptrs.ObReferenceObjectByPointer = (ObReferenceObjectByPointer_t)tools::get_system_routine(skCrypt("ObReferenceObjectByPointer"));
		func_ptrs.ObfDereferenceObject = (ObfDereferenceObject_t)tools::get_system_routine(skCrypt("ObfDereferenceObject"));
		func_ptrs.ObOpenObjectByPointer = (ObOpenObjectByPointer_t)tools::get_system_routine(skCrypt("ObOpenObjectByPointer"));
		func_ptrs.ObQueryNameString = (ObQueryNameString_t)tools::get_system_routine(skCrypt("ObQueryNameString"));

		func_ptrs.IoCreateDevice = (IoCreateDevice_t)tools::get_system_routine(skCrypt("IoCreateDevice"));
		func_ptrs.IoDeleteDevice = (IoDeleteDevice_t)tools::get_system_routine(skCrypt("IoDeleteDevice"));
		func_ptrs.IoCreateSymbolicLink = (IoCreateSymbolicLink_t)tools::get_system_routine(skCrypt("IoCreateSymbolicLink"));
		func_ptrs.IoDeleteSymbolicLink = (IoDeleteSymbolicLink_t)tools::get_system_routine(skCrypt("IoDeleteSymbolicLink"));
		func_ptrs.IofCompleteRequest = (IofCompleteRequest_t)tools::get_system_routine(skCrypt("IofCompleteRequest"));
		func_ptrs.IoGetCurrentIrpStackLocation = (IoGetCurrentIrpStackLocation_t)tools::get_system_routine(skCrypt("IoGetCurrentIrpStackLocation"));
		func_ptrs.IoGetDeviceObjectPointer = (IoGetDeviceObjectPointer_t)tools::get_system_routine(skCrypt("IoGetDeviceObjectPointer"));
		func_ptrs.IoGetRelatedDeviceObject = (IoGetRelatedDeviceObject_t)tools::get_system_routine(skCrypt("IoGetRelatedDeviceObject"));
		func_ptrs.IoGetAttachedDeviceReference = (IoGetAttachedDeviceReference_t)tools::get_system_routine(skCrypt("IoGetAttachedDeviceReference"));
		func_ptrs.IoAttachDeviceToDeviceStack = (IoAttachDeviceToDeviceStack_t)tools::get_system_routine(skCrypt("IoAttachDeviceToDeviceStack"));
		func_ptrs.IoDetachDevice = (IoDetachDevice_t)tools::get_system_routine(skCrypt("IoDetachDevice"));
		func_ptrs.IoCallDriver = (IoCallDriver_t)tools::get_system_routine(skCrypt("IoCallDriver"));
		func_ptrs.IofCallDriver = (IofCallDriver_t)tools::get_system_routine(skCrypt("IofCallDriver"));
		func_ptrs.IoBuildDeviceIoControlRequest = (IoBuildDeviceIoControlRequest_t)tools::get_system_routine(skCrypt("IoBuildDeviceIoControlRequest"));
		func_ptrs.IoBuildSynchronousFsdRequest = (IoBuildSynchronousFsdRequest_t)tools::get_system_routine(skCrypt("IoBuildSynchronousFsdRequest"));

		func_ptrs.ZwCreateFile = (ZwCreateFile_t)tools::get_system_routine(skCrypt("ZwCreateFile"));
		func_ptrs.ZwOpenFile = (ZwOpenFile_t)tools::get_system_routine(skCrypt("ZwOpenFile"));
		func_ptrs.ZwReadFile = (ZwReadFile_t)tools::get_system_routine(skCrypt("ZwReadFile"));
		func_ptrs.ZwWriteFile = (ZwWriteFile_t)tools::get_system_routine(skCrypt("ZwWriteFile"));
		func_ptrs.ZwClose = (ZwClose_t)tools::get_system_routine(skCrypt("ZwClose"));
		func_ptrs.ZwQueryInformationFile = (ZwQueryInformationFile_t)tools::get_system_routine(skCrypt("ZwQueryInformationFile"));
		func_ptrs.ZwSetInformationFile = (ZwSetInformationFile_t)tools::get_system_routine(skCrypt("ZwSetInformationFile"));
		func_ptrs.ZwDeleteFile = (ZwDeleteFile_t)tools::get_system_routine(skCrypt("ZwDeleteFile"));

		func_ptrs.ZwCreateKey = (ZwCreateKey_t)tools::get_system_routine(skCrypt("ZwCreateKey"));
		func_ptrs.ZwOpenKey = (ZwOpenKey_t)tools::get_system_routine(skCrypt("ZwOpenKey"));
		func_ptrs.ZwDeleteKey = (ZwDeleteKey_t)tools::get_system_routine(skCrypt("ZwDeleteKey"));
		func_ptrs.ZwQueryValueKey = (ZwQueryValueKey_t)tools::get_system_routine(skCrypt("ZwQueryValueKey"));
		func_ptrs.ZwSetValueKey = (ZwSetValueKey_t)tools::get_system_routine(skCrypt("ZwSetValueKey"));
		func_ptrs.ZwDeleteValueKey = (ZwDeleteValueKey_t)tools::get_system_routine(skCrypt("ZwDeleteValueKey"));
		func_ptrs.ZwEnumerateKey = (ZwEnumerateKey_t)tools::get_system_routine(skCrypt("ZwEnumerateKey"));
		func_ptrs.ZwEnumerateValueKey = (ZwEnumerateValueKey_t)tools::get_system_routine(skCrypt("ZwEnumerateValueKey"));

		func_ptrs.KeSetEvent = (KeSetEvent_t)tools::get_system_routine(skCrypt("KeSetEvent"));
		func_ptrs.KeResetEvent = (KeResetEvent_t)tools::get_system_routine(skCrypt("KeResetEvent"));
		func_ptrs.KeClearEvent = (KeClearEvent_t)tools::get_system_routine(skCrypt("KeClearEvent"));
		func_ptrs.KeWaitForSingleObject = (KeWaitForSingleObject_t)tools::get_system_routine(skCrypt("KeWaitForSingleObject"));
		func_ptrs.KeWaitForMultipleObjects = (KeWaitForMultipleObjects_t)tools::get_system_routine(skCrypt("KeWaitForMultipleObjects"));

		func_ptrs.KeInitializeMutex = (KeInitializeMutex_t)tools::get_system_routine(skCrypt("KeInitializeMutex"));
		func_ptrs.KeReleaseMutex = (KeReleaseMutex_t)tools::get_system_routine(skCrypt("KeReleaseMutex"));

		func_ptrs.KeInitializeSemaphore = (KeInitializeSemaphore_t)tools::get_system_routine(skCrypt("KeInitializeSemaphore"));
		func_ptrs.KeReleaseSemaphore = (KeReleaseSemaphore_t)tools::get_system_routine(skCrypt("KeReleaseSemaphore"));

		func_ptrs.KeInitializeSpinLock = (KeInitializeSpinLock_t)tools::get_system_routine(skCrypt("KeInitializeSpinLock"));
		func_ptrs.KeAcquireSpinLock = (KeAcquireSpinLock_t)tools::get_system_routine(skCrypt("KeAcquireSpinLock"));
		func_ptrs.KeReleaseSpinLock = (KeReleaseSpinLock_t)tools::get_system_routine(skCrypt("KeReleaseSpinLock"));
		func_ptrs.KeAcquireSpinLockAtDpcLevel = (KeAcquireSpinLockAtDpcLevel_t)tools::get_system_routine(skCrypt("KeAcquireSpinLockAtDpcLevel"));
		func_ptrs.KeReleaseSpinLockFromDpcLevel = (KeReleaseSpinLockFromDpcLevel_t)tools::get_system_routine(skCrypt("KeReleaseSpinLockFromDpcLevel"));

		func_ptrs.KeInitializeDpc = (KeInitializeDpc_t)tools::get_system_routine(skCrypt("KeInitializeDpc"));
		func_ptrs.KeInsertQueueDpc = (KeInsertQueueDpc_t)tools::get_system_routine(skCrypt("KeInsertQueueDpc"));
		func_ptrs.KeRemoveQueueDpc = (KeRemoveQueueDpc_t)tools::get_system_routine(skCrypt("KeRemoveQueueDpc"));
		func_ptrs.KeInitializeTimer = (KeInitializeTimer_t)tools::get_system_routine(skCrypt("KeInitializeTimer"));
		func_ptrs.KeSetTimer = (KeSetTimer_t)tools::get_system_routine(skCrypt("KeSetTimer"));
		func_ptrs.KeCancelTimer = (KeCancelTimer_t)tools::get_system_routine(skCrypt("KeCancelTimer"));

		func_ptrs.KeInitializeApc = (KeInitializeApc_t)tools::get_system_routine(skCrypt("KeInitializeApc"));
		func_ptrs.KeInsertQueueApc = (KeInsertQueueApc_t)tools::get_system_routine(skCrypt("KeInsertQueueApc"));
		func_ptrs.KeTestAlertThread = (KeTestAlertThread_t)tools::get_system_routine(skCrypt("KeTestAlertThread"));

		func_ptrs.KeGetCurrentIrql = (KeGetCurrentIrql_t)tools::get_system_routine(skCrypt("KeGetCurrentIrql"));
		func_ptrs.KfRaiseIrql = (KfRaiseIrql_t)tools::get_system_routine(skCrypt("KfRaiseIrql"));
		func_ptrs.KeLowerIrql = (KeLowerIrql_t)tools::get_system_routine(skCrypt("KeLowerIrql"));

		func_ptrs.KeGetCurrentProcessorIndex = (KeGetCurrentProcessorIndex_t)tools::get_system_routine(skCrypt("KeGetCurrentProcessorIndex"));
		func_ptrs.KeSetSystemAffinityThread = (KeSetSystemAffinityThread_t)tools::get_system_routine(skCrypt("KeSetSystemAffinityThread"));
		func_ptrs.KeRevertToUserAffinityThread = (KeRevertToUserAffinityThread_t)tools::get_system_routine(skCrypt("KeRevertToUserAffinityThread"));
		func_ptrs.KeQueryActiveProcessorCount = (KeQueryActiveProcessorCount_t)tools::get_system_routine(skCrypt("KeQueryActiveProcessorCount"));

		func_ptrs.ZwQuerySystemInformation = (ZwQuerySystemInformation_t)tools::get_system_routine(skCrypt("ZwQuerySystemInformation"));
		func_ptrs.ZwSetSystemInformation = (ZwSetSystemInformation_t)tools::get_system_routine(skCrypt("ZwSetSystemInformation"));
		func_ptrs.ZwQueryInformationProcess = (ZwQueryInformationProcess_t)tools::get_system_routine(skCrypt("ZwQueryInformationProcess"));
		func_ptrs.ZwSetInformationProcess = (ZwSetInformationProcess_t)tools::get_system_routine(skCrypt("ZwSetInformationProcess"));
		func_ptrs.ZwQueryInformationThread = (ZwQueryInformationThread_t)tools::get_system_routine(skCrypt("ZwQueryInformationThread"));
		func_ptrs.ZwSetInformationThread = (ZwSetInformationThread_t)tools::get_system_routine(skCrypt("ZwSetInformationThread"));

		func_ptrs.ZwCreateSection = (ZwCreateSection_t)tools::get_system_routine(skCrypt("ZwCreateSection"));
		func_ptrs.ZwOpenSection = (ZwOpenSection_t)tools::get_system_routine(skCrypt("ZwOpenSection"));
		func_ptrs.ZwMapViewOfSection = (ZwMapViewOfSection_t)tools::get_system_routine(skCrypt("ZwMapViewOfSection"));
		func_ptrs.ZwUnmapViewOfSection = (ZwUnmapViewOfSection_t)tools::get_system_routine(skCrypt("ZwUnmapViewOfSection"));

		func_ptrs.ZwDuplicateObject = (ZwDuplicateObject_t)tools::get_system_routine(skCrypt("ZwDuplicateObject"));
		func_ptrs.ZwQueryObject = (ZwQueryObject_t)tools::get_system_routine(skCrypt("ZwQueryObject"));

		func_ptrs.SeAccessCheck = (SeAccessCheck_t)tools::get_system_routine(skCrypt("SeAccessCheck"));
		func_ptrs.SeSinglePrivilegeCheck = (SeSinglePrivilegeCheck_t)tools::get_system_routine(skCrypt("SeSinglePrivilegeCheck"));

		func_ptrs.ZwLoadDriver = (ZwLoadDriver_t)tools::get_system_routine(skCrypt("ZwLoadDriver"));
		func_ptrs.ZwUnloadDriver = (ZwUnloadDriver_t)tools::get_system_routine(skCrypt("ZwUnloadDriver"));

		func_ptrs.ExEnterCriticalRegionAndAcquireResourceExclusive = (ExEnterCriticalRegionAndAcquireResourceExclusive_t)tools::get_system_routine(skCrypt("ExEnterCriticalRegionAndAcquireResourceExclusive"));
		func_ptrs.ExReleaseResourceAndLeaveCriticalRegion = (ExReleaseResourceAndLeaveCriticalRegion_t)tools::get_system_routine(skCrypt("ExReleaseResourceAndLeaveCriticalRegion"));

		func_ptrs.InterlockedExchange = (InterlockedExchange_t)tools::get_system_routine(skCrypt("InterlockedExchange"));
		func_ptrs.InterlockedCompareExchange = (InterlockedCompareExchange_t)tools::get_system_routine(skCrypt("InterlockedCompareExchange"));
		func_ptrs.InterlockedIncrement = (InterlockedIncrement_t)tools::get_system_routine(skCrypt("InterlockedIncrement"));
		func_ptrs.InterlockedDecrement = (InterlockedDecrement_t)tools::get_system_routine(skCrypt("InterlockedDecrement"));

		func_ptrs.DbgPrint = (DbgPrint_t)tools::get_system_routine(skCrypt("DbgPrint"));
		func_ptrs.DbgPrintEx = (DbgPrintEx_t)tools::get_system_routine(skCrypt("DbgPrintEx"));

		func_ptrs.ExGetPreviousMode = (PEX_GET_PREVIOUS_MODE)tools::get_system_routine(skCrypt("ExGetPreviousMode"));
		func_ptrs._InterlockedExchangePointer = (_InterlockedExchangePointer_t)tools::get_system_routine(skCrypt("InterlockedExchangePointer"));

		return true;
	}
}


#endif // !RESOLVER_H
