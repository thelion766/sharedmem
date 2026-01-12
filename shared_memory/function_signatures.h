#include "ntifs.h"
#include "structures.h"

#ifndef FUNCTION_SIGNATURES_H
#define FUNCTION_SIGNATURES_H


typedef NTSTATUS(*MmCopyMemory_t)(PVOID TargetAddress, MM_COPY_ADDRESS SourceAddress, SIZE_T NumberOfBytes, ULONG Flags, PSIZE_T NumberOfBytesTransferred);
typedef BOOLEAN(*MmIsAddressValid_t)(PVOID VirtualAddress);
typedef NTSTATUS(*MmCopyVirtualMemory_t)(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
typedef PVOID(*MmAllocateContiguousMemory_t)(SIZE_T NumberOfBytes, PHYSICAL_ADDRESS HighestAcceptableAddress);
typedef PVOID(*MmAllocateContiguousMemorySpecifyCache_t)(SIZE_T NumberOfBytes, PHYSICAL_ADDRESS LowestAcceptableAddress, PHYSICAL_ADDRESS HighestAcceptableAddress, PHYSICAL_ADDRESS BoundaryAddressMultiple, MEMORY_CACHING_TYPE CacheType);
typedef VOID(*MmFreeContiguousMemory_t)(PVOID BaseAddress);
typedef PMDL(*MmAllocatePagesForMdl_t)(PHYSICAL_ADDRESS LowAddress, PHYSICAL_ADDRESS HighAddress, PHYSICAL_ADDRESS SkipBytes, SIZE_T TotalBytes);
typedef VOID(*MmFreePagesFromMdl_t)(PMDL MemoryDescriptorList);
typedef PVOID(*MmMapLockedPages_t)(PMDL MemoryDescriptorList, KPROCESSOR_MODE AccessMode);
typedef VOID(*MmBuildMdlForNonPagedPool_t)(PMDL MemoryDescriptorList);
typedef HANDLE(*MmSecureVirtualMemory_t)(PVOID Address, SIZE_T Size, ULONG ProbeMode);
typedef VOID(*MmUnsecureVirtualMemory_t)(HANDLE SecureHandle);
typedef PVOID(*MmGetSystemRoutineAddress_t)(PUNICODE_STRING SystemRoutineName);
typedef PHYSICAL_ADDRESS(*MmGetPhysicalAddress_t)(PVOID BaseAddress);
typedef PVOID(*MmGetVirtualForPhysical_t)(PHYSICAL_ADDRESS PhysicalAddress);
typedef PPHYSICAL_MEMORY_RANGE(*MmGetPhysicalMemoryRanges_t)(VOID);
typedef PVOID(*MmMapIoSpace_t)(PHYSICAL_ADDRESS PhysicalAddress, SIZE_T NumberOfBytes, MEMORY_CACHING_TYPE CacheType);
typedef PVOID(*MmMapIoSpaceEx_t)(PHYSICAL_ADDRESS PhysicalAddress, SIZE_T NumberOfBytes, ULONG Protect);
typedef VOID(*MmUnmapIoSpace_t)(PVOID BaseAddress, SIZE_T NumberOfBytes);

typedef struct _MM_COPY_ADDRESS_T {
    union {
        PVOID VirtualAddress;
        PHYSICAL_ADDRESS PhysicalAddress;
    };
} MM_COPY_ADDRESS_T, * PMM_COPY_ADDRESS;

typedef PMDL(*IoAllocateMdl_t)(PVOID VirtualAddress, ULONG Length, BOOLEAN SecondaryBuffer, BOOLEAN ChargeQuota, PIRP Irp);
typedef VOID(*IoFreeMdl_t)(PMDL Mdl);
typedef VOID(*MmProbeAndLockPages_t)(PMDL MemoryDescriptorList, KPROCESSOR_MODE AccessMode, LOCK_OPERATION Operation);
typedef VOID(*MmUnlockPages_t)(PMDL MemoryDescriptorList);
typedef PPFN_NUMBER(*MmGetMdlPfnArray_t)(PMDL Mdl);
typedef NTSTATUS(*PMM_PROTECT_MDL_SYSTEM_ADDRESS)(PMDL MemoryDescriptorList, ULONG NewProtect);
typedef PVOID(*PMM_MAP_LOCKED_PAGES_SPECIFY_CACHE)(PMDL MemoryDescriptorList, KPROCESSOR_MODE AccessMode, MEMORY_CACHING_TYPE CacheType, PVOID RequestedAddress, ULONG BugCheckOnFailure, ULONG Priority);
typedef VOID(*PMM_UNMAP_LOCKED_PAGES)(PVOID BaseAddress, PMDL MemoryDescriptorList);

typedef NTSTATUS(*PsLookupProcessByProcessId_t)(HANDLE ProcessId, PEPROCESS* Process);
typedef PEPROCESS(*PsGetCurrentProcess_t)(VOID);
typedef HANDLE(*PsGetCurrentProcessId_t)(VOID);
typedef HANDLE(*PsGetProcessId_t)(PEPROCESS Process);
typedef PUCHAR(*PsGetProcessImageFileName_t)(PEPROCESS Process);
typedef PVOID(*PsGetProcessSectionBaseAddress_t)(PEPROCESS Process);
typedef BOOLEAN(*PsIsProtectedProcess_t)(PEPROCESS Process);
typedef PPEB(*PsGetProcessPeb_t)(PEPROCESS Process);
typedef PVOID(*PsGetProcessWow64Process_t)(PEPROCESS Process);
typedef LONGLONG(*PsGetProcessCreateTimeQuadPart_t)(PEPROCESS Process);
typedef LARGE_INTEGER(*PsGetProcessExitTime_t)(VOID);
typedef NTSTATUS(*PsTerminateProcess_t)(PEPROCESS Process, NTSTATUS ExitStatus);
typedef NTSTATUS(*PsSuspendProcess_t)(PEPROCESS Process);
typedef NTSTATUS(*PsResumeProcess_t)(PEPROCESS Process);

typedef PETHREAD(*PsGetCurrentThread_t)(VOID);
typedef HANDLE(*PsGetCurrentThreadId_t)(VOID);
typedef NTSTATUS(*PsLookupThreadByThreadId_t)(HANDLE ThreadId, PETHREAD* Thread);
typedef HANDLE(*PsGetThreadId_t)(PETHREAD Thread);
typedef VOID(*KeStackAttachProcess_t)(PEPROCESS Process, PKAPC_STATE ApcState);
typedef VOID(*KeUnstackDetachProcess_t)(PKAPC_STATE ApcState);

typedef PVOID(*ExAllocatePool_t)(POOL_TYPE PoolType, SIZE_T NumberOfBytes);
typedef PVOID(*ExAllocatePoolWithTag_t)(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag);
typedef VOID(*ExFreePool_t)(PVOID P);
typedef VOID(*ExFreePoolWithTag_t)(PVOID P, ULONG Tag);

typedef NTSTATUS(*ZwAllocateVirtualMemory_t)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS(*ZwFreeVirtualMemory_t)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
typedef NTSTATUS(*ZwProtectVirtualMemory_t)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
typedef NTSTATUS(*ZwReadVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
typedef NTSTATUS(*ZwWriteVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);
typedef NTSTATUS(*ZwQueryVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
typedef NTSTATUS(*ZwLockVirtualMemory_t)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG MapType);
typedef NTSTATUS(*ZwUnlockVirtualMemory_t)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG MapType);

typedef NTSTATUS(*ObReferenceObjectByHandle_t)(HANDLE Handle, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID* Object, POBJECT_HANDLE_INFORMATION HandleInformation);
typedef NTSTATUS(*ObReferenceObjectByPointer_t)(PVOID Object, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode);
typedef VOID(*ObfDereferenceObject_t)(PVOID Object);
typedef NTSTATUS(*ObOpenObjectByPointer_t)(PVOID Object, ULONG HandleAttributes, PACCESS_STATE PassedAccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PHANDLE Handle);
typedef NTSTATUS(*ObQueryNameString_t)(PVOID Object, POBJECT_NAME_INFORMATION ObjectNameInfo, ULONG Length, PULONG ReturnLength);

typedef NTSTATUS(*IoCreateDevice_t)(PDRIVER_OBJECT DriverObject, ULONG DeviceExtensionSize, PUNICODE_STRING DeviceName, DEVICE_TYPE DeviceType, ULONG DeviceCharacteristics, BOOLEAN Exclusive, PDEVICE_OBJECT* DeviceObject);
typedef VOID(*IoDeleteDevice_t)(PDEVICE_OBJECT DeviceObject);
typedef NTSTATUS(*IoCreateSymbolicLink_t)(PUNICODE_STRING SymbolicLinkName, PUNICODE_STRING DeviceName);
typedef NTSTATUS(*IoDeleteSymbolicLink_t)(PUNICODE_STRING SymbolicLinkName);
typedef VOID(*IofCompleteRequest_t)(PIRP Irp, CCHAR PriorityBoost);
typedef PIO_STACK_LOCATION(*IoGetCurrentIrpStackLocation_t)(PIRP Irp);
typedef NTSTATUS(*IoGetDeviceObjectPointer_t)(PUNICODE_STRING ObjectName, ACCESS_MASK DesiredAccess, PFILE_OBJECT* FileObject, PDEVICE_OBJECT* DeviceObject);
typedef PDEVICE_OBJECT(*IoGetRelatedDeviceObject_t)(PFILE_OBJECT FileObject);
typedef PDEVICE_OBJECT(*IoGetAttachedDeviceReference_t)(PDEVICE_OBJECT DeviceObject);
typedef PDEVICE_OBJECT(*IoAttachDeviceToDeviceStack_t)(PDEVICE_OBJECT SourceDevice, PDEVICE_OBJECT TargetDevice);
typedef VOID(*IoDetachDevice_t)(PDEVICE_OBJECT TargetDevice);
typedef NTSTATUS(*IoCallDriver_t)(PDEVICE_OBJECT DeviceObject, PIRP Irp);
typedef NTSTATUS(*IofCallDriver_t)(PDEVICE_OBJECT DeviceObject, PIRP Irp);
typedef PIRP(*IoBuildDeviceIoControlRequest_t)(ULONG IoControlCode, PDEVICE_OBJECT DeviceObject, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, BOOLEAN InternalDeviceIoControl, PKEVENT Event, PIO_STATUS_BLOCK IoStatusBlock);
typedef PIRP(*IoBuildSynchronousFsdRequest_t)(ULONG MajorFunction, PDEVICE_OBJECT DeviceObject, PVOID Buffer, ULONG Length, PLARGE_INTEGER StartingOffset, PKEVENT Event, PIO_STATUS_BLOCK IoStatusBlock);

typedef NTSTATUS(*ZwCreateFile_t)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
typedef NTSTATUS(*ZwOpenFile_t)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
typedef NTSTATUS(*ZwReadFile_t)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
typedef NTSTATUS(*ZwWriteFile_t)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
typedef NTSTATUS(*ZwClose_t)(HANDLE Handle);
typedef NTSTATUS(*ZwQueryInformationFile_t)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
typedef NTSTATUS(*ZwSetInformationFile_t)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
typedef NTSTATUS(*ZwDeleteFile_t)(POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS(*ZwCreateKey_t)(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition);
typedef NTSTATUS(*ZwOpenKey_t)(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS(*ZwDeleteKey_t)(HANDLE KeyHandle);
typedef NTSTATUS(*ZwQueryValueKey_t)(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);
typedef NTSTATUS(*ZwSetValueKey_t)(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize);
typedef NTSTATUS(*ZwDeleteValueKey_t)(HANDLE KeyHandle, PUNICODE_STRING ValueName);
typedef NTSTATUS(*ZwEnumerateKey_t)(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);
typedef NTSTATUS(*ZwEnumerateValueKey_t)(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);

typedef VOID(*KeInitializeEvent_t)(PRKEVENT Event, EVENT_TYPE Type, BOOLEAN State);
typedef LONG(*KeSetEvent_t)(PRKEVENT Event, KPRIORITY Increment, BOOLEAN Wait);
typedef LONG(*KeResetEvent_t)(PRKEVENT Event);
typedef VOID(*KeClearEvent_t)(PRKEVENT Event);
typedef NTSTATUS(*KeWaitForSingleObject_t)(PVOID Object, KWAIT_REASON WaitReason, KPROCESSOR_MODE WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
typedef NTSTATUS(*KeWaitForMultipleObjects_t)(ULONG Count, PVOID Object[], WAIT_TYPE WaitType, KWAIT_REASON WaitReason, KPROCESSOR_MODE WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Timeout, PKWAIT_BLOCK WaitBlockArray);

typedef VOID(*KeInitializeMutex_t)(PRKMUTEX Mutex, ULONG Level);
typedef LONG(*KeReleaseMutex_t)(PRKMUTEX Mutex, BOOLEAN Wait);

typedef VOID(*KeInitializeSemaphore_t)(PRKSEMAPHORE Semaphore, LONG Count, LONG Limit);
typedef LONG(*KeReleaseSemaphore_t)(PRKSEMAPHORE Semaphore, KPRIORITY Increment, LONG Adjustment, BOOLEAN Wait);

typedef VOID(*KeInitializeSpinLock_t)(PKSPIN_LOCK SpinLock);
typedef VOID(*KeAcquireSpinLock_t)(PKSPIN_LOCK SpinLock, PKIRQL OldIrql);
typedef VOID(*KeReleaseSpinLock_t)(PKSPIN_LOCK SpinLock, KIRQL NewIrql);
typedef VOID(*KeAcquireSpinLockAtDpcLevel_t)(PKSPIN_LOCK SpinLock);
typedef VOID(*KeReleaseSpinLockFromDpcLevel_t)(PKSPIN_LOCK SpinLock);

typedef VOID(*KeInitializeDpc_t)(PRKDPC Dpc, PKDEFERRED_ROUTINE DeferredRoutine, PVOID DeferredContext);
typedef BOOLEAN(*KeInsertQueueDpc_t)(PRKDPC Dpc, PVOID SystemArgument1, PVOID SystemArgument2);
typedef BOOLEAN(*KeRemoveQueueDpc_t)(PRKDPC Dpc);
typedef VOID(*KeInitializeTimer_t)(PKTIMER Timer);
typedef BOOLEAN(*KeSetTimer_t)(PKTIMER Timer, LARGE_INTEGER DueTime, PKDPC Dpc);
typedef BOOLEAN(*KeCancelTimer_t)(PKTIMER Timer);

typedef VOID(*KeInitializeApc_t)(PRKAPC Apc, PETHREAD Thread, KAPC_ENVIRONMENT Environment, PKKERNEL_ROUTINE KernelRoutine, PKRUNDOWN_ROUTINE RundownRoutine, PKNORMAL_ROUTINE NormalRoutine, KPROCESSOR_MODE ApcMode, PVOID NormalContext);
typedef BOOLEAN(*KeInsertQueueApc_t)(PRKAPC Apc, PVOID SystemArgument1, PVOID SystemArgument2, KPRIORITY Increment);
typedef BOOLEAN(*KeTestAlertThread_t)(KPROCESSOR_MODE AlertMode);

typedef KIRQL(*KeGetCurrentIrql_t)(VOID);
typedef KIRQL(*KfRaiseIrql_t)(KIRQL NewIrql);
typedef VOID(*KeLowerIrql_t)(KIRQL NewIrql);

typedef ULONG(*KeGetCurrentProcessorIndex_t)(VOID);
typedef VOID(*KeSetSystemAffinityThread_t)(KAFFINITY Affinity);
typedef VOID(*KeRevertToUserAffinityThread_t)(VOID);
typedef ULONG(*KeQueryActiveProcessorCount_t)(PKAFFINITY ActiveProcessors);

typedef VOID(*RtlInitUnicodeString_t)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef BOOLEAN(*RtlEqualUnicodeString_t)(PUNICODE_STRING String1, PUNICODE_STRING String2, BOOLEAN CaseInSensitive);
typedef LONG(*RtlCompareUnicodeString_t)(PUNICODE_STRING String1, PUNICODE_STRING String2, BOOLEAN CaseInSensitive);
typedef VOID(*RtlCopyUnicodeString_t)(PUNICODE_STRING DestinationString, PUNICODE_STRING SourceString);
typedef NTSTATUS(*RtlAppendUnicodeStringToString_t)(PUNICODE_STRING Destination, PUNICODE_STRING Source);
typedef NTSTATUS(*RtlAppendUnicodeToString_t)(PUNICODE_STRING Destination, PCWSTR Source);
typedef VOID(*RtlFreeUnicodeString_t)(PUNICODE_STRING UnicodeString);
typedef NTSTATUS(*RtlUnicodeStringToAnsiString_t)(PANSI_STRING DestinationString, PUNICODE_STRING SourceString, BOOLEAN AllocateDestinationString);
typedef NTSTATUS(*RtlAnsiStringToUnicodeString_t)(PUNICODE_STRING DestinationString, PCANSI_STRING SourceString, BOOLEAN AllocateDestinationString);
typedef VOID(*RtlInitAnsiString_t)(PANSI_STRING DestinationString, PCSZ SourceString);
typedef SIZE_T(*RtlCompareMemory_t)(const VOID* Source1, const VOID* Source2, SIZE_T Length);
typedef VOID(*RtlCopyMemory_t)(VOID* Destination, const VOID* Source, SIZE_T Length);
typedef VOID(*RtlZeroMemory_t)(VOID* Destination, SIZE_T Length);
typedef VOID(*RtlFillMemory_t)(VOID* Destination, SIZE_T Length, UCHAR Fill);

typedef NTSTATUS(*ZwQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(*ZwSetSystemInformation_t)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength);
typedef NTSTATUS(*ZwQueryInformationProcess_t)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
typedef NTSTATUS(*ZwSetInformationProcess_t)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
typedef NTSTATUS(*ZwQueryInformationThread_t)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
typedef NTSTATUS(*ZwSetInformationThread_t)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);

typedef NTSTATUS(*ZwCreateSection_t)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
typedef NTSTATUS(*ZwOpenSection_t)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS(*ZwMapViewOfSection_t)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
typedef NTSTATUS(*ZwUnmapViewOfSection_t)(HANDLE ProcessHandle, PVOID BaseAddress);

typedef NTSTATUS(*ZwDuplicateObject_t)(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);
typedef NTSTATUS(*ZwQueryObject_t)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);

typedef BOOLEAN(*SeAccessCheck_t)(PSECURITY_DESCRIPTOR SecurityDescriptor, PSECURITY_SUBJECT_CONTEXT SubjectSecurityContext, BOOLEAN SubjectContextLocked, ACCESS_MASK DesiredAccess, ACCESS_MASK PreviouslyGrantedAccess, PPRIVILEGE_SET* Privileges, PGENERIC_MAPPING GenericMapping, KPROCESSOR_MODE AccessMode, PACCESS_MASK GrantedAccess, PNTSTATUS AccessStatus);
typedef BOOLEAN(*SeSinglePrivilegeCheck_t)(LUID PrivilegeValue, KPROCESSOR_MODE PreviousMode);

typedef NTSTATUS(*ZwLoadDriver_t)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(*ZwUnloadDriver_t)(PUNICODE_STRING DriverServiceName);

typedef VOID(*ExEnterCriticalRegionAndAcquireResourceExclusive_t)(PERESOURCE Resource);
typedef VOID(*ExReleaseResourceAndLeaveCriticalRegion_t)(PERESOURCE Resource);

typedef LONG(*InterlockedExchange_t)(LONG volatile* Target, LONG Value);
typedef LONG(*InterlockedCompareExchange_t)(LONG volatile* Destination, LONG Exchange, LONG Comparand);
typedef LONG(*InterlockedIncrement_t)(LONG volatile* Addend);
typedef LONG(*InterlockedDecrement_t)(LONG volatile* Addend);
typedef PVOID(*_InterlockedExchangePointer_t)(volatile PVOID* Target, PVOID Value);

typedef ULONG(*DbgPrint_t)(PCCH Format, ...);
typedef ULONG(*DbgPrintEx_t)(ULONG ComponentId, ULONG Level, PCCH Format, ...);

typedef KPROCESSOR_MODE(*PEX_GET_PREVIOUS_MODE)(VOID);

typedef NTSTATUS(*PsCreateSystemThread_t)(
    PHANDLE ThreadHandle,
    ULONG DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PCLIENT_ID ClientId,
    PKSTART_ROUTINE StartRoutine,
    PVOID StartContext

    );

typedef PEPROCESS(*IoGetCurrentProcess_t)(VOID);

typedef NTSTATUS(*PsTerminateSystemThread_t)(NTSTATUS);


struct {
    POBJECT_TYPE* PsThreadType_t;
    PsTerminateSystemThread_t PsTerminateSystemThread;
    IoGetCurrentProcess_t IoGetCurrentProcess;
    RtlInitUnicodeString_t RtlInitUnicodeString;
    PsCreateSystemThread_t PsCreateSystemThread;
    RtlEqualUnicodeString_t RtlEqualUnicodeString;
    RtlCompareUnicodeString_t RtlCompareUnicodeString;
    RtlCopyUnicodeString_t RtlCopyUnicodeString;
    RtlAppendUnicodeStringToString_t RtlAppendUnicodeStringToString;
    RtlAppendUnicodeToString_t RtlAppendUnicodeToString;
    RtlFreeUnicodeString_t RtlFreeUnicodeString;
    RtlUnicodeStringToAnsiString_t RtlUnicodeStringToAnsiString;
    RtlAnsiStringToUnicodeString_t RtlAnsiStringToUnicodeString;
    RtlInitAnsiString_t RtlInitAnsiString;
    RtlCompareMemory_t RtlCompareMemory;
    RtlCopyMemory_t RtlCopyMemory;
    RtlZeroMemory_t RtlZeroMemory;
    RtlFillMemory_t RtlFillMemory;

    PsLookupProcessByProcessId_t PsLookupProcessByProcessId;
    PsGetCurrentProcess_t PsGetCurrentProcess_;
    PsGetCurrentProcessId_t PsGetCurrentProcessId;
    PsGetProcessId_t PsGetProcessId;
    PsGetProcessImageFileName_t PsGetProcessImageFileName;
    PsGetProcessSectionBaseAddress_t PsGetProcessSectionBaseAddress;
    PsIsProtectedProcess_t PsIsProtectedProcess;
    PsGetProcessPeb_t PsGetProcessPeb;
    PsGetProcessWow64Process_t PsGetProcessWow64Process;
    PsGetProcessCreateTimeQuadPart_t PsGetProcessCreateTimeQuadPart;
    PsGetProcessExitTime_t PsGetProcessExitTime;
    PsTerminateProcess_t PsTerminateProcess;
    PsSuspendProcess_t PsSuspendProcess;
    PsResumeProcess_t PsResumeProcess;

    PsGetCurrentThread_t PsGetCurrentThread;
    PsGetCurrentThreadId_t PsGetCurrentThreadId;
    PsLookupThreadByThreadId_t PsLookupThreadByThreadId;
    PsGetThreadId_t PsGetThreadId;
    KeStackAttachProcess_t KeStackAttachProcess;
    KeUnstackDetachProcess_t KeUnstackDetachProcess;

    MmCopyMemory_t MmCopyMemory;
    MmIsAddressValid_t MmIsAddressValid;
    MmCopyVirtualMemory_t MmCopyVirtualMemory;
    MmAllocateContiguousMemory_t MmAllocateContiguousMemory;
    MmAllocateContiguousMemorySpecifyCache_t MmAllocateContiguousMemorySpecifyCache;
    MmFreeContiguousMemory_t MmFreeContiguousMemory;
    MmAllocatePagesForMdl_t MmAllocatePagesForMdl;
    MmFreePagesFromMdl_t MmFreePagesFromMdl;
    MmGetPhysicalAddress_t MmGetPhysicalAddress;
    MmGetVirtualForPhysical_t MmGetVirtualForPhysical;
    MmGetPhysicalMemoryRanges_t MmGetPhysicalMemoryRanges;
    MmMapIoSpace_t MmMapIoSpace;
    MmMapIoSpaceEx_t MmMapIoSpaceEx;
    MmUnmapIoSpace_t MmUnmapIoSpace;
    MmSecureVirtualMemory_t MmSecureVirtualMemory;
    MmUnsecureVirtualMemory_t MmUnsecureVirtualMemory;
    MmGetSystemRoutineAddress_t MmGetSystemRoutineAddress;

    IoAllocateMdl_t IoAllocateMdl;
    IoFreeMdl_t IoFreeMdl;
    MmProbeAndLockPages_t MmProbeAndLockPages;
    MmUnlockPages_t MmUnlockPages;
    MmGetMdlPfnArray_t MmGetMdlPfnArray;
    MmMapLockedPages_t MmMapLockedPages;
    PMM_MAP_LOCKED_PAGES_SPECIFY_CACHE MmMapLockedPagesSpecifyCache;
    PMM_UNMAP_LOCKED_PAGES MmUnmapLockedPages;
    PMM_PROTECT_MDL_SYSTEM_ADDRESS MmProtectMdlSystemAddress;
    MmBuildMdlForNonPagedPool_t MmBuildMdlForNonPagedPool;

    ExAllocatePool_t ExAllocatePool;
    ExAllocatePoolWithTag_t ExAllocatePoolWithTag;
    ExFreePool_t ExFreePool;
    ExFreePoolWithTag_t ExFreePoolWithTag;

    ZwAllocateVirtualMemory_t ZwAllocateVirtualMemory;
    ZwFreeVirtualMemory_t ZwFreeVirtualMemory;
    ZwProtectVirtualMemory_t ZwProtectVirtualMemory;
    ZwReadVirtualMemory_t ZwReadVirtualMemory;
    ZwWriteVirtualMemory_t ZwWriteVirtualMemory;
    ZwQueryVirtualMemory_t ZwQueryVirtualMemory;
    ZwLockVirtualMemory_t ZwLockVirtualMemory;
    ZwUnlockVirtualMemory_t ZwUnlockVirtualMemory;

    ObReferenceObjectByHandle_t ObReferenceObjectByHandle;
    ObReferenceObjectByPointer_t ObReferenceObjectByPointer;
    ObfDereferenceObject_t ObfDereferenceObject;
    ObOpenObjectByPointer_t ObOpenObjectByPointer;
    ObQueryNameString_t ObQueryNameString;

    IoCreateDevice_t IoCreateDevice;
    IoDeleteDevice_t IoDeleteDevice;
    IoCreateSymbolicLink_t IoCreateSymbolicLink;
    IoDeleteSymbolicLink_t IoDeleteSymbolicLink;
    IofCompleteRequest_t IofCompleteRequest;
    IoGetCurrentIrpStackLocation_t IoGetCurrentIrpStackLocation;
    IoGetDeviceObjectPointer_t IoGetDeviceObjectPointer;
    IoGetRelatedDeviceObject_t IoGetRelatedDeviceObject;
    IoGetAttachedDeviceReference_t IoGetAttachedDeviceReference;
    IoAttachDeviceToDeviceStack_t IoAttachDeviceToDeviceStack;
    IoDetachDevice_t IoDetachDevice;
    IoCallDriver_t IoCallDriver;
    IofCallDriver_t IofCallDriver;
    IoBuildDeviceIoControlRequest_t IoBuildDeviceIoControlRequest;
    IoBuildSynchronousFsdRequest_t IoBuildSynchronousFsdRequest;

    ZwCreateFile_t ZwCreateFile;
    ZwOpenFile_t ZwOpenFile;
    ZwReadFile_t ZwReadFile;
    ZwWriteFile_t ZwWriteFile;
    ZwClose_t ZwClose;
    ZwQueryInformationFile_t ZwQueryInformationFile;
    ZwSetInformationFile_t ZwSetInformationFile;
    ZwDeleteFile_t ZwDeleteFile;

    ZwCreateKey_t ZwCreateKey;
    ZwOpenKey_t ZwOpenKey;
    ZwDeleteKey_t ZwDeleteKey;
    ZwQueryValueKey_t ZwQueryValueKey;
    ZwSetValueKey_t ZwSetValueKey;
    ZwDeleteValueKey_t ZwDeleteValueKey;
    ZwEnumerateKey_t ZwEnumerateKey;
    ZwEnumerateValueKey_t ZwEnumerateValueKey;

    KeInitializeEvent_t KeInitializeEvent;
    KeSetEvent_t KeSetEvent;
    KeResetEvent_t KeResetEvent;
    KeClearEvent_t KeClearEvent;
    KeWaitForSingleObject_t KeWaitForSingleObject;
    KeWaitForMultipleObjects_t KeWaitForMultipleObjects;

    KeInitializeMutex_t KeInitializeMutex;
    KeReleaseMutex_t KeReleaseMutex;

    KeInitializeSemaphore_t KeInitializeSemaphore;
    KeReleaseSemaphore_t KeReleaseSemaphore;

    KeInitializeSpinLock_t KeInitializeSpinLock;
    KeAcquireSpinLock_t KeAcquireSpinLock;
    KeReleaseSpinLock_t KeReleaseSpinLock;
    KeAcquireSpinLockAtDpcLevel_t KeAcquireSpinLockAtDpcLevel;
    KeReleaseSpinLockFromDpcLevel_t KeReleaseSpinLockFromDpcLevel;

    KeInitializeDpc_t KeInitializeDpc;
    KeInsertQueueDpc_t KeInsertQueueDpc;
    KeRemoveQueueDpc_t KeRemoveQueueDpc;
    KeInitializeTimer_t KeInitializeTimer;
    KeSetTimer_t KeSetTimer;
    KeCancelTimer_t KeCancelTimer;

    KeInitializeApc_t KeInitializeApc;
    KeInsertQueueApc_t KeInsertQueueApc;
    KeTestAlertThread_t KeTestAlertThread;

    KeGetCurrentIrql_t KeGetCurrentIrql;
    KfRaiseIrql_t KfRaiseIrql;
    KeLowerIrql_t KeLowerIrql;

    KeGetCurrentProcessorIndex_t KeGetCurrentProcessorIndex;
    KeSetSystemAffinityThread_t KeSetSystemAffinityThread;
    KeRevertToUserAffinityThread_t KeRevertToUserAffinityThread;
    KeQueryActiveProcessorCount_t KeQueryActiveProcessorCount;

    ZwQuerySystemInformation_t ZwQuerySystemInformation;
    ZwSetSystemInformation_t ZwSetSystemInformation;
    ZwQueryInformationProcess_t ZwQueryInformationProcess;
    ZwSetInformationProcess_t ZwSetInformationProcess;
    ZwQueryInformationThread_t ZwQueryInformationThread;
    ZwSetInformationThread_t ZwSetInformationThread;

    ZwCreateSection_t ZwCreateSection;
    ZwOpenSection_t ZwOpenSection;
    ZwMapViewOfSection_t ZwMapViewOfSection;
    ZwUnmapViewOfSection_t ZwUnmapViewOfSection;

    ZwDuplicateObject_t ZwDuplicateObject;
    ZwQueryObject_t ZwQueryObject;

    SeAccessCheck_t SeAccessCheck;
    SeSinglePrivilegeCheck_t SeSinglePrivilegeCheck;

    ZwLoadDriver_t ZwLoadDriver;
    ZwUnloadDriver_t ZwUnloadDriver;

    ExEnterCriticalRegionAndAcquireResourceExclusive_t ExEnterCriticalRegionAndAcquireResourceExclusive;
    ExReleaseResourceAndLeaveCriticalRegion_t ExReleaseResourceAndLeaveCriticalRegion;

    InterlockedExchange_t InterlockedExchange;
    InterlockedCompareExchange_t InterlockedCompareExchange;
    InterlockedIncrement_t InterlockedIncrement;
    InterlockedDecrement_t InterlockedDecrement;
    _InterlockedExchangePointer_t _InterlockedExchangePointer;

    DbgPrint_t DbgPrint;
    DbgPrintEx_t DbgPrintEx;

    PEX_GET_PREVIOUS_MODE ExGetPreviousMode;
} func_ptrs;

#endif // !FUNCTION_SIGNATURES_H

