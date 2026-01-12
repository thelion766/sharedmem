#include <intrin.h>
#include <ntifs.h>

#ifndef STRUCTURES_H
#define STRUCTURES_H



constexpr auto obj_kernel_handle = 0x00000200L;
constexpr auto obj_case_insensitive = 0x00000040L;

constexpr auto section_all_access = 0xF001F;
constexpr auto process_all_access = 0x1F0FFF;
constexpr auto thread_all_access = 0x1F03FF;
constexpr auto page_execute_readwrite = 0x40;
constexpr auto sec_image = 0x1000000;

constexpr auto ps_attribute_image_info = 3;
constexpr auto ps_attribute_image_section = 4;

namespace std
{
    using int8_t = signed char;
    using int16_t = short;
    using int32_t = int;
    using int64_t = long long;
    using uint8_t = unsigned char;
    using uint16_t = unsigned short;
    using uint32_t = unsigned int;
    using uint64_t = unsigned long long;

    using int_least8_t = signed char;
    using int_least16_t = short;
    using int_least32_t = int;
    using int_least64_t = long long;
    using uint_least8_t = unsigned char;
    using uint_least16_t = unsigned short;
    using uint_least32_t = unsigned int;
    using uint_least64_t = unsigned long long;

    using int_fast8_t = signed char;
    using int_fast16_t = int;
    using int_fast32_t = int;
    using int_fast64_t = long long;
    using uint_fast8_t = unsigned char;
    using uint_fast16_t = unsigned int;
    using uint_fast32_t = unsigned int;
    using uint_fast64_t = unsigned long long;

    using uintptr_t = unsigned long long;
    using size_t = unsigned long long;
    using intmax_t = long long;
    using uintmax_t = long long;
    using ptrdiff_t = long long;

    using addr_t = unsigned char*;
    using double_t = double;
    using float_t = float;

    struct m128a_t {
        std::uint64_t m_low;
        std::int64_t m_high;
    };

    struct uint128_t {
        std::uint64_t m_low;     // Lower 64 bits
        std::uint64_t m_high;    // Upper 64 bits

        uint128_t() : m_low(0), m_high(0) {}
        uint128_t(std::uint64_t low, std::uint64_t high) :
            m_low(low), m_high(high) {
        }

        bool operator==(const uint128_t& other) const {
            return m_low == other.m_low && m_high == other.m_high;
        }

        bool operator!=(const uint128_t& other) const {
            return !(*this == other);
        }

        uint128_t& operator=(std::uint64_t value) {
            m_low = value;
            m_high = 0;
            return *this;
        }
    };
}

#define containing_record(address, type, field) ((type *)( \
                                                  (char*)(address) - \
                                                  (std::size_t)(&((type *)0)->field)))


enum nt_status_t {
    success,
    unsuccessful = 0xc1,
    alerted = 0x101,
    timeout = 0x102,
    pending = 0x103,
    control_c_exit = 0xc000013a,
    info_length_mismatch = 0xc4l,
    insufficient_resources = 0xc9A,
    length_mismatch = 0xc4,
    invalid_parameter = 0xcd,
    access_violation = 0xc5
};

enum nt_build_t {
    win11_23h2 = 0x589c,
    win11_22h2 = 0x585d,
    win11_21h2 = 0x55f0,
    win10_22h2 = 0x5a63,
    win10_21h1 = 0x4fc6,
    win10_20h2 = 0x4ec2,
    win10_20h1 = 0x4a61,
    win_server_2022 = 0x5900,
    win_server_2019 = 0x3c5a,
    win_server_2016 = 0x23f0,
    win8_1_update = 0x1db0,
    win8_1 = 0x1a2b,
    win7_sp1 = 0x1db1,
    win7_rtm = 0x1a28
};

enum pe_magic_t {
    dos_header = 0x5a4d,
    nt_headers = 0x4550,
    opt_header = 0x020b
};

struct unicode_string_t {
    std::uint16_t m_length;
    std::uint16_t m_maximum_length;
    wchar_t* m_buffer;
};

struct dos_header_t {
    std::int16_t m_magic;
    std::int16_t m_cblp;
    std::int16_t m_cp;
    std::int16_t m_crlc;
    std::int16_t m_cparhdr;
    std::int16_t m_minalloc;
    std::int16_t m_maxalloc;
    std::int16_t m_ss;
    std::int16_t m_sp;
    std::int16_t m_csum;
    std::int16_t m_ip;
    std::int16_t m_cs;
    std::int16_t m_lfarlc;
    std::int16_t m_ovno;
    std::int16_t m_res0[0x4];
    std::int16_t m_oemid;
    std::int16_t m_oeminfo;
    std::int16_t m_res1[0xa];
    std::int32_t m_lfanew;

    [[ nodiscard ]]
    constexpr bool is_valid() {
        return m_magic == pe_magic_t::dos_header;
    }
};

struct data_directory_t {
    std::int32_t m_virtual_address;
    std::int32_t m_size;

    template< class type_t >
    [[ nodiscard ]]
    type_t as_rva(
        std::uintptr_t rva
    ) {
        return reinterpret_cast<type_t>(rva + m_virtual_address);
    }
};

struct import_descriptor_t {
    union {
        std::uint32_t m_characteristics;
        std::uint32_t m_original_first_thunk;
    };
    std::uint32_t m_time_date_stamp;
    std::uint32_t m_forwarder_chain;
    std::uint32_t m_name;
    std::uint32_t m_first_thunk;
};

struct nt_headers_t {
    std::int32_t m_signature;
    std::int16_t m_machine;
    std::int16_t m_number_of_sections;
    std::int32_t m_time_date_stamp;
    std::int32_t m_pointer_to_symbol_table;
    std::int32_t m_number_of_symbols;
    std::int16_t m_size_of_optional_header;
    std::int16_t m_characteristics;

    std::int16_t m_magic;
    std::int8_t m_major_linker_version;
    std::int8_t m_minor_linker_version;
    std::int32_t m_size_of_code;
    std::int32_t m_size_of_initialized_data;
    std::int32_t m_size_of_uninitialized_data;
    std::int32_t m_address_of_entry_point;
    std::int32_t m_base_of_code;
    std::uint64_t m_image_base;
    std::int32_t m_section_alignment;
    std::int32_t m_file_alignment;
    std::int16_t m_major_operating_system_version;
    std::int16_t m_minor_operating_system_version;
    std::int16_t m_major_image_version;
    std::int16_t m_minor_image_version;
    std::int16_t m_major_subsystem_version;
    std::int16_t m_minor_subsystem_version;
    std::int32_t m_win32_version_value;
    std::int32_t m_size_of_image;
    std::int32_t m_size_of_headers;
    std::int32_t m_check_sum;
    std::int16_t m_subsystem;
    std::int16_t m_dll_characteristics;
    std::uint64_t m_size_of_stack_reserve;
    std::uint64_t m_size_of_stack_commit;
    std::uint64_t m_size_of_heap_reserve;
    std::uint64_t m_size_of_heap_commit;
    std::int32_t m_loader_flags;
    std::int32_t m_number_of_rva_and_sizes;

    data_directory_t m_export_table;
    data_directory_t m_import_table;
    data_directory_t m_resource_table;
    data_directory_t m_exception_table;
    data_directory_t m_certificate_table;
    data_directory_t m_base_relocation_table;
    data_directory_t m_debug;
    data_directory_t m_architecture;
    data_directory_t m_global_ptr;
    data_directory_t m_tls_table;
    data_directory_t m_load_config_table;
    data_directory_t m_bound_import;
    data_directory_t m_iat;
    data_directory_t m_delay_import_descriptor;
    data_directory_t m_clr_runtime_header;
    data_directory_t m_reserved;

    [[ nodiscard ]]
    constexpr bool is_valid() {
        return m_signature == pe_magic_t::nt_headers
            && m_magic == pe_magic_t::opt_header;
    }
};

struct export_directory_t {
    std::int32_t m_characteristics;
    std::int32_t m_time_date_stamp;
    std::int16_t m_major_version;
    std::int16_t m_minor_version;
    std::int32_t m_name;
    std::int32_t m_base;
    std::int32_t m_number_of_functions;
    std::int32_t m_number_of_names;
    std::int32_t m_address_of_functions;
    std::int32_t m_address_of_names;
    std::int32_t m_address_of_names_ordinals;
};

struct section_header_t {
    char m_name[0x8];
    union {
        std::int32_t m_physical_address;
        std::int32_t m_virtual_size;
    };
    std::int32_t m_virtual_address;
    std::int32_t m_size_of_raw_data;
    std::int32_t m_pointer_to_raw_data;
    std::int32_t m_pointer_to_relocations;
    std::int32_t m_pointer_to_line_numbers;
    std::int16_t m_number_of_relocations;
    std::int16_t m_number_of_line_numbers;
    std::int32_t m_characteristics;
};

typedef struct _memory_basic_information {
    void* m_base_address;          // Base address of the region
    void* m_allocation_base;       // Base address of allocated range
    std::uint32_t   m_allocation_protect;    // Initial access protection
    std::uint32_t   m_partition_id;         // Data partition ID
    std::uint64_t   m_region_size;          // Size of the region in bytes
    std::uint32_t   m_state;                // Committed, reserved, or free
    std::uint32_t   m_protect;              // Current access protection
    std::uint32_t   m_type;                 // Type of pages
} memory_basic_information, * pmemory_basic_information;

struct list_entry_t {
    list_entry_t* m_flink;
    list_entry_t* m_blink;
};



enum pe_characteristics_t : std::uint16_t {
    pe_relocs_stripped = 0x0001,
    pe_executable = 0x0002,
    pe_line_nums_stripped = 0x0004,
    pe_local_syms_stripped = 0x0008,
    pe_aggressive_ws_trim = 0x0010,
    pe_large_address_aware = 0x0020,
    pe_bytes_reversed_lo = 0x0080,
    pe_32bit_machine = 0x0100,
    pe_debug_stripped = 0x0200,
    pe_removable_run_from_swap = 0x0400,
    pe_net_run_from_swap = 0x0800,
    pe_system = 0x1000,
    pe_dll = 0x2000,
    pe_up_system_only = 0x4000,
    pe_bytes_reversed_hi = 0x8000
};

enum view_share_t : std::uint32_t {
    view_share = 1,
    view_unmap = 2
};

enum allocation_type_t : std::uint32_t {
    mem_commit = 0x1000,
    mem_reserve = 0x2000,
    mem_reset = 0x80000,
    mem_large_pages = 0x20000000,
    mem_physical = 0x400000,
    mem_top_down = 0x100000,
    mem_write_watch = 0x200000
};

struct kspin_lock_t {
    volatile long m_lock; // +0x000
};


typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef VOID(*PKNORMAL_ROUTINE)(
    IN PVOID NormalContext,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2);

typedef VOID(*PKKERNEL_ROUTINE)(
    IN PKAPC Apc,
    IN OUT PKNORMAL_ROUTINE* NormalRoutine,
    IN OUT PVOID* NormalContext,
    IN OUT PVOID* SystemArgument1,
    IN OUT PVOID* SystemArgument2);

typedef VOID(*PKRUNDOWN_ROUTINE)(
    IN  PKAPC Apc);



typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation,                                 // q: SYSTEM_BASIC_INFORMATION
    SystemProcessorInformation,                             // q: SYSTEM_PROCESSOR_INFORMATION
    SystemPerformanceInformation,                           // q: SYSTEM_PERFORMANCE_INFORMATION
    SystemTimeOfDayInformation,                             // q: SYSTEM_TIMEOFDAY_INFORMATION
    SystemPathInformation,                                  // q: not implemented
    SystemProcessInformation,                               // q: SYSTEM_PROCESS_INFORMATION
    SystemCallCountInformation,                             // q: SYSTEM_CALL_COUNT_INFORMATION
    SystemDeviceInformation,                                // q: SYSTEM_DEVICE_INFORMATION
    SystemProcessorPerformanceInformation,                  // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemFlagsInformation,                                 // qs: SYSTEM_FLAGS_INFORMATION
    SystemCallTimeInformation,                              // q: SYSTEM_CALL_TIME_INFORMATION // not implemented // 10
    SystemModuleInformation,                                // q: RTL_PROCESS_MODULES
    SystemLocksInformation,                                 // q: RTL_PROCESS_LOCKS
    SystemStackTraceInformation,                            // q: RTL_PROCESS_BACKTRACES
    SystemPagedPoolInformation,                             // q: not implemented
    SystemNonPagedPoolInformation,                          // q: not implemented
    SystemHandleInformation,                                // q: SYSTEM_HANDLE_INFORMATION
    SystemObjectInformation,                                // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
    SystemPageFileInformation,                              // q: SYSTEM_PAGEFILE_INFORMATION
    SystemVdmInstemulInformation,                           // q: SYSTEM_VDM_INSTEMUL_INFO
    SystemVdmBopInformation,                                // q: not implemented // 20
    SystemFileCacheInformation,                             // qs: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
    SystemPoolTagInformation,                               // q: SYSTEM_POOLTAG_INFORMATION
    SystemInterruptInformation,                             // q: SYSTEM_INTERRUPT_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemDpcBehaviorInformation,                           // qs: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
    SystemFullMemoryInformation,                            // q: SYSTEM_MEMORY_USAGE_INFORMATION // not implemented
    SystemLoadGdiDriverInformation,                         // s: (kernel-mode only)
    SystemUnloadGdiDriverInformation,                       // s: (kernel-mode only)
    SystemTimeAdjustmentInformation,                        // qs: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
    SystemSummaryMemoryInformation,                         // q: SYSTEM_MEMORY_USAGE_INFORMATION // not implemented
    SystemMirrorMemoryInformation,                          // qs: (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
    SystemPerformanceTraceInformation,                      // qs: (type depends on EVENT_TRACE_INFORMATION_CLASS)
    SystemObsolete0,                                        // q: not implemented
    SystemExceptionInformation,                             // q: SYSTEM_EXCEPTION_INFORMATION
    SystemCrashDumpStateInformation,                        // s: SYSTEM_CRASH_DUMP_STATE_INFORMATION (requires SeDebugPrivilege)
    SystemKernelDebuggerInformation,                        // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
    SystemContextSwitchInformation,                         // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
    SystemRegistryQuotaInformation,                         // qs: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
    SystemExtendServiceTableInformation,                    // s: (requires SeLoadDriverPrivilege) // loads win32k only
    SystemPrioritySeparation,                               // s: (requires SeTcbPrivilege)
    SystemVerifierAddDriverInformation,                     // s: UNICODE_STRING (requires SeDebugPrivilege) // 40
    SystemVerifierRemoveDriverInformation,                  // s: UNICODE_STRING (requires SeDebugPrivilege)
    SystemProcessorIdleInformation,                         // q: SYSTEM_PROCESSOR_IDLE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemLegacyDriverInformation,                          // q: SYSTEM_LEGACY_DRIVER_INFORMATION
    SystemCurrentTimeZoneInformation,                       // qs: RTL_TIME_ZONE_INFORMATION
    SystemLookasideInformation,                             // q: SYSTEM_LOOKASIDE_INFORMATION
    SystemTimeSlipNotification,                             // s: HANDLE (NtCreateEvent) (requires SeSystemtimePrivilege)
    SystemSessionCreate,                                    // q: not implemented
    SystemSessionDetach,                                    // q: not implemented
    SystemSessionInformation,                               // q: not implemented (SYSTEM_SESSION_INFORMATION)
    SystemRangeStartInformation,                            // q: SYSTEM_RANGE_START_INFORMATION // 50
    SystemVerifierInformation,                              // qs: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
    SystemVerifierThunkExtend,                              // qs: (kernel-mode only)
    SystemSessionProcessInformation,                        // q: SYSTEM_SESSION_PROCESS_INFORMATION
    SystemLoadGdiDriverInSystemSpace,                       // qs: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only) (same as SystemLoadGdiDriverInformation)
    SystemNumaProcessorMap,                                 // q: SYSTEM_NUMA_INFORMATION
    SystemPrefetcherInformation,                            // qs: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
    SystemExtendedProcessInformation,                       // q: SYSTEM_EXTENDED_PROCESS_INFORMATION
    SystemRecommendedSharedDataAlignment,                   // q: ULONG // KeGetRecommendedSharedDataAlignment
    SystemComPlusPackage,                                   // qs: ULONG
    SystemNumaAvailableMemory,                              // q: SYSTEM_NUMA_INFORMATION // 60
    SystemProcessorPowerInformation,                        // q: SYSTEM_PROCESSOR_POWER_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemEmulationBasicInformation,                        // q: SYSTEM_BASIC_INFORMATION
    SystemEmulationProcessorInformation,                    // q: SYSTEM_PROCESSOR_INFORMATION
    SystemExtendedHandleInformation,                        // q: SYSTEM_HANDLE_INFORMATION_EX
    SystemLostDelayedWriteInformation,                      // q: ULONG
    SystemBigPoolInformation,                               // q: SYSTEM_BIGPOOL_INFORMATION
    SystemSessionPoolTagInformation,                        // q: SYSTEM_SESSION_POOLTAG_INFORMATION
    SystemSessionMappedViewInformation,                     // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
    SystemHotpatchInformation,                              // qs: SYSTEM_HOTPATCH_CODE_INFORMATION
    SystemObjectSecurityMode,                               // q: ULONG // 70
    SystemWatchdogTimerHandler,                             // s: SYSTEM_WATCHDOG_HANDLER_INFORMATION // (kernel-mode only)
    SystemWatchdogTimerInformation,                         // qs: out: SYSTEM_WATCHDOG_TIMER_INFORMATION (EX in: ULONG WATCHDOG_INFORMATION_CLASS) // NtQuerySystemInformationEx
    SystemLogicalProcessorInformation,                      // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx
    SystemWow64SharedInformationObsolete,                   // q: not implemented
    SystemRegisterFirmwareTableInformationHandler,          // s: SYSTEM_FIRMWARE_TABLE_HANDLER // (kernel-mode only)
    SystemFirmwareTableInformation,                         // q: SYSTEM_FIRMWARE_TABLE_INFORMATION
    SystemModuleInformationEx,                              // q: RTL_PROCESS_MODULE_INFORMATION_EX // since VISTA
    SystemVerifierTriageInformation,                        // q: not implemented
    SystemSuperfetchInformation,                            // qs: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
    SystemMemoryListInformation,                            // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
    SystemFileCacheInformationEx,                           // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
    SystemThreadPriorityClientIdInformation,                // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege) // NtQuerySystemInformationEx
    SystemProcessorIdleCycleTimeInformation,                // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx
    SystemVerifierCancellationInformation,                  // q: SYSTEM_VERIFIER_CANCELLATION_INFORMATION // name:wow64:whNT32QuerySystemVerifierCancellationInformation
    SystemProcessorPowerInformationEx,                      // q: not implemented
    SystemRefTraceInformation,                              // qs: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
    SystemSpecialPoolInformation,                           // qs: SYSTEM_SPECIAL_POOL_INFORMATION (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
    SystemProcessIdInformation,                             // q: SYSTEM_PROCESS_ID_INFORMATION
    SystemErrorPortInformation,                             // s: (requires SeTcbPrivilege)
    SystemBootEnvironmentInformation,                       // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
    SystemHypervisorInformation,                            // q: SYSTEM_HYPERVISOR_QUERY_INFORMATION
    SystemVerifierInformationEx,                            // qs: SYSTEM_VERIFIER_INFORMATION_EX
    SystemTimeZoneInformation,                              // qs: RTL_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemImageFileExecutionOptionsInformation,             // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
    SystemCoverageInformation,                              // q: COVERAGE_MODULES s: COVERAGE_MODULE_REQUEST // ExpCovQueryInformation (requires SeDebugPrivilege)
    SystemPrefetchPatchInformation,                         // q: SYSTEM_PREFETCH_PATCH_INFORMATION
    SystemVerifierFaultsInformation,                        // s: SYSTEM_VERIFIER_FAULTS_INFORMATION (requires SeDebugPrivilege)
    SystemSystemPartitionInformation,                       // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
    SystemSystemDiskInformation,                            // q: SYSTEM_SYSTEM_DISK_INFORMATION
    SystemProcessorPerformanceDistribution,                 // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx // 100
    SystemNumaProximityNodeInformation,                     // qs: SYSTEM_NUMA_PROXIMITY_MAP
    SystemDynamicTimeZoneInformation,                       // qs: RTL_DYNAMIC_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemCodeIntegrityInformation,                         // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
    SystemProcessorMicrocodeUpdateInformation,              // s: SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION (requires SeLoadDriverPrivilege)
    SystemProcessorBrandString,                             // q: CHAR[] // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
    SystemVirtualAddressInformation,                        // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
    SystemLogicalProcessorAndGroupInformation,              // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX (EX in: LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType) // since WIN7 // NtQuerySystemInformationEx // KeQueryLogicalProcessorRelationship
    SystemProcessorCycleTimeInformation,                    // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx
    SystemStoreInformation,                                 // qs: SYSTEM_STORE_INFORMATION (requires SeProfileSingleProcessPrivilege) // SmQueryStoreInformation
    SystemRegistryAppendString,                             // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
    SystemAitSamplingValue,                                 // s: ULONG (requires SeProfileSingleProcessPrivilege)
    SystemVhdBootInformation,                               // q: SYSTEM_VHD_BOOT_INFORMATION
    SystemCpuQuotaInformation,                              // qs: PS_CPU_QUOTA_QUERY_INFORMATION
    SystemNativeBasicInformation,                           // q: SYSTEM_BASIC_INFORMATION
    SystemErrorPortTimeouts,                                // q: SYSTEM_ERROR_PORT_TIMEOUTS
    SystemLowPriorityIoInformation,                         // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
    SystemTpmBootEntropyInformation,                        // q: BOOT_ENTROPY_NT_RESULT // ExQueryBootEntropyInformation
    SystemVerifierCountersInformation,                      // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
    SystemPagedPoolInformationEx,                           // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
    SystemSystemPtesInformationEx,                          // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
    SystemNodeDistanceInformation,                          // q: USHORT[4*NumaNodes] // (EX in: USHORT NodeNumber) // NtQuerySystemInformationEx
    SystemAcpiAuditInformation,                             // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
    SystemBasicPerformanceInformation,                      // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
    SystemQueryPerformanceCounterInformation,               // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
    SystemSessionBigPoolInformation,                        // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
    SystemBootGraphicsInformation,                          // qs: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
    SystemScrubPhysicalMemoryInformation,                   // qs: MEMORY_SCRUB_INFORMATION
    SystemBadPageInformation,                               // q: SYSTEM_BAD_PAGE_INFORMATION
    SystemProcessorProfileControlArea,                      // qs: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
    SystemCombinePhysicalMemoryInformation,                 // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
    SystemEntropyInterruptTimingInformation,                // qs: SYSTEM_ENTROPY_TIMING_INFORMATION
    SystemConsoleInformation,                               // qs: SYSTEM_CONSOLE_INFORMATION // (requires SeLoadDriverPrivilege)
    SystemPlatformBinaryInformation,                        // q: SYSTEM_PLATFORM_BINARY_INFORMATION (requires SeTcbPrivilege)
    SystemPolicyInformation,                                // q: SYSTEM_POLICY_INFORMATION (Warbird/Encrypt/Decrypt/Execute)
    SystemHypervisorProcessorCountInformation,              // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
    SystemDeviceDataInformation,                            // q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemDeviceDataEnumerationInformation,                 // q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemMemoryTopologyInformation,                        // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
    SystemMemoryChannelInformation,                         // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
    SystemBootLogoInformation,                              // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
    SystemProcessorPerformanceInformationEx,                // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx // since WINBLUE
    SystemCriticalProcessErrorLogInformation,               // q: CRITICAL_PROCESS_EXCEPTION_DATA
    SystemSecureBootPolicyInformation,                      // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
    SystemPageFileInformationEx,                            // q: SYSTEM_PAGEFILE_INFORMATION_EX
    SystemSecureBootInformation,                            // q: SYSTEM_SECUREBOOT_INFORMATION
    SystemEntropyInterruptTimingRawInformation,             // qs: SYSTEM_ENTROPY_TIMING_INFORMATION
    SystemPortableWorkspaceEfiLauncherInformation,          // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
    SystemFullProcessInformation,                           // q: SYSTEM_EXTENDED_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
    SystemKernelDebuggerInformationEx,                      // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
    SystemBootMetadataInformation,                          // q: (requires SeTcbPrivilege) // 150
    SystemSoftRebootInformation,                            // q: ULONG
    SystemElamCertificateInformation,                       // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
    SystemOfflineDumpConfigInformation,                     // q: OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
    SystemProcessorFeaturesInformation,                     // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
    SystemRegistryReconciliationInformation,                // s: NULL (requires admin) (flushes registry hives)
    SystemEdidInformation,                                  // q: SYSTEM_EDID_INFORMATION
    SystemManufacturingInformation,                         // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
    SystemEnergyEstimationConfigInformation,                // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
    SystemHypervisorDetailInformation,                      // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
    SystemProcessorCycleStatsInformation,                   // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx // 160
    SystemVmGenerationCountInformation,                     // s:
    SystemTrustedPlatformModuleInformation,                 // q: SYSTEM_TPM_INFORMATION
    SystemKernelDebuggerFlags,                              // q: SYSTEM_KERNEL_DEBUGGER_FLAGS
    SystemCodeIntegrityPolicyInformation,                   // qs: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
    SystemIsolatedUserModeInformation,                      // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
    SystemHardwareSecurityTestInterfaceResultsInformation,  // q:
    SystemSingleModuleInformation,                          // q: SYSTEM_SINGLE_MODULE_INFORMATION
    SystemAllowedCpuSetsInformation,                        // s: SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION
    SystemVsmProtectionInformation,                         // q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
    SystemInterruptCpuSetsInformation,                      // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
    SystemSecureBootPolicyFullInformation,                  // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
    SystemCodeIntegrityPolicyFullInformation,               // q:
    SystemAffinitizedInterruptProcessorInformation,         // q: KAFFINITY_EX // (requires SeIncreaseBasePriorityPrivilege)
    SystemRootSiloInformation,                              // q: SYSTEM_ROOT_SILO_INFORMATION
    SystemCpuSetInformation,                                // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
    SystemCpuSetTagInformation,                             // q: SYSTEM_CPU_SET_TAG_INFORMATION
    SystemWin32WerStartCallout,                             // s:
    SystemSecureKernelProfileInformation,                   // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
    SystemCodeIntegrityPlatformManifestInformation,         // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // NtQuerySystemInformationEx // since REDSTONE
    SystemInterruptSteeringInformation,                     // q: in: SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT, out: SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT // NtQuerySystemInformationEx
    SystemSupportedProcessorArchitectures,                  // p: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx // 180
    SystemMemoryUsageInformation,                           // q: SYSTEM_MEMORY_USAGE_INFORMATION
    SystemCodeIntegrityCertificateInformation,              // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
    SystemPhysicalMemoryInformation,                        // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
    SystemControlFlowTransition,                            // qs: (Warbird/Encrypt/Decrypt/Execute)
    SystemKernelDebuggingAllowed,                           // s: ULONG
    SystemActivityModerationExeState,                       // s: SYSTEM_ACTIVITY_MODERATION_EXE_STATE
    SystemActivityModerationUserSettings,                   // q: SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
    SystemCodeIntegrityPoliciesFullInformation,             // qs: NtQuerySystemInformationEx
    SystemCodeIntegrityUnlockInformation,                   // q: SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
    SystemIntegrityQuotaInformation,                        // s: SYSTEM_INTEGRITY_QUOTA_INFORMATION (requires SeDebugPrivilege)
    SystemFlushInformation,                                 // q: SYSTEM_FLUSH_INFORMATION
    SystemProcessorIdleMaskInformation,                     // q: ULONG_PTR[ActiveGroupCount] // since REDSTONE3
    SystemSecureDumpEncryptionInformation,                  // qs: NtQuerySystemInformationEx // (q: requires SeDebugPrivilege) (s: requires SeTcbPrivilege)
    SystemWriteConstraintInformation,                       // q: SYSTEM_WRITE_CONSTRAINT_INFORMATION
    SystemKernelVaShadowInformation,                        // q: SYSTEM_KERNEL_VA_SHADOW_INFORMATION
    SystemHypervisorSharedPageInformation,                  // q: SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
    SystemFirmwareBootPerformanceInformation,               // q:
    SystemCodeIntegrityVerificationInformation,             // q: SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
    SystemFirmwarePartitionInformation,                     // q: SYSTEM_FIRMWARE_PARTITION_INFORMATION // 200
    SystemSpeculationControlInformation,                    // q: SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
    SystemDmaGuardPolicyInformation,                        // q: SYSTEM_DMA_GUARD_POLICY_INFORMATION
    SystemEnclaveLaunchControlInformation,                  // q: SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
    SystemWorkloadAllowedCpuSetsInformation,                // q: SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
    SystemCodeIntegrityUnlockModeInformation,               // q: SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION
    SystemLeapSecondInformation,                            // qs: SYSTEM_LEAP_SECOND_INFORMATION // (s: requires SeSystemtimePrivilege)
    SystemFlags2Information,                                // q: SYSTEM_FLAGS_INFORMATION // (s: requires SeDebugPrivilege)
    SystemSecurityModelInformation,                         // q: SYSTEM_SECURITY_MODEL_INFORMATION // since 19H1
    SystemCodeIntegritySyntheticCacheInformation,           // qs: NtQuerySystemInformationEx
    SystemFeatureConfigurationInformation,                  // q: in: SYSTEM_FEATURE_CONFIGURATION_QUERY, out: SYSTEM_FEATURE_CONFIGURATION_INFORMATION; s: SYSTEM_FEATURE_CONFIGURATION_UPDATE // NtQuerySystemInformationEx // since 20H1 // 210
    SystemFeatureConfigurationSectionInformation,           // q: in: SYSTEM_FEATURE_CONFIGURATION_SECTIONS_REQUEST, out: SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION // NtQuerySystemInformationEx
    SystemFeatureUsageSubscriptionInformation,              // q: SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS; s: SYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE
    SystemSecureSpeculationControlInformation,              // q: SECURE_SPECULATION_CONTROL_INFORMATION
    SystemSpacesBootInformation,                            // qs: // since 20H2
    SystemFwRamdiskInformation,                             // q: SYSTEM_FIRMWARE_RAMDISK_INFORMATION
    SystemWheaIpmiHardwareInformation,                      // q:
    SystemDifSetRuleClassInformation,                       // s: SYSTEM_DIF_VOLATILE_INFORMATION (requires SeDebugPrivilege)
    SystemDifClearRuleClassInformation,                     // s: NULL (requires SeDebugPrivilege)
    SystemDifApplyPluginVerificationOnDriver,               // q: SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION (requires SeDebugPrivilege)
    SystemDifRemovePluginVerificationOnDriver,              // q: SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION (requires SeDebugPrivilege) // 220
    SystemShadowStackInformation,                           // q: SYSTEM_SHADOW_STACK_INFORMATION
    SystemBuildVersionInformation,                          // q: in: ULONG (LayerNumber), out: SYSTEM_BUILD_VERSION_INFORMATION // NtQuerySystemInformationEx
    SystemPoolLimitInformation,                             // q: SYSTEM_POOL_LIMIT_INFORMATION (requires SeIncreaseQuotaPrivilege) // NtQuerySystemInformationEx
    SystemCodeIntegrityAddDynamicStore,                     // q: CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners
    SystemCodeIntegrityClearDynamicStores,                  // q: CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners
    SystemDifPoolTrackingInformation,                       // s: SYSTEM_DIF_POOL_TRACKING_INFORMATION (requires SeDebugPrivilege)
    SystemPoolZeroingInformation,                           // q: SYSTEM_POOL_ZEROING_INFORMATION
    SystemDpcWatchdogInformation,                           // qs: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION
    SystemDpcWatchdogInformation2,                          // qs: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION_V2
    SystemSupportedProcessorArchitectures2,                 // q: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx // 230
    SystemSingleProcessorRelationshipInformation,           // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // (EX in: PROCESSOR_NUMBER Processor) // NtQuerySystemInformationEx
    SystemXfgCheckFailureInformation,                       // q: SYSTEM_XFG_FAILURE_INFORMATION
    SystemIommuStateInformation,                            // q: SYSTEM_IOMMU_STATE_INFORMATION // since 22H1
    SystemHypervisorMinrootInformation,                     // q: SYSTEM_HYPERVISOR_MINROOT_INFORMATION
    SystemHypervisorBootPagesInformation,                   // q: SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION
    SystemPointerAuthInformation,                           // q: SYSTEM_POINTER_AUTH_INFORMATION
    SystemSecureKernelDebuggerInformation,                  // qs: NtQuerySystemInformationEx
    SystemOriginalImageFeatureInformation,                  // q: in: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_INPUT, out: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_OUTPUT // NtQuerySystemInformationEx
    SystemMemoryNumaInformation,                            // q: SYSTEM_MEMORY_NUMA_INFORMATION_INPUT, SYSTEM_MEMORY_NUMA_INFORMATION_OUTPUT // NtQuerySystemInformationEx
    SystemMemoryNumaPerformanceInformation,                 // q: SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_INPUTSYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_INPUT, SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_OUTPUT // since 24H2 // 240
    SystemCodeIntegritySignedPoliciesFullInformation,       // qs: NtQuerySystemInformationEx
    SystemSecureCoreInformation,                            // qs: SystemSecureSecretsInformation
    SystemTrustedAppsRuntimeInformation,                    // q: SYSTEM_TRUSTEDAPPS_RUNTIME_INFORMATION
    SystemBadPageInformationEx,                             // q: SYSTEM_BAD_PAGE_INFORMATION
    SystemResourceDeadlockTimeout,                          // q: ULONG
    SystemBreakOnContextUnwindFailureInformation,           // q: ULONG (requires SeDebugPrivilege)
    SystemOslRamdiskInformation,                            // q: SYSTEM_OSL_RAMDISK_INFORMATION
    SystemCodeIntegrityPolicyManagementInformation,         // q: SYSTEM_CODEINTEGRITYPOLICY_MANAGEMENT // since 25H2
    SystemMemoryNumaCacheInformation,                       // q:
    SystemProcessorFeaturesBitMapInformation,               // q: // 250
    SystemRefTraceInformationEx,                            // q: SYSTEM_REF_TRACE_INFORMATION_EX
    SystemBasicProcessInformation,                          // q: SYSTEM_BASICPROCESS_INFORMATION
    SystemHandleCountInformation,                           // q: SYSTEM_HANDLECOUNT_INFORMATION
    SystemRuntimeAttestationReport,                         // q: // since 26H1
    SystemPoolTagInformation2,                              // q: SYSTEM_POOLTAG_INFORMATION2
    MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;

#endif // !STRUCTURES_H
