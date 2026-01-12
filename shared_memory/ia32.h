#pragma once
#include "structures.h"

#ifndef IA32_H
#define IA32_H


constexpr auto ia32_gs_base = 0xC0000101;
constexpr auto ia32_kernel_gs_base = 0xC0000102;
constexpr auto ia32_fs_base = 0xC0000100;

constexpr auto page_mask_4kib = 0x000FFFFFFFFFF000ULL;
constexpr auto page_mask_2mib = 0x000FFFFFFFE00000ULL;
constexpr auto page_mask_1gib = 0x000FFFFFC0000000ULL;

constexpr auto page_offset_4kib = 0x0000000000000FFFULL;
constexpr auto page_offset_2mib = 0x00000000001FFFFFULL;
constexpr auto page_offset_1gib = 0x000000003FFFFFFFULL;

typedef union _virt_addr_t
{
    std::uintptr_t value;
    struct
    {
        std::uint64_t offset : 12;        // 0:11
        std::uint64_t pte_index : 9;      // 12:20
        std::uint64_t pde_index : 9;      // 21:29
        std::uint64_t pdpte_index : 9;    // 30:38
        std::uint64_t pml4e_index : 9;    // 39:47
        std::uint64_t reserved : 16;      // 48:63
    };
    struct
    {
        std::uint64_t offset_4kb : 12;    // 4KB page offset
        std::uint64_t pt_offset : 9;
        std::uint64_t pd_offset : 9;
        std::uint64_t pdpt_offset : 9;
        std::uint64_t pml4_offset : 9;
        std::uint64_t reserved2 : 16;
    };
    struct
    {
        std::uint64_t offset_2mb : 21;    // 2MB page offset
        std::uint64_t pd_offset2 : 9;
        std::uint64_t pdpt_offset2 : 9;
        std::uint64_t pml4_offset2 : 9;
        std::uint64_t reserved3 : 16;
    };
    struct
    {
        std::uint64_t offset_1gb : 30;    // 1GB page offset
        std::uint64_t pdpt_offset3 : 9;
        std::uint64_t pml4_offset3 : 9;
        std::uint64_t reserved4 : 16;
    };
} virt_addr_t, * pvirt_addr_t;

typedef union _pml4e
{
    struct
    {
        std::uint64_t present : 1;                   // Must be 1 if valid
        std::uint64_t read_write : 1;               // Write access control
        std::uint64_t user_supervisor : 1;           // User/supervisor access control
        std::uint64_t page_write_through : 1;        // Write-through caching
        std::uint64_t cached_disable : 1;            // Cache disable
        std::uint64_t accessed : 1;                  // Set when accessed
        std::uint64_t ignored0 : 1;                  // Ignored
        std::uint64_t large_page : 1;               // Reserved (must be 0)
        std::uint64_t ignored1 : 4;                 // Ignored
        std::uint64_t pfn : 36;                     // Physical frame number
        std::uint64_t reserved : 4;                 // Reserved for software
        std::uint64_t ignored2 : 11;                // Ignored
        std::uint64_t no_execute : 1;               // No-execute bit
    } hard;
    std::uint64_t value;
} pml4e, * ppml4e;

typedef union _pdpte
{
    struct
    {
        std::uint64_t present : 1;                   // Must be 1 if valid
        std::uint64_t read_write : 1;               // Write access control
        std::uint64_t user_supervisor : 1;           // User/supervisor access control
        std::uint64_t page_write_through : 1;        // Write-through caching
        std::uint64_t cached_disable : 1;            // Cache disable
        std::uint64_t accessed : 1;                  // Set when accessed
        std::uint64_t dirty : 1;                    // Set when written to (1GB pages)
        std::uint64_t page_size : 1;                // 1=1GB page, 0=points to page directory
        std::uint64_t ignored1 : 4;                 // Ignored
        std::uint64_t pfn : 36;                     // Physical frame number
        std::uint64_t reserved : 4;                 // Reserved for software
        std::uint64_t ignored2 : 11;                // Ignored
        std::uint64_t no_execute : 1;               // No-execute bit
    } hard;
    std::uint64_t value;
} pdpte, * ppdpte;


typedef union _pde
{
    struct
    {
        std::uint64_t present : 1;                   // Must be 1 if valid
        std::uint64_t read_write : 1;               // Write access control
        std::uint64_t user_supervisor : 1;           // User/supervisor access control
        std::uint64_t page_write_through : 1;        // Write-through caching
        std::uint64_t cached_disable : 1;            // Cache disable
        std::uint64_t accessed : 1;                  // Set when accessed
        std::uint64_t dirty : 1;                    // Set when written to (2MB pages)
        std::uint64_t page_size : 1;                // 1=2MB page, 0=points to page table
        std::uint64_t global : 1;                   // Global page (if CR4.PGE=1)
        std::uint64_t ignored1 : 3;                 // Ignored
        std::uint64_t pfn : 36;                     // Physical frame number
        std::uint64_t reserved : 4;                 // Reserved for software
        std::uint64_t ignored2 : 11;                // Ignored
        std::uint64_t no_execute : 1;               // No-execute bit
    } hard;
    std::uint64_t value;
} pde, * ppde;

typedef union _pte
{
    struct
    {
        std::uint64_t present : 1;                   // Must be 1 if valid
        std::uint64_t read_write : 1;               // Write access control
        std::uint64_t user_supervisor : 1;           // User/supervisor access control
        std::uint64_t page_write_through : 1;        // Write-through caching
        std::uint64_t cached_disable : 1;            // Cache disable
        std::uint64_t accessed : 1;                  // Set when accessed
        std::uint64_t dirty : 1;                    // Set when written to
        std::uint64_t pat : 1;                      // Page Attribute Table bit
        std::uint64_t global : 1;                   // Global page
        std::uint64_t ignored1 : 3;                 // Ignored
        std::uint64_t pfn : 36;                     // Physical frame number
        std::uint64_t reserved : 4;                 // Reserved for software
        std::uint64_t ignored2 : 7;                 // Ignored
        std::uint64_t protection_key : 4;           // Protection key
        std::uint64_t no_execute : 1;               // No-execute bit
    } hard;
    std::uint64_t value;
} pte, * ppte;


struct single_list_entry_t
{
    struct single_list_entry_t* Next;                                        //0x0
};


typedef union _cr3 {
    std::uint64_t flags;

    struct {
        std::uint64_t pcid : 12;
        std::uint64_t page_frame_number : 36;
        std::uint64_t reserved_1 : 12;
        std::uint64_t reserved_2 : 3;
        std::uint64_t pcid_invalidate : 1;
    };
} cr3, * pcr3;

struct slist_header_t {
    union {
        std::uint64_t m_alignment;
        struct {
            single_list_entry_t m_next;
            std::uint16_t m_depth;
            std::uint16_t m_sequence;
        };
    };
};

union ularge_integer_t
{
    struct
    {
        std::uint32_t  m_low_part;                                                      //0x0
        std::uint32_t  m_high_part;                                                     //0x4
    };
    struct
    {
        std::uint32_t  m_low_part;                                                      //0x0
        std::uint32_t  m_high_part;                                                     //0x4
    } u;                                                                    //0x0
    std::uint64_t m_quad_part;                                                     //0x0
};

struct machine_frame_t
{
    std::uint64_t m_rip;
    std::uint64_t m_cs;
    std::uint64_t m_eflags;
    std::uint64_t m_rsp;
    std::uint64_t m_ss;
};

// Task State Segment structure
struct ktss_t {
    std::uint32_t m_reserved0;
    std::uint64_t m_rsp0;
    std::uint64_t m_rsp1;
    std::uint64_t m_rsp2;
    std::uint64_t m_reserved1;
    std::uint64_t m_ist[8];
    std::uint64_t m_reserved2;
    std::uint16_t m_reserved3;
    std::uint16_t m_io_map_base;
};

// DPC structure
struct kdpc_t {
    std::uint16_t m_type;
    std::uint8_t m_importance;
    std::uint8_t m_number;
    list_entry_t m_dpc_list_entry;
    void* m_deferred_routine;
    void* m_deferred_context;
    void* m_system_argument1;
    void* m_system_argument2;
    void* m_dpc_data;
};

struct ldr_data_table_entry_t {
    list_entry_t m_in_load_order_module_list;
    list_entry_t m_in_memory_order_module_list;
    list_entry_t m_in_initialization_order_module_list;
    void* m_dll_base;
    void* m_entry_point;
    std::uint32_t m_size_of_image;
    unicode_string_t m_full_dll_name;
    unicode_string_t m_base_dll_name;
    std::uint32_t m_flags;
    std::uint16_t m_load_count;
    std::uint16_t m_tls_index;
    list_entry_t m_hash_links;
    void* m_section_pointer;
    std::uint32_t m_check_sum;
    std::uint32_t m_time_date_stamp;
};

struct rtl_critical_section_t {
    void* m_debug_info;
    std::int32_t m_lock_count;
    std::int32_t m_recursion_count;
    void* m_owning_thread;
    void* m_lock_semaphore;
    std::uint32_t m_spin_count;
};

struct peb_ldr_data_t {
    std::uint32_t m_length;
    bool m_initialized;
    void* m_ss_handle;
    list_entry_t m_module_list_load_order;
    list_entry_t m_module_list_memory_order;
    list_entry_t m_module_list_in_it_order;
};

struct mmsupport_t {
    list_entry_t m_work_set_exp_head;                   // +0x000
    std::uint64_t m_flags;                              // +0x010
    std::uint64_t m_last_trim_time;                     // +0x018
    union {
        std::uint64_t m_page_fault_count;
        std::uint64_t m_peak_virtual_size;
        std::uint64_t m_virtual_size;
    };                                                  // +0x020
    std::uint64_t m_min_ws_size;                       // +0x028
    std::uint64_t m_max_ws_size;                       // +0x030
    std::uint64_t m_virtual_memory_threshold;          // +0x038
    std::uint64_t m_working_set_size;                  // +0x040
    std::uint64_t m_peak_working_set_size;            // +0x048
};

struct ex_push_lock_t {
    union {
        struct {
            std::uint64_t m_locked : 1;
            std::uint64_t m_waiting : 1;
            std::uint64_t m_waking : 1;
            std::uint64_t m_multiple_shared : 1;
            std::uint64_t m_shared : 60;
        };
        std::uint64_t m_value;
        void* m_ptr;
    };
}; // Size: 0x8

struct ex_fast_ref_t {
    union {
        void* m_object;
        std::uint64_t m_ref_cnt : 4;
        std::uint64_t m_value;
    };
}; // Size: 0x8

struct dispatcher_header_t {
    union {
        struct {
            std::uint8_t m_type;
            union {
                std::uint8_t m_absolute_timer : 1;
                std::uint8_t m_timer_resolution : 1;
                std::uint8_t m_timer_resolution_required : 1;
                std::uint8_t m_timer_resolution_set : 1;
            };
            union {
                std::uint8_t m_inserted : 1;
                std::uint8_t m_large_stack : 1;
                std::uint8_t m_priority_boost : 1;
                std::uint8_t m_thread_control_flags;
            };
            std::uint8_t m_signal_state;
        };
        std::uint32_t m_lock;
    };
    std::uint32_t m_size;
    union {
        std::uint64_t m_reserved1;
        struct {
            std::uint8_t m_hand_size;
            std::uint8_t m_inserted_2;
        };
    };
    union {
        std::uint64_t m_signal_state_2;
        struct {
            std::uint32_t m_signal_state_3;
            std::uint32_t m_thread_apc_disable;
        };
    };
}; // Size: 0x18

struct kwait_status_register_t {
    union {
        std::uint8_t m_flags;
        struct {
            std::uint8_t m_state : 3;
            std::uint8_t m_affinity : 1;
            std::uint8_t m_priority : 1;
            std::uint8_t m_apc : 1;
            std::uint8_t m_user_apc : 1;
            std::uint8_t m_alert : 1;
        };
    };
}; // Size: 0x1

//0x8 bytes (sizeof)


struct ktimer_t {
    dispatcher_header_t m_header;
    std::uint64_t m_due_time;
    list_entry_t m_timer_list_entry;
    struct kdpc_t* m_dpc;
    std::uint32_t m_period;
    std::uint32_t m_processor;
    std::uint32_t m_timer_type;
}; // Size: 0x40

struct group_affinity_t {
    std::uint64_t m_mask;
    std::uint16_t m_group;
    std::uint16_t m_reserved[3];
}; // Size: 0x10

struct kevent_t {
    dispatcher_header_t m_header;
}; // Size: 0x18

//0x438 bytes (sizeof)
struct kprocess_t
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    struct _LIST_ENTRY ProfileListHead;                                     //0x18
    ULONGLONG DirectoryTableBase;                                           //0x28
    struct _LIST_ENTRY ThreadListHead;                                      //0x30
    ULONG ProcessLock;                                                      //0x40
    ULONG ProcessTimerDelay;                                                //0x44
    ULONGLONG DeepFreezeStartTime;                                          //0x48
    ULONGLONG AffinityPadding[12];                                          //0xf8
    struct _LIST_ENTRY ReadyListHead;                                       //0x158
    struct _SINGLE_LIST_ENTRY SwapListEntry;                                //0x168
    ULONGLONG ActiveProcessorsPadding[12];                                  //0x218
    union
    {
        struct
        {
            ULONG AutoAlignment : 1;                                          //0x278
            ULONG DisableBoost : 1;                                           //0x278
            ULONG DisableQuantum : 1;                                         //0x278
            ULONG DeepFreeze : 1;                                             //0x278
            ULONG TimerVirtualization : 1;                                    //0x278
            ULONG CheckStackExtents : 1;                                      //0x278
            ULONG CacheIsolationEnabled : 1;                                  //0x278
            ULONG PpmPolicy : 3;                                              //0x278
            ULONG VaSpaceDeleted : 1;                                         //0x278
            ULONG ReservedFlags : 21;                                         //0x278
        };
        volatile LONG ProcessFlags;                                         //0x278
    };
    ULONG ActiveGroupsMask;                                                 //0x27c
    CHAR BasePriority;                                                      //0x280
    CHAR QuantumReset;                                                      //0x281
    CHAR Visited;                                                           //0x282
    USHORT ThreadSeed[20];                                                  //0x284
    USHORT ThreadSeedPadding[12];                                           //0x2ac
    USHORT IdealProcessor[20];                                              //0x2c4
    USHORT IdealProcessorPadding[12];                                       //0x2ec
    USHORT IdealNode[20];                                                   //0x304
    USHORT IdealNodePadding[12];                                            //0x32c
    USHORT IdealGlobalNode;                                                 //0x344
    USHORT Spare1;                                                          //0x346
    struct _LIST_ENTRY ProcessListEntry;                                    //0x350
    ULONGLONG CycleTime;                                                    //0x360
    ULONGLONG ContextSwitches;                                              //0x368
    struct _KSCHEDULING_GROUP* SchedulingGroup;                             //0x370
    ULONG FreezeCount;                                                      //0x378
    ULONG KernelTime;                                                       //0x37c
    ULONG UserTime;                                                         //0x380
    ULONG ReadyTime;                                                        //0x384
    ULONGLONG UserDirectoryTableBase;                                       //0x388
    UCHAR AddressPolicy;                                                    //0x390
    UCHAR Spare2[71];                                                       //0x391
    VOID* InstrumentationCallback;                                          //0x3d8
    union
    {
        ULONGLONG SecureHandle;                                             //0x3e0
        struct
        {
            ULONGLONG SecureProcess : 1;                                      //0x3e0
            ULONGLONG Unused : 1;                                             //0x3e0
        } Flags;                                                            //0x3e0
    } SecureState;                                                          //0x3e0
    ULONGLONG KernelWaitTime;                                               //0x3e8
    ULONGLONG UserWaitTime;                                                 //0x3f0
    ULONGLONG EndPadding[8];                                                //0x3f8
};


struct object_header_t {
    std::int64_t m_pointer_count;
    union {
        std::int64_t m_handle_count;
        void* m_next_to_free;
    };
    std::uint8_t m_type_index;
    std::uint8_t m_flags;
    std::uint8_t m_name_info_offset;
    std::uint8_t m_handle_info_offset;
    std::uint8_t m_quota_info_offset;
    std::uint8_t m_process_info_offset;
};

struct ex_rundown_ref_t {
    union {
        std::uint64_t m_count;                    // Size=0x8
        void* m_ptr;                              // Size=0x8
    };
};

struct rtl_avl_tree_t {
    void* m_root;                                 // Size=0x8
};

struct se_audit_process_creation_info_t {
    unicode_string_t* m_image_file_name;    // Pointer to UNICODE_STRING
};

//0xa40 bytes (sizeof)
struct eprocess_t
{
    struct kprocess_t Pcb;                                                   //0x0
    VOID* UniqueProcessId;                                                  //0x440
    struct _LIST_ENTRY ActiveProcessLinks;                                  //0x448
    struct _EX_RUNDOWN_REF RundownProtect;                                  //0x458
    union
    {
        ULONG Flags2;                                                       //0x460
        struct
        {
            ULONG JobNotReallyActive : 1;                                     //0x460
            ULONG AccountingFolded : 1;                                       //0x460
            ULONG NewProcessReported : 1;                                     //0x460
            ULONG ExitProcessReported : 1;                                    //0x460
            ULONG ReportCommitChanges : 1;                                    //0x460
            ULONG LastReportMemory : 1;                                       //0x460
            ULONG ForceWakeCharge : 1;                                        //0x460
            ULONG CrossSessionCreate : 1;                                     //0x460
            ULONG NeedsHandleRundown : 1;                                     //0x460
            ULONG RefTraceEnabled : 1;                                        //0x460
            ULONG PicoCreated : 1;                                            //0x460
            ULONG EmptyJobEvaluated : 1;                                      //0x460
            ULONG DefaultPagePriority : 3;                                    //0x460
            ULONG PrimaryTokenFrozen : 1;                                     //0x460
            ULONG ProcessVerifierTarget : 1;                                  //0x460
            ULONG RestrictSetThreadContext : 1;                               //0x460
            ULONG AffinityPermanent : 1;                                      //0x460
            ULONG AffinityUpdateEnable : 1;                                   //0x460
            ULONG PropagateNode : 1;                                          //0x460
            ULONG ExplicitAffinity : 1;                                       //0x460
            ULONG ProcessExecutionState : 2;                                  //0x460
            ULONG EnableReadVmLogging : 1;                                    //0x460
            ULONG EnableWriteVmLogging : 1;                                   //0x460
            ULONG FatalAccessTerminationRequested : 1;                        //0x460
            ULONG DisableSystemAllowedCpuSet : 1;                             //0x460
            ULONG ProcessStateChangeRequest : 2;                              //0x460
            ULONG ProcessStateChangeInProgress : 1;                           //0x460
            ULONG InPrivate : 1;                                              //0x460
        };
    };
    union
    {
        ULONG Flags;                                                        //0x464
        struct
        {
            ULONG CreateReported : 1;                                         //0x464
            ULONG NoDebugInherit : 1;                                         //0x464
            ULONG ProcessExiting : 1;                                         //0x464
            ULONG ProcessDelete : 1;                                          //0x464
            ULONG ManageExecutableMemoryWrites : 1;                           //0x464
            ULONG VmDeleted : 1;                                              //0x464
            ULONG OutswapEnabled : 1;                                         //0x464
            ULONG Outswapped : 1;                                             //0x464
            ULONG FailFastOnCommitFail : 1;                                   //0x464
            ULONG Wow64VaSpace4Gb : 1;                                        //0x464
            ULONG AddressSpaceInitialized : 2;                                //0x464
            ULONG SetTimerResolution : 1;                                     //0x464
            ULONG BreakOnTermination : 1;                                     //0x464
            ULONG DeprioritizeViews : 1;                                      //0x464
            ULONG WriteWatch : 1;                                             //0x464
            ULONG ProcessInSession : 1;                                       //0x464
            ULONG OverrideAddressSpace : 1;                                   //0x464
            ULONG HasAddressSpace : 1;                                        //0x464
            ULONG LaunchPrefetched : 1;                                       //0x464
            ULONG Background : 1;                                             //0x464
            ULONG VmTopDown : 1;                                              //0x464
            ULONG ImageNotifyDone : 1;                                        //0x464
            ULONG PdeUpdateNeeded : 1;                                        //0x464
            ULONG VdmAllowed : 1;                                             //0x464
            ULONG ProcessRundown : 1;                                         //0x464
            ULONG ProcessInserted : 1;                                        //0x464
            ULONG DefaultIoPriority : 3;                                      //0x464
            ULONG ProcessSelfDelete : 1;                                      //0x464
            ULONG SetTimerResolutionLink : 1;                                 //0x464
        };
    };
    union _LARGE_INTEGER CreateTime;                                        //0x468
    ULONGLONG ProcessQuotaUsage[2];                                         //0x470
    ULONGLONG ProcessQuotaPeak[2];                                          //0x480
    ULONGLONG PeakVirtualSize;                                              //0x490
    ULONGLONG VirtualSize;                                                  //0x498
    struct _LIST_ENTRY SessionProcessLinks;                                 //0x4a0
    union
    {
        VOID* ExceptionPortData;                                            //0x4b0
        ULONGLONG ExceptionPortValue;                                       //0x4b0
        ULONGLONG ExceptionPortState : 3;                                     //0x4b0
    };
    ULONGLONG MmReserved;                                                   //0x4c0
    struct _ETHREAD* RotateInProgress;                                      //0x4d8
    struct _ETHREAD* ForkInProgress;                                        //0x4e0
    struct _EJOB* volatile CommitChargeJob;                                 //0x4e8
    volatile ULONGLONG NumberOfPrivatePages;                                //0x4f8
    volatile ULONGLONG NumberOfLockedPages;                                 //0x500
    VOID* Win32Process;                                                     //0x508
    struct _EJOB* volatile Job;                                             //0x510
    VOID* SectionObject;                                                    //0x518
    VOID* SectionBaseAddress;                                               //0x520
    ULONG Cookie;                                                           //0x528
    struct _PAGEFAULT_HISTORY* WorkingSetWatch;                             //0x530
    VOID* Win32WindowStation;                                               //0x538
    VOID* InheritedFromUniqueProcessId;                                     //0x540
    volatile ULONGLONG OwnerProcessId;                                      //0x548
    struct _PEB* Peb;                                                       //0x550
    struct _MM_SESSION_SPACE* Session;                                      //0x558
    VOID* Spare1;                                                           //0x560
    struct _EPROCESS_QUOTA_BLOCK* QuotaBlock;                               //0x568
    struct _HANDLE_TABLE* ObjectTable;                                      //0x570
    VOID* DebugPort;                                                        //0x578
    struct _EWOW64PROCESS* WoW64Process;                                    //0x580
    VOID* DeviceMap;                                                        //0x588
    VOID* EtwDataSource;                                                    //0x590
    ULONGLONG PageDirectoryPte;                                             //0x598
    struct _FILE_OBJECT* ImageFilePointer;                                  //0x5a0
    UCHAR ImageFileName[15];                                                //0x5a8
    UCHAR PriorityClass;                                                    //0x5b7
    VOID* SecurityPort;                                                     //0x5b8
    struct _LIST_ENTRY JobLinks;                                            //0x5c8
    VOID* HighestUserAddress;                                               //0x5d8
    struct _LIST_ENTRY ThreadListHead;                                      //0x5e0
    volatile ULONG ActiveThreads;                                           //0x5f0
    ULONG ImagePathHash;                                                    //0x5f4
    ULONG DefaultHardErrorProcessing;                                       //0x5f8
    LONG LastThreadExitStatus;                                              //0x5fc
    VOID* LockedPagesList;                                                  //0x608
    union _LARGE_INTEGER ReadOperationCount;                                //0x610
    union _LARGE_INTEGER WriteOperationCount;                               //0x618
    union _LARGE_INTEGER OtherOperationCount;                               //0x620
    union _LARGE_INTEGER ReadTransferCount;                                 //0x628
    union _LARGE_INTEGER WriteTransferCount;                                //0x630
    union _LARGE_INTEGER OtherTransferCount;                                //0x638
    ULONGLONG CommitChargeLimit;                                            //0x640
    volatile ULONGLONG CommitCharge;                                        //0x648
    volatile ULONGLONG CommitChargePeak;                                    //0x650
    struct _LIST_ENTRY MmProcessLinks;                                      //0x7c0
    ULONG ModifiedPageCount;                                                //0x7d0
    LONG ExitStatus;                                                        //0x7d4
    VOID* VadHint;                                                          //0x7e0
    ULONGLONG VadCount;                                                     //0x7e8
    volatile ULONGLONG VadPhysicalPages;                                    //0x7f0
    ULONGLONG VadPhysicalPagesLimit;                                        //0x7f8
    struct _LIST_ENTRY TimerResolutionLink;                                 //0x820
    struct _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord;               //0x830
    ULONG RequestedTimerResolution;                                         //0x838
    ULONG SmallestTimerResolution;                                          //0x83c
    union _LARGE_INTEGER ExitTime;                                          //0x840
    struct _INVERTED_FUNCTION_TABLE* InvertedFunctionTable;                 //0x848
    ULONG ActiveThreadsHighWatermark;                                       //0x858
    ULONG LargePrivateVadCount;                                             //0x85c
    VOID* WnfContext;                                                       //0x868
    struct _EJOB* ServerSilo;                                               //0x870
    UCHAR SignatureLevel;                                                   //0x878
    UCHAR SectionSignatureLevel;                                            //0x879
    UCHAR HangCount : 3;                                                      //0x87b
    UCHAR GhostCount : 3;                                                     //0x87b
    UCHAR PrefilterException : 1;                                             //0x87b
    union
    {
        ULONG Flags3;                                                       //0x87c
        struct
        {
            ULONG Minimal : 1;                                                //0x87c
            ULONG ReplacingPageRoot : 1;                                      //0x87c
            ULONG Crashed : 1;                                                //0x87c
            ULONG JobVadsAreTracked : 1;                                      //0x87c
            ULONG VadTrackingDisabled : 1;                                    //0x87c
            ULONG AuxiliaryProcess : 1;                                       //0x87c
            ULONG SubsystemProcess : 1;                                       //0x87c
            ULONG IndirectCpuSets : 1;                                        //0x87c
            ULONG RelinquishedCommit : 1;                                     //0x87c
            ULONG HighGraphicsPriority : 1;                                   //0x87c
            ULONG CommitFailLogged : 1;                                       //0x87c
            ULONG ReserveFailLogged : 1;                                      //0x87c
            ULONG SystemProcess : 1;                                          //0x87c
            ULONG HideImageBaseAddresses : 1;                                 //0x87c
            ULONG AddressPolicyFrozen : 1;                                    //0x87c
            ULONG ProcessFirstResume : 1;                                     //0x87c
            ULONG ForegroundExternal : 1;                                     //0x87c
            ULONG ForegroundSystem : 1;                                       //0x87c
            ULONG HighMemoryPriority : 1;                                     //0x87c
            ULONG EnableProcessSuspendResumeLogging : 1;                      //0x87c
            ULONG EnableThreadSuspendResumeLogging : 1;                       //0x87c
            ULONG SecurityDomainChanged : 1;                                  //0x87c
            ULONG SecurityFreezeComplete : 1;                                 //0x87c
            ULONG VmProcessorHost : 1;                                        //0x87c
            ULONG VmProcessorHostTransition : 1;                              //0x87c
            ULONG AltSyscall : 1;                                             //0x87c
            ULONG TimerResolutionIgnore : 1;                                  //0x87c
            ULONG DisallowUserTerminate : 1;                                  //0x87c
        };
    };
    LONG DeviceAsid;                                                        //0x880
    VOID* SvmData;                                                          //0x888
    ULONGLONG SvmLock;                                                      //0x898
    struct _LIST_ENTRY SvmProcessDeviceListHead;                            //0x8a0
    ULONGLONG LastFreezeInterruptTime;                                      //0x8b0
    struct _PROCESS_DISK_COUNTERS* DiskCounters;                            //0x8b8
    VOID* PicoContext;                                                      //0x8c0
    VOID* EnclaveTable;                                                     //0x8c8
    ULONGLONG EnclaveNumber;                                                //0x8d0
    ULONG HighPriorityFaultsAllowed;                                        //0x8e0
    struct _PO_PROCESS_ENERGY_CONTEXT* EnergyContext;                       //0x8e8
    VOID* VmContext;                                                        //0x8f0
    ULONGLONG SequenceNumber;                                               //0x8f8
    ULONGLONG CreateInterruptTime;                                          //0x900
    ULONGLONG CreateUnbiasedInterruptTime;                                  //0x908
    ULONGLONG TotalUnbiasedFrozenTime;                                      //0x910
    ULONGLONG LastAppStateUpdateTime;                                       //0x918
    ULONGLONG LastAppStateUptime : 61;                                        //0x920
    ULONGLONG LastAppState : 3;                                               //0x920
    volatile ULONGLONG SharedCommitCharge;                                  //0x928
    struct _LIST_ENTRY SharedCommitLinks;                                   //0x938
    union
    {
        struct
        {
            ULONGLONG AllowedCpuSets;                                       //0x948
            ULONGLONG DefaultCpuSets;                                       //0x950
        };
        struct
        {
            ULONGLONG* AllowedCpuSetsIndirect;                              //0x948
            ULONGLONG* DefaultCpuSetsIndirect;                              //0x950
        };
    };
    VOID* DiskIoAttribution;                                                //0x958
    VOID* DxgProcess;                                                       //0x960
    ULONG Win32KFilterSet;                                                  //0x968
    volatile ULONG KTimerSets;                                              //0x978
    volatile ULONG KTimer2Sets;                                             //0x97c
    volatile ULONG ThreadTimerSets;                                         //0x980
    ULONGLONG VirtualTimerListLock;                                         //0x988
    struct _LIST_ENTRY VirtualTimerListHead;                                //0x990
    union
    {
        struct _WNF_STATE_NAME WakeChannel;                                 //0x9a0
    };
    union
    {
        ULONG MitigationFlags;                                              //0x9d0
        struct
        {
            ULONG ControlFlowGuardEnabled : 1;                                //0x9d0
            ULONG ControlFlowGuardExportSuppressionEnabled : 1;               //0x9d0
            ULONG ControlFlowGuardStrict : 1;                                 //0x9d0
            ULONG DisallowStrippedImages : 1;                                 //0x9d0
            ULONG ForceRelocateImages : 1;                                    //0x9d0
            ULONG HighEntropyASLREnabled : 1;                                 //0x9d0
            ULONG StackRandomizationDisabled : 1;                             //0x9d0
            ULONG ExtensionPointDisable : 1;                                  //0x9d0
            ULONG DisableDynamicCode : 1;                                     //0x9d0
            ULONG DisableDynamicCodeAllowOptOut : 1;                          //0x9d0
            ULONG DisableDynamicCodeAllowRemoteDowngrade : 1;                 //0x9d0
            ULONG AuditDisableDynamicCode : 1;                                //0x9d0
            ULONG DisallowWin32kSystemCalls : 1;                              //0x9d0
            ULONG AuditDisallowWin32kSystemCalls : 1;                         //0x9d0
            ULONG EnableFilteredWin32kAPIs : 1;                               //0x9d0
            ULONG AuditFilteredWin32kAPIs : 1;                                //0x9d0
            ULONG DisableNonSystemFonts : 1;                                  //0x9d0
            ULONG AuditNonSystemFontLoading : 1;                              //0x9d0
            ULONG PreferSystem32Images : 1;                                   //0x9d0
            ULONG ProhibitRemoteImageMap : 1;                                 //0x9d0
            ULONG AuditProhibitRemoteImageMap : 1;                            //0x9d0
            ULONG ProhibitLowILImageMap : 1;                                  //0x9d0
            ULONG AuditProhibitLowILImageMap : 1;                             //0x9d0
            ULONG SignatureMitigationOptIn : 1;                               //0x9d0
            ULONG AuditBlockNonMicrosoftBinaries : 1;                         //0x9d0
            ULONG AuditBlockNonMicrosoftBinariesAllowStore : 1;               //0x9d0
            ULONG LoaderIntegrityContinuityEnabled : 1;                       //0x9d0
            ULONG AuditLoaderIntegrityContinuity : 1;                         //0x9d0
            ULONG EnableModuleTamperingProtection : 1;                        //0x9d0
            ULONG EnableModuleTamperingProtectionNoInherit : 1;               //0x9d0
            ULONG RestrictIndirectBranchPrediction : 1;                       //0x9d0
            ULONG IsolateSecurityDomain : 1;                                  //0x9d0
        } MitigationFlagsValues;                                            //0x9d0
    };
    union
    {
        ULONG MitigationFlags2;                                             //0x9d4
        struct
        {
            ULONG EnableExportAddressFilter : 1;                              //0x9d4
            ULONG AuditExportAddressFilter : 1;                               //0x9d4
            ULONG EnableExportAddressFilterPlus : 1;                          //0x9d4
            ULONG AuditExportAddressFilterPlus : 1;                           //0x9d4
            ULONG EnableRopStackPivot : 1;                                    //0x9d4
            ULONG AuditRopStackPivot : 1;                                     //0x9d4
            ULONG EnableRopCallerCheck : 1;                                   //0x9d4
            ULONG AuditRopCallerCheck : 1;                                    //0x9d4
            ULONG EnableRopSimExec : 1;                                       //0x9d4
            ULONG AuditRopSimExec : 1;                                        //0x9d4
            ULONG EnableImportAddressFilter : 1;                              //0x9d4
            ULONG AuditImportAddressFilter : 1;                               //0x9d4
            ULONG DisablePageCombine : 1;                                     //0x9d4
            ULONG SpeculativeStoreBypassDisable : 1;                          //0x9d4
            ULONG CetUserShadowStacks : 1;                                    //0x9d4
            ULONG AuditCetUserShadowStacks : 1;                               //0x9d4
            ULONG AuditCetUserShadowStacksLogged : 1;                         //0x9d4
            ULONG UserCetSetContextIpValidation : 1;                          //0x9d4
            ULONG AuditUserCetSetContextIpValidation : 1;                     //0x9d4
            ULONG AuditUserCetSetContextIpValidationLogged : 1;               //0x9d4
            ULONG CetUserShadowStacksStrictMode : 1;                          //0x9d4
            ULONG BlockNonCetBinaries : 1;                                    //0x9d4
            ULONG BlockNonCetBinariesNonEhcont : 1;                           //0x9d4
            ULONG AuditBlockNonCetBinaries : 1;                               //0x9d4
            ULONG AuditBlockNonCetBinariesLogged : 1;                         //0x9d4
            ULONG Reserved1 : 1;                                              //0x9d4
            ULONG Reserved2 : 1;                                              //0x9d4
            ULONG Reserved3 : 1;                                              //0x9d4
            ULONG Reserved4 : 1;                                              //0x9d4
            ULONG Reserved5 : 1;                                              //0x9d4
            ULONG CetDynamicApisOutOfProcOnly : 1;                            //0x9d4
            ULONG UserCetSetContextIpValidationRelaxedMode : 1;               //0x9d4
        } MitigationFlags2Values;                                           //0x9d4
    };
    VOID* PartitionObject;                                                  //0x9d8
    ULONGLONG SecurityDomain;                                               //0x9e0
    ULONGLONG ParentSecurityDomain;                                         //0x9e8
    VOID* CoverageSamplerContext;                                           //0x9f0
    VOID* MmHotPatchContext;                                                //0x9f8


    ULONG DisabledComponentFlags;                                           //0xa20
    ULONG* volatile PathRedirectionHashes;                                  //0xa28
};

struct kaffinity_ex_t {
    std::uint16_t m_count;          // +0x000 Count
    std::uint16_t m_size;           // +0x002 Size
    std::uint16_t m_reserved;       // +0x004 Reserved
    std::uint16_t m_maximum;        // +0x006 Maximum
    std::uint64_t m_bitmap[20];     // +0x008 Bitmap array
};  // Size: 0xA8 bytes

struct peb_t {
    std::uint8_t m_inherited_address_space;
    std::uint8_t m_read_image_file_exec_options;
    std::uint8_t m_being_debugged;
    std::uint8_t m_bit_field;

    struct {
        std::uint32_t m_image_uses_large_pages : 1;
        std::uint32_t m_is_protected_process : 1;
        std::uint32_t m_is_legacy_process : 1;
        std::uint32_t m_is_image_dynamically_relocated : 1;
        std::uint32_t m_spare_bits : 4;
    };

    void* m_mutant;
    void* m_image_base_address;
    peb_ldr_data_t m_ldr;
    void* m_process_parameters;
    void* m_subsystem_data;
    void* m_process_heap;
    rtl_critical_section_t* m_fast_peb_lock;
    void* m_atl_thunk_slist_ptr;
    void* m_ifeo_key;

    struct {
        std::uint32_t m_process_in_job : 1;
        std::uint32_t m_process_initializing : 1;
        std::uint32_t m_reserved_bits0 : 30;
    } m_cross_process_flags;

    union {
        void* m_kernel_callback_table;
        void* m_user_shared_info_ptr;
    };

    std::uint32_t m_system_reserved[1];
    std::uint32_t m_spare_ulong;
    void* m_free_list;
    std::uint32_t m_tls_expansion_counter;
    void* m_tls_bitmap;
    std::uint32_t m_tls_bitmap_bits[2];
    void* m_read_only_shared_memory_base;
    void* m_hotpatch_information;
    void** m_read_only_static_server_data;
    void* m_ansi_code_page_data;
    void* m_oem_code_page_data;
    void* m_unicode_case_table_data;
    std::uint32_t m_number_of_processors;
    std::uint32_t m_nt_global_flag;
    std::int64_t m_critical_section_timeout;
    std::uint32_t m_heap_segment_reserve;
    std::uint32_t m_heap_segment_commit;
    std::uint32_t m_heap_decomit_total_free_threshold;
    std::uint32_t m_heap_decomit_free_block_threshold;
    std::uint32_t m_number_of_heaps;
    std::uint32_t m_maximum_number_of_heaps;
    void** m_process_heaps;
    void* m_gdi_shared_handle_table;
    void* m_process_starter_helper;
    std::uint32_t m_gdi_dc_attribute_list;
    rtl_critical_section_t* m_loader_lock;
    std::uint32_t m_os_major_version;
    std::uint32_t m_os_minor_version;
    std::uint16_t m_os_build_number;
    std::uint16_t m_os_csd_version;
    std::uint32_t m_os_platform_id;
    std::uint32_t m_image_subsystem;
    std::uint32_t m_image_subsystem_major_version;
    std::uint32_t m_image_subsystem_minor_version;
    std::uint32_t m_image_process_affinity_mask;
    std::uint32_t m_gdi_handle_buffer[34];
    void* m_post_process_init_routine;
    void* m_tls_expansion_bitmap;
    std::uint32_t m_tls_expansion_bitmap_bits[32];
    std::uint32_t m_session_id;
    std::uint64_t m_app_compat_flags;
    std::uint64_t m_app_compat_flags_user;
    void* m_p_shim_data;
    void* m_app_compat_info;
    unicode_string_t m_csd_version;
    void* m_activation_context_data;
    void* m_process_assembly_storage_map;
    void* m_system_default_activation_context_data;
    void* m_system_assembly_storage_map;
    std::uint32_t m_minimum_stack_commit;
    void* m_fls_callback;
    list_entry_t m_fls_list_head;
    void* m_fls_bitmap;
    std::uint32_t m_fls_bitmap_bits[4];
    std::uint32_t m_fls_high_index;
    void* m_wer_registration_data;
    void* m_wer_ship_assert_ptr;
};

//0x30 bytes (sizeof)
struct kwait_block_t
{
    struct list_entry_t WaitListEntry;                                       //0x0
    std::uint8_t WaitType;                                                         //0x10
    volatile std::uint8_t BlockState;                                              //0x11
    std::uint16_t WaitKey;                                                         //0x12
    std::int32_t SpareLong;                                                         //0x14
    union
    {
        struct kthread* Thread;                                            //0x18
        struct _KQUEUE* NotificationQueue;                                  //0x18
    };
    void* Object;                                                           //0x20
    void* SparePtr;                                                         //0x28
};

struct large_integer_t {
    union {
        struct {
            std::uint32_t m_low_part;
            std::int32_t m_high_part;
        };
        struct {
            std::uint32_t m_low_part;
            std::int32_t m_high_part;
        } u;
        std::int64_t m_quad_part;
    };
};

enum class pool_type_t : std::uint32_t {
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS,
    MaxPoolType,
    NonPagedPoolBase = 0,
    NonPagedPoolBaseMustSucceed = 2,
    NonPagedPoolBaseCacheAligned = 4,
    NonPagedPoolBaseCacheAlignedMustS = 6
};

enum class processor_cache_type_t : std::uint32_t {
    Unified = 0,
    Instruction = 1,
    Data = 2,
    Trace = 3
};

struct kdpc_data_t {
    list_entry_t m_dpc_list_head;
    std::uint32_t m_dpc_list_lock;
    std::uint32_t m_dpc_queue_depth;
    std::uint32_t m_dpc_count;
};

struct kgate_t {
    dispatcher_header_t m_header;
};

struct cache_descriptor_t {
    std::uint8_t m_level;
    std::uint8_t m_associativity;
    std::uint16_t m_line_size;
    std::uint32_t m_size;
    processor_cache_type_t m_type;
};

struct rtl_rb_tree_t {
    void* m_root;
    void* m_min;
};

struct processor_power_state_t {
    void* m_idle_function;
    std::uint32_t m_idle_state_max;
    std::uint32_t m_last_idle_check;
    std::uint32_t m_last_thermal_interval;
    struct {
        std::uint32_t m_idle_check : 1;
        std::uint32_t m_thermal_check : 1;
        std::uint32_t m_thermal_active : 1;
        std::uint32_t m_reserved : 29;
    } m_flags;
    std::uint32_t m_last_idle_duration;
    std::uint32_t m_idle_sum;
    std::uint32_t m_idle_count;
    std::uint32_t m_idle_average;
    std::uint32_t m_thermal_sum;
    std::uint32_t m_thermal_count;
    std::uint32_t m_thermal_average;
    std::uint32_t m_thermal_interval;
    std::uint32_t m_reserved[8];
};

struct kprocessor_state_t {
    struct {
        std::uint64_t m_rax;
        std::uint64_t m_rbx;
        std::uint64_t m_rcx;
        std::uint64_t m_rdx;
        std::uint64_t m_rsi;
        std::uint64_t m_rdi;
        std::uint64_t m_rbp;
        std::uint64_t m_rsp;
        std::uint64_t m_r8;
        std::uint64_t m_r9;
        std::uint64_t m_r10;
        std::uint64_t m_r11;
        std::uint64_t m_r12;
        std::uint64_t m_r13;
        std::uint64_t m_r14;
        std::uint64_t m_r15;
        std::uint64_t m_rip;
        std::uint64_t m_rflags;
        std::uint64_t m_cs;
        std::uint64_t m_ss;
        std::uint64_t m_ds;
        std::uint64_t m_es;
        std::uint64_t m_fs;
        std::uint64_t m_gs;
    } m_context_frame;
    std::uint16_t m_segment_registers[6];
    std::uint32_t m_reserved[6];
};

struct kspin_lock_queue_t {
    void* m_next;
    void* m_lock;
};

struct ktimer_table_t {
    std::uint64_t m_timer_expiry;
    kdpc_t m_timer_dpc;
    std::uint64_t m_timer_entries[256];
};

struct ktimer_expiration_trace_t {
    std::uint64_t m_time;
    void* m_thread;
};

struct kstatic_affinity_block_t {
    std::uint64_t m_bitmap[64];
};

struct kshared_ready_queue_t {
    std::uint32_t m_lock;
    std::uint32_t m_owner;
    std::uint32_t m_current_size;
    std::uint32_t m_maximum_size;
    list_entry_t m_list_head;
};


struct ksecure_fault_information_t {
    std::uint32_t m_fault_type;
    std::uint32_t m_reserved;
    std::uint64_t m_virtual_address;
};

struct klock_queue_handle_t {
    kspin_lock_queue_t m_lock_queue;
    std::uint8_t m_old_irql;
};

struct kentropy_timing_state_t {
    std::uint64_t m_enter_time;
    std::uint64_t m_enter_cycles;
    std::uint64_t m_reserved[2];
};

struct pp_lookaside_list_t {
    struct {
        slist_header_t m_list_head;
        std::uint16_t m_depth;
        std::uint16_t m_maximum_depth;
        std::uint32_t m_total_allocates;
        union {
            std::uint32_t m_allocate_misses;
            std::uint32_t m_allocate_hits;
        };
        std::uint32_t m_total_frees;
        union {
            std::uint32_t m_free_misses;
            std::uint32_t m_free_hits;
        };
        pool_type_t m_pool_type;
        std::uint32_t m_tag;
        std::uint32_t m_size;
        void* m_allocate_ex;
        void* m_free_ex;
        list_entry_t m_list_entry;
    } m_p;
    struct {
        std::uint32_t m_total_allocates;
        union {
            std::uint32_t m_allocate_misses;
            std::uint32_t m_allocate_hits;
        };
        std::uint32_t m_total_frees;
        union {
            std::uint32_t m_free_misses;
            std::uint32_t m_free_hits;
        };
    } m_l;
};

struct general_lookaside_pool_t {
    slist_header_t m_list_head;
    std::uint16_t m_depth;
    std::uint16_t m_maximum_depth;
    std::uint32_t m_total_allocates;
    union {
        std::uint32_t m_allocate_misses;
        std::uint32_t m_allocate_hits;
    };
    std::uint32_t m_total_frees;
    union {
        std::uint32_t m_free_misses;
        std::uint32_t m_free_hits;
    };
    pool_type_t m_pool_type;
    std::uint32_t m_tag;
    std::uint32_t m_size;
    void* m_allocate_ex;
    void* m_free_ex;
    list_entry_t m_list_entry;
};

struct filesystem_disk_counters_t {
    std::uint32_t m_fs_read_operations;
    std::uint32_t m_fs_write_operations;
    std::uint32_t m_fs_other_operations;
    std::uint32_t m_fs_read_bytes;
    std::uint32_t m_fs_write_bytes;
    std::uint32_t m_fs_other_bytes;
};

struct iop_irp_stack_profiler_t {
    std::uint32_t m_size;
    std::uint32_t m_count;
    std::uint32_t m_max_depth;
    std::uint32_t m_reserved;
};

struct machine_check_context_t {
    std::uint32_t m_version_id;
    std::uint32_t m_check_type;
    std::uint32_t m_processor_number;
    std::uint32_t m_bank_number;
    std::uint64_t m_address;
    std::uint64_t m_misc;
};

struct synch_counters_t {
    std::uint32_t m_spinlock_acquire;
    std::uint32_t m_spinlock_content;
    std::uint32_t m_spinlock_spin;
    std::uint32_t m_kevent;
    std::uint32_t m_kevent_level;
    std::uint32_t m_kevent_spinlock_spin;
    std::uint32_t m_kmutex_acquire;
    std::uint32_t m_kmutex_content;
    std::uint32_t m_kmutex_spin;
    std::uint32_t m_fast_mutex_acquire;
    std::uint32_t m_fast_mutex_content;
    std::uint32_t m_fast_mutex_spin;
    std::uint32_t m_guarded_mutex_acquire;
    std::uint32_t m_guarded_mutex_content;
    std::uint32_t m_guarded_mutex_spin;
};

struct request_mailbox_t {
    std::uint64_t m_next;
    std::uint32_t m_request_type;
    std::uint32_t m_request_flags;
    list_entry_t m_request_list_entry;
    std::uint64_t m_request_context;
    union {
        struct {
            std::uint32_t m_processor_number;
            std::uint32_t m_node_number;
        };
        std::uint64_t m_target_object;
    };
    std::uint64_t m_reserved[2];
};

struct m128a {
    std::uint64_t low;
    std::uint64_t high;
};

struct ktrap_frame_t {
    std::uint64_t m_p1_home;                    // +0x000
    std::uint64_t m_p2_home;                    // +0x008
    std::uint64_t m_p3_home;                    // +0x010
    std::uint64_t m_p4_home;                    // +0x018
    std::uint64_t m_p5;                         // +0x020

    std::uint8_t m_previous_mode;               // +0x028
    std::uint8_t m_previous_irql;               // +0x029
    std::uint8_t m_fault_indicator;             // +0x02A
    std::uint8_t m_exception_active;            // +0x02B
    std::uint32_t m_mxcsr;                      // +0x02C

    std::uint64_t m_rax;                        // +0x030
    std::uint64_t m_rcx;                        // +0x038
    std::uint64_t m_rdx;                        // +0x040
    std::uint64_t m_r8;                         // +0x048
    std::uint64_t m_r9;                         // +0x050
    std::uint64_t m_r10;                        // +0x058
    std::uint64_t m_r11;                        // +0x060

    union {
        std::uint64_t m_gs_base;                // +0x068
        std::uint64_t m_gs_swap;
    };

    m128a m_xmm0;                               // +0x070
    m128a m_xmm1;                               // +0x080
    m128a m_xmm2;                               // +0x090
    m128a m_xmm3;                               // +0x0A0
    m128a m_xmm4;                               // +0x0B0
    m128a m_xmm5;                               // +0x0C0

    union {
        std::uint64_t m_fault_address;          // +0x0D0
        std::uint64_t m_context_record;
    };

    std::uint64_t m_dr0;                        // +0x0D8
    std::uint64_t m_dr1;                        // +0x0E0
    std::uint64_t m_dr2;                        // +0x0E8
    std::uint64_t m_dr3;                        // +0x0F0
    std::uint64_t m_dr6;                        // +0x0F8
    std::uint64_t m_dr7;                        // +0x100

    // Debug registers block
    std::uint64_t m_debug_control;              // +0x108
    std::uint64_t m_last_branch_to_rip;         // +0x110
    std::uint64_t m_last_branch_from_rip;       // +0x118
    std::uint64_t m_last_exception_to_rip;      // +0x120
    std::uint64_t m_last_exception_from_rip;    // +0x128

    std::uint16_t m_seg_ds;                     // +0x130
    std::uint16_t m_seg_es;                     // +0x132
    std::uint16_t m_seg_fs;                     // +0x134
    std::uint16_t m_seg_gs;                     // +0x136

    std::uint64_t m_nested_trap_frame;                 // +0x138
    std::uint64_t m_rbx;                        // +0x140
    std::uint64_t m_rdi;                        // +0x148
    std::uint64_t m_rsi;                        // +0x150
    std::uint64_t m_rbp;                        // +0x158

    union {
        std::uint64_t m_error_code;             // +0x160
        std::uint64_t m_exception_frame;
    };

    std::uint64_t m_rip;                        // +0x168
    std::uint16_t m_seg_cs;                     // +0x170
    std::uint8_t m_fill0;                       // +0x172
    std::uint8_t m_logging;                     // +0x173
    std::uint16_t m_fill1[2];                   // +0x174
    std::uint32_t m_eflags;                     // +0x178
    std::uint32_t m_fill2;                      // +0x17C
    std::uint64_t m_rsp;                        // +0x180
    std::uint16_t m_seg_ss;                     // +0x188
    std::uint16_t m_fill3;                      // +0x18A
    std::uint32_t m_fill4;                      // +0x18C
}; // Size = 0x190

struct activation_context_stack_t
{
    std::addr_t active_frame;                    // 0x000
    list_entry_t frame_list_cache;               // 0x008
    std::uint32_t flags;                         // 0x018
    std::uint32_t next_cookie;                   // 0x01C
    std::uint32_t frame_count;                   // 0x020
    std::uint32_t padding;                       // 0x024
};

struct client_id_t {
    void* m_unique_process;
    void* m_unique_thread;
};

struct _exception_registration_record {
    struct _exception_registration_record* m_next;
    void* m_handler;
};

struct _vectored_handler_entry {
    list_entry_t m_link;
    std::uint32_t m_reference_count;
    void* m_vectored_handler;
};

struct _vectored_handler_list {
    std::uint32_t m_count;
    list_entry_t m_head;
};

struct teb_t;
struct nt_tib_t
{
    struct _exception_registration_record* m_exception_list;  // 0x000
    std::addr_t m_stack_base;                                // 0x008
    std::addr_t m_stack_limit;                              // 0x010
    std::addr_t m_sub_system_tib;                           // 0x018
    union {
        std::addr_t m_fiber_data;                           // 0x020
        std::uint32_t m_version;                            // 0x020
    };
    std::addr_t m_arbitrary_user_pointer;                    // 0x028
    teb_t* m_self;                                          // 0x030
};

struct teb_t
{
    nt_tib_t m_nt_tib;                          // 0x000 Contains exception_list, stack_base, stack_limit, etc.
    std::addr_t m_environment_pointer;           // 0x038
    client_id_t m_client_id;                    // 0x040
    std::addr_t m_active_rpc_handle;            // 0x050
    std::addr_t m_thread_local_storage_pointer; // 0x058
    peb_t* m_process_environment_block;         // 0x060
    std::uint32_t m_last_error_value;           // 0x068
    std::uint32_t m_count_of_owned_critical_sections; // 0x06C
    std::addr_t m_csr_client_thread;            // 0x070
    std::addr_t m_win32_thread_info;            // 0x078
    std::uint32_t m_user32_reserved[26];        // 0x080
    std::addr_t m_user_reserved[5];             // 0x0E8
    std::addr_t m_wow32_reserved;               // 0x100
    std::uint32_t m_current_locale;             // 0x108
    std::uint32_t m_fp_software_status_register; // 0x10C
    std::addr_t m_system_reserved1[54];         // 0x110
    std::int32_t m_exception_code;              // 0x2C0

    activation_context_stack_t* m_activation_context_stack_pointer; // 0x2C8
    std::uint8_t m_spare_bytes[24];             // 0x2D0
    std::uint32_t m_tls_slots[64];              // 0x2E8
    list_entry_t m_tls_links;                   // 0x4E8
};

struct kapc_state_t {
    list_entry_t m_apc_list_head[2];
    eprocess_t* m_process;
    std::uint8_t m_kernel_apc_in_progress;
    std::uint8_t m_kernel_apc_pending;
    std::uint8_t m_user_apc_pending;
    std::uint8_t m_pad;
}; // Size: 0x40

struct kapc_t {
    std::uint8_t type;
    std::uint8_t spare_byte0;
    std::uint8_t size;
    std::uint8_t spare_byte1;
    std::uint32_t spare_long0;
    void* thread;
    list_entry_t apc_list_entry;
    void* kernel_routine;
    void* rundown_routine;
    void* normal_routine;
    void* normal_context;
    void* system_argument1;
    void* system_argument2;
    std::uint8_t apc_state_index;
    std::uint8_t apc_mode;
    std::uint8_t inserted;
    std::uint8_t pad;
}; // Size: 0x58




//0x430 bytes (sizeof)
struct kthread_t
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    VOID* SListFaultAddress;                                                //0x18
    ULONGLONG QuantumTarget;                                                //0x20
    VOID* InitialStack;                                                     //0x28
    VOID* volatile StackLimit;                                              //0x30
    VOID* StackBase;                                                        //0x38
    ULONGLONG ThreadLock;                                                   //0x40
    volatile ULONGLONG CycleTime;                                           //0x48
    ULONG CurrentRunTime;                                                   //0x50
    ULONG ExpectedRunTime;                                                  //0x54
    VOID* KernelStack;                                                      //0x58
    struct _XSAVE_FORMAT* StateSaveArea;                                    //0x60
    struct _KSCHEDULING_GROUP* volatile SchedulingGroup;                    //0x68
    volatile UCHAR Running;                                                 //0x71
    UCHAR Alerted[2];                                                       //0x72
    union
    {
        struct
        {
            ULONG AutoBoostActive : 1;                                        //0x74
            ULONG ReadyTransition : 1;                                        //0x74
            ULONG WaitNext : 1;                                               //0x74
            ULONG SystemAffinityActive : 1;                                   //0x74
            ULONG Alertable : 1;                                              //0x74
            ULONG UserStackWalkActive : 1;                                    //0x74
            ULONG ApcInterruptRequest : 1;                                    //0x74
            ULONG QuantumEndMigrate : 1;                                      //0x74
            ULONG UmsDirectedSwitchEnable : 1;                                //0x74
            ULONG TimerActive : 1;                                            //0x74
            ULONG SystemThread : 1;                                           //0x74
            ULONG ProcessDetachActive : 1;                                    //0x74
            ULONG CalloutActive : 1;                                          //0x74
            ULONG ScbReadyQueue : 1;                                          //0x74
            ULONG ApcQueueable : 1;                                           //0x74
            ULONG ReservedStackInUse : 1;                                     //0x74
            ULONG UmsPerformingSyscall : 1;                                   //0x74
            ULONG TimerSuspended : 1;                                         //0x74
            ULONG SuspendedWaitMode : 1;                                      //0x74
            ULONG SuspendSchedulerApcWait : 1;                                //0x74
            ULONG CetUserShadowStack : 1;                                     //0x74
            ULONG BypassProcessFreeze : 1;                                    //0x74
            ULONG Reserved : 10;                                              //0x74
        };
        LONG MiscFlags;                                                     //0x74
    };
    union
    {
        struct
        {
            ULONG ThreadFlagsSpare : 2;                                       //0x78
            ULONG AutoAlignment : 1;                                          //0x78
            ULONG DisableBoost : 1;                                           //0x78
            ULONG AlertedByThreadId : 1;                                      //0x78
            ULONG QuantumDonation : 1;                                        //0x78
            ULONG EnableStackSwap : 1;                                        //0x78
            ULONG GuiThread : 1;                                              //0x78
            ULONG DisableQuantum : 1;                                         //0x78
            ULONG ChargeOnlySchedulingGroup : 1;                              //0x78
            ULONG DeferPreemption : 1;                                        //0x78
            ULONG QueueDeferPreemption : 1;                                   //0x78
            ULONG ForceDeferSchedule : 1;                                     //0x78
            ULONG SharedReadyQueueAffinity : 1;                               //0x78
            ULONG FreezeCount : 1;                                            //0x78
            ULONG TerminationApcRequest : 1;                                  //0x78
            ULONG AutoBoostEntriesExhausted : 1;                              //0x78
            ULONG KernelStackResident : 1;                                    //0x78
            ULONG TerminateRequestReason : 2;                                 //0x78
            ULONG ProcessStackCountDecremented : 1;                           //0x78
            ULONG RestrictedGuiThread : 1;                                    //0x78
            ULONG VpBackingThread : 1;                                        //0x78
            ULONG ThreadFlagsSpare2 : 1;                                      //0x78
            ULONG EtwStackTraceApcInserted : 8;                               //0x78
        };
        volatile LONG ThreadFlags;                                          //0x78
    };
    volatile UCHAR Tag;                                                     //0x7c
    UCHAR SystemHeteroCpuPolicy;                                            //0x7d
    UCHAR UserHeteroCpuPolicy : 7;                                            //0x7e
    UCHAR ExplicitSystemHeteroCpuPolicy : 1;                                  //0x7e
    union
    {
        struct
        {
            UCHAR RunningNonRetpolineCode : 1;                                //0x7f
            UCHAR SpecCtrlSpare : 7;                                          //0x7f
        };
        UCHAR SpecCtrl;                                                     //0x7f
    };
    ULONG SystemCallNumber;                                                 //0x80
    ULONG ReadyTime;                                                        //0x84
    VOID* FirstArgument;                                                    //0x88
    struct _KTRAP_FRAME* TrapFrame;                                         //0x90
    union
    {
        struct _KAPC_STATE ApcState;                                        //0x98
        struct
        {
            UCHAR ApcStateFill[43];                                         //0x98
            CHAR Priority;                                                  //0xc3
            ULONG UserIdealProcessor;                                       //0xc4
        };
    };
    volatile LONGLONG WaitStatus;                                           //0xc8
    struct _KWAIT_BLOCK* WaitBlockList;                                     //0xd0
    union
    {
        struct list_entry_t WaitListEntry;                                   //0xd8
        struct single_list_entry_t SwapListEntry;                            //0xd8
    };
    struct _DISPATCHER_HEADER* volatile Queue;                              //0xe8
    VOID* Teb;                                                              //0xf0
    ULONGLONG RelativeTimerBias;                                            //0xf8
    struct _KTIMER Timer;                                                   //0x100
    union
    {
        struct _KWAIT_BLOCK WaitBlock[4];                                   //0x140
        struct
        {
            UCHAR WaitBlockFill4[20];                                       //0x140
            ULONG ContextSwitches;                                          //0x154
        };
        struct
        {
            UCHAR WaitBlockFill5[68];                                       //0x140
            volatile UCHAR State;                                           //0x184
            CHAR Spare13;                                                   //0x185
            UCHAR WaitIrql;                                                 //0x186
            CHAR WaitMode;                                                  //0x187
        };
        struct
        {
            UCHAR WaitBlockFill6[116];                                      //0x140
            ULONG WaitTime;                                                 //0x1b4
        };
        struct
        {
            UCHAR WaitBlockFill7[164];                                      //0x140
            union
            {
                struct
                {
                    SHORT KernelApcDisable;                                 //0x1e4
                    SHORT SpecialApcDisable;                                //0x1e6
                };
                ULONG CombinedApcDisable;                                   //0x1e4
            };
        };
        struct
        {
            UCHAR WaitBlockFill8[40];                                       //0x140
            struct _KTHREAD_COUNTERS* ThreadCounters;                       //0x168
        };
        struct
        {
            UCHAR WaitBlockFill9[88];                                       //0x140
            struct _XSTATE_SAVE* XStateSave;                                //0x198
        };
        struct
        {
            UCHAR WaitBlockFill10[136];                                     //0x140
            VOID* volatile Win32Thread;                                     //0x1c8
        };
        struct
        {
            UCHAR WaitBlockFill11[176];                                     //0x140
            struct _UMS_CONTROL_BLOCK* Ucb;                                 //0x1f0
            struct _KUMS_CONTEXT_HEADER* volatile Uch;                      //0x1f8
        };
    };
    union
    {
        volatile LONG ThreadFlags2;                                         //0x200
        struct
        {
            ULONG BamQosLevel : 8;                                            //0x200
            ULONG ThreadFlags2Reserved : 24;                                  //0x200
        };
    };
    ULONG Spare21;                                                          //0x204
    struct list_entry_t QueueListEntry;                                      //0x208
    union
    {
        volatile ULONG NextProcessor;                                       //0x218
        struct
        {
            ULONG NextProcessorNumber : 31;                                   //0x218
            ULONG SharedReadyQueue : 1;                                       //0x218
        };
    };
    LONG QueuePriority;                                                     //0x21c
    struct _KPROCESS* Process;                                              //0x220
    union
    {
        struct _GROUP_AFFINITY UserAffinity;                                //0x228
        struct
        {
            UCHAR UserAffinityFill[10];                                     //0x228
            CHAR PreviousMode;                                              //0x232
            CHAR BasePriority;                                              //0x233
            union
            {
                CHAR PriorityDecrement;                                     //0x234
                struct
                {
                    UCHAR ForegroundBoost : 4;                                //0x234
                    UCHAR UnusualBoost : 4;                                   //0x234
                };
            };
            UCHAR Preempted;                                                //0x235
            UCHAR AdjustReason;                                             //0x236
            CHAR AdjustIncrement;                                           //0x237
        };
    };
    ULONGLONG AffinityVersion;                                              //0x238
    union
    {
        struct _GROUP_AFFINITY Affinity;                                    //0x240
        struct
        {
            UCHAR AffinityFill[10];                                         //0x240
            UCHAR ApcStateIndex;                                            //0x24a
            UCHAR WaitBlockCount;                                           //0x24b
            ULONG IdealProcessor;                                           //0x24c
        };
    };
    ULONGLONG NpxState;                                                     //0x250
    union
    {
        struct _KAPC_STATE SavedApcState;                                   //0x258
        struct
        {
            UCHAR SavedApcStateFill[43];                                    //0x258
            UCHAR WaitReason;                                               //0x283
            CHAR SuspendCount;                                              //0x284
            CHAR Saturation;                                                //0x285
            USHORT SListFaultCount;                                         //0x286
        };
    };
    union
    {
        struct _KAPC SchedulerApc;                                          //0x288
        struct
        {
            UCHAR SchedulerApcFill0[1];                                     //0x288
            UCHAR ResourceIndex;                                            //0x289
        };
        struct
        {
            UCHAR SchedulerApcFill1[3];                                     //0x288
            UCHAR QuantumReset;                                             //0x28b
        };
        struct
        {
            UCHAR SchedulerApcFill2[4];                                     //0x288
            ULONG KernelTime;                                               //0x28c
        };
        struct
        {
            UCHAR SchedulerApcFill3[64];                                    //0x288
            struct _KPRCB* volatile WaitPrcb;                               //0x2c8
        };
        struct
        {
            UCHAR SchedulerApcFill4[72];                                    //0x288
            VOID* LegoData;                                                 //0x2d0
        };
        struct
        {
            UCHAR SchedulerApcFill5[83];                                    //0x288
            UCHAR CallbackNestingLevel;                                     //0x2db
            ULONG UserTime;                                                 //0x2dc
        };
    };
    struct _KEVENT SuspendEvent;                                            //0x2e0
    struct list_entry_t ThreadListEntry;                                     //0x2f8
    struct list_entry_t MutantListHead;                                      //0x308
    UCHAR AbEntrySummary;                                                   //0x318
    UCHAR AbWaitEntryCount;                                                 //0x319
    UCHAR AbAllocationRegionCount;                                          //0x31a
    CHAR SystemPriority;                                                    //0x31b
    ULONG SecureThreadCookie;                                               //0x31c
    struct _KLOCK_ENTRY* LockEntries;                                       //0x320
    struct single_list_entry_t PropagateBoostsEntry;                         //0x328
    struct single_list_entry_t IoSelfBoostsEntry;                            //0x330
    UCHAR PriorityFloorCounts[16];                                          //0x338
    UCHAR PriorityFloorCountsReserved[16];                                  //0x348
    ULONG PriorityFloorSummary;                                             //0x358
    volatile LONG AbCompletedIoBoostCount;                                  //0x35c
    volatile LONG AbCompletedIoQoSBoostCount;                               //0x360
    volatile SHORT KeReferenceCount;                                        //0x364
    UCHAR AbOrphanedEntrySummary;                                           //0x366
    UCHAR AbOwnedEntryCount;                                                //0x367
    ULONG ForegroundLossTime;                                               //0x368
    union
    {
        struct list_entry_t GlobalForegroundListEntry;                       //0x370
        struct
        {
            struct single_list_entry_t ForegroundDpcStackListEntry;          //0x370
            ULONGLONG InGlobalForegroundList;                               //0x378
        };
    };
    LONGLONG ReadOperationCount;                                            //0x380
    LONGLONG WriteOperationCount;                                           //0x388
    LONGLONG OtherOperationCount;                                           //0x390
    LONGLONG ReadTransferCount;                                             //0x398
    LONGLONG WriteTransferCount;                                            //0x3a0
    LONGLONG OtherTransferCount;                                            //0x3a8
    struct _KSCB* QueuedScb;                                                //0x3b0
    volatile ULONG ThreadTimerDelay;                                        //0x3b8
    union
    {
        volatile LONG ThreadFlags3;                                         //0x3bc
        struct
        {
            ULONG ThreadFlags3Reserved : 8;                                   //0x3bc
            ULONG PpmPolicy : 2;                                              //0x3bc
            ULONG ThreadFlags3Reserved2 : 22;                                 //0x3bc
        };
    };
    ULONGLONG TracingPrivate[1];                                            //0x3c0
    VOID* SchedulerAssist;                                                  //0x3c8
    VOID* volatile AbWaitObject;                                            //0x3d0
    ULONG ReservedPreviousReadyTimeValue;                                   //0x3d8
    ULONGLONG KernelWaitTime;                                               //0x3e0
    ULONGLONG UserWaitTime;                                                 //0x3e8
    union
    {
        struct list_entry_t GlobalUpdateVpThreadPriorityListEntry;           //0x3f0
        struct
        {
            struct single_list_entry_t UpdateVpThreadPriorityDpcStackListEntry; //0x3f0
            ULONGLONG InGlobalUpdateVpThreadPriorityList;                   //0x3f8
        };
    };
    LONG SchedulerAssistPriorityFloor;                                      //0x400
    ULONG Spare28;                                                          //0x404
    ULONGLONG EndPadding[5];                                                //0x408
};



//0x898 bytes (sizeof)
struct ethread_t
{
    struct kthread_t Tcb;                                                    //0x0
    union _LARGE_INTEGER CreateTime;                                        //0x430
    union
    {
        union _LARGE_INTEGER ExitTime;                                      //0x438
        struct list_entry_t KeyedWaitChain;                                  //0x438
    };
    union
    {
        struct list_entry_t PostBlockList;                                   //0x448
        struct
        {
            VOID* ForwardLinkShadow;                                        //0x448
            VOID* StartAddress;                                             //0x450
        };
    };
    union
    {
        struct _TERMINATION_PORT* TerminationPort;                          //0x458
        struct ethread_t* ReaperLink;                                        //0x458
        VOID* KeyedWaitValue;                                               //0x458
    };
    ULONGLONG ActiveTimerListLock;                                          //0x460
    struct list_entry_t ActiveTimerListHead;                                 //0x468
    struct _CLIENT_ID Cid;                                                  //0x478
    union
    {
        struct _KSEMAPHORE KeyedWaitSemaphore;                              //0x488
        struct _KSEMAPHORE AlpcWaitSemaphore;                               //0x488
    };
    struct list_entry_t IrpList;                                             //0x4b0
    ULONGLONG TopLevelIrp;                                                  //0x4c0
    struct _DEVICE_OBJECT* DeviceToVerify;                                  //0x4c8
    VOID* Win32StartAddress;                                                //0x4d0
    VOID* ChargeOnlySession;                                                //0x4d8
    VOID* LegacyPowerObject;                                                //0x4e0
    struct list_entry_t ThreadListEntry;                                     //0x4e8
    struct _EX_RUNDOWN_REF RundownProtect;                                  //0x4f8
    ULONG ReadClusterSize;                                                  //0x508
    volatile LONG MmLockOrdering;                                           //0x50c
    union
    {
        ULONG CrossThreadFlags;                                             //0x510
        struct
        {
            ULONG Terminated : 1;                                             //0x510
            ULONG ThreadInserted : 1;                                         //0x510
            ULONG HideFromDebugger : 1;                                       //0x510
            ULONG ActiveImpersonationInfo : 1;                                //0x510
            ULONG HardErrorsAreDisabled : 1;                                  //0x510
            ULONG BreakOnTermination : 1;                                     //0x510
            ULONG SkipCreationMsg : 1;                                        //0x510
            ULONG SkipTerminationMsg : 1;                                     //0x510
            ULONG CopyTokenOnOpen : 1;                                        //0x510
            ULONG ThreadIoPriority : 3;                                       //0x510
            ULONG ThreadPagePriority : 3;                                     //0x510
            ULONG RundownFail : 1;                                            //0x510
            ULONG UmsForceQueueTermination : 1;                               //0x510
            ULONG IndirectCpuSets : 1;                                        //0x510
            ULONG DisableDynamicCodeOptOut : 1;                               //0x510
            ULONG ExplicitCaseSensitivity : 1;                                //0x510
            ULONG PicoNotifyExit : 1;                                         //0x510
            ULONG DbgWerUserReportActive : 1;                                 //0x510
            ULONG ForcedSelfTrimActive : 1;                                   //0x510
            ULONG SamplingCoverage : 1;                                       //0x510
            ULONG ReservedCrossThreadFlags : 8;                               //0x510
        };
    };
    union
    {
        ULONG SameThreadPassiveFlags;                                       //0x514
        struct
        {
            ULONG ActiveExWorker : 1;                                         //0x514
            ULONG MemoryMaker : 1;                                            //0x514
            ULONG StoreLockThread : 2;                                        //0x514
            ULONG ClonedThread : 1;                                           //0x514
            ULONG KeyedEventInUse : 1;                                        //0x514
            ULONG SelfTerminate : 1;                                          //0x514
            ULONG RespectIoPriority : 1;                                      //0x514
            ULONG ActivePageLists : 1;                                        //0x514
            ULONG SecureContext : 1;                                          //0x514
            ULONG ZeroPageThread : 1;                                         //0x514
            ULONG WorkloadClass : 1;                                          //0x514
            ULONG ReservedSameThreadPassiveFlags : 20;                        //0x514
        };
    };
    union
    {
        ULONG SameThreadApcFlags;                                           //0x518
        struct
        {
            UCHAR OwnsProcessAddressSpaceExclusive : 1;                       //0x518
            UCHAR OwnsProcessAddressSpaceShared : 1;                          //0x518
            UCHAR HardFaultBehavior : 1;                                      //0x518
            volatile UCHAR StartAddressInvalid : 1;                           //0x518
            UCHAR EtwCalloutActive : 1;                                       //0x518
            UCHAR SuppressSymbolLoad : 1;                                     //0x518
            UCHAR Prefetching : 1;                                            //0x518
            UCHAR OwnsVadExclusive : 1;                                       //0x518
            UCHAR SystemPagePriorityActive : 1;                               //0x519
            UCHAR SystemPagePriority : 3;                                     //0x519
            UCHAR AllowUserWritesToExecutableMemory : 1;                      //0x519
            UCHAR AllowKernelWritesToExecutableMemory : 1;                    //0x519
            UCHAR OwnsVadShared : 1;                                          //0x519
        };
    };
    UCHAR CacheManagerActive;                                               //0x51c
    UCHAR DisablePageFaultClustering;                                       //0x51d
    UCHAR ActiveFaultCount;                                                 //0x51e
    UCHAR LockOrderState;                                                   //0x51f
    ULONG PerformanceCountLowReserved;                                      //0x520
    LONG PerformanceCountHighReserved;                                      //0x524
    ULONGLONG AlpcMessageId;                                                //0x528
    union
    {
        VOID* AlpcMessage;                                                  //0x530
        ULONG AlpcReceiveAttributeSet;                                      //0x530
    };
    struct list_entry_t AlpcWaitListEntry;                                   //0x538
    LONG ExitStatus;                                                        //0x548
    ULONG CacheManagerCount;                                                //0x54c
    ULONG IoBoostCount;                                                     //0x550
    ULONG IoQoSBoostCount;                                                  //0x554
    ULONG IoQoSThrottleCount;                                               //0x558
    ULONG KernelStackReference;                                             //0x55c
    struct list_entry_t BoostList;                                           //0x560
    struct list_entry_t DeboostList;                                         //0x570
    ULONGLONG BoostListLock;                                                //0x580
    ULONGLONG IrpListLock;                                                  //0x588
    VOID* ReservedForSynchTracking;                                         //0x590
    struct single_list_entry_t CmCallbackListHead;                           //0x598
    struct _GUID* ActivityId;                                               //0x5a0
    struct single_list_entry_t SeLearningModeListHead;                       //0x5a8
    VOID* VerifierContext;                                                  //0x5b0
    VOID* AdjustedClientToken;                                              //0x5b8
    VOID* WorkOnBehalfThread;                                               //0x5c0
    VOID* PicoContext;                                                      //0x5e0
    ULONGLONG UserFsBase;                                                   //0x5e8
    ULONGLONG UserGsBase;                                                   //0x5f0
    struct _THREAD_ENERGY_VALUES* EnergyValues;                             //0x5f8
    union
    {
        ULONGLONG SelectedCpuSets;                                          //0x600
        ULONGLONG* SelectedCpuSetsIndirect;                                 //0x600
    };
    struct _EJOB* Silo;                                                     //0x608
    struct _UNICODE_STRING* ThreadName;                                     //0x610
    struct _CONTEXT* SetContextState;                                       //0x618
    ULONG LastExpectedRunTime;                                              //0x620
    ULONG HeapData;                                                         //0x624
    struct list_entry_t OwnerEntryListHead;                                  //0x628
    ULONGLONG DisownedOwnerEntryListLock;                                   //0x638
    struct list_entry_t DisownedOwnerEntryListHead;                          //0x640
    VOID* CmDbgInfo;                                                        //0x890
};

struct xmm_save_area32_t {
    std::uint16_t m_control_word;
    std::uint16_t m_status_word;
    std::uint8_t m_tag_word;
    std::uint8_t m_reserved1;
    std::uint16_t m_error_opcode;
    std::uint32_t m_error_offset;
    std::uint16_t m_error_selector;
    std::uint16_t m_reserved2;
    std::uint32_t m_data_offset;
    std::uint16_t m_data_selector;
    std::uint16_t m_reserved3;
    std::uint32_t m_mx_csr;
    std::uint32_t m_mx_csr_mask;
    std::m128a_t m_float_registers[8];
    std::m128a_t m_xmm_registers[16];
    std::uint8_t m_reserved4[96];
};

//0x4d0 bytes (sizeof)
struct context_t
{
    ULONGLONG P1Home;                                                       //0x0
    ULONGLONG P2Home;                                                       //0x8
    ULONGLONG P3Home;                                                       //0x10
    ULONGLONG P4Home;                                                       //0x18
    ULONGLONG P5Home;                                                       //0x20
    ULONGLONG P6Home;                                                       //0x28
    ULONG ContextFlags;                                                     //0x30
    ULONG MxCsr;                                                            //0x34
    USHORT SegCs;                                                           //0x38
    USHORT SegDs;                                                           //0x3a
    USHORT SegEs;                                                           //0x3c
    USHORT SegFs;                                                           //0x3e
    USHORT SegGs;                                                           //0x40
    USHORT SegSs;                                                           //0x42
    ULONG EFlags;                                                           //0x44
    ULONGLONG Dr0;                                                          //0x48
    ULONGLONG Dr1;                                                          //0x50
    ULONGLONG Dr2;                                                          //0x58
    ULONGLONG Dr3;                                                          //0x60
    ULONGLONG Dr6;                                                          //0x68
    ULONGLONG Dr7;                                                          //0x70
    ULONGLONG Rax;                                                          //0x78
    ULONGLONG Rcx;                                                          //0x80
    ULONGLONG Rdx;                                                          //0x88
    ULONGLONG Rbx;                                                          //0x90
    ULONGLONG Rsp;                                                          //0x98
    ULONGLONG Rbp;                                                          //0xa0
    ULONGLONG Rsi;                                                          //0xa8
    ULONGLONG Rdi;                                                          //0xb0
    ULONGLONG R8;                                                           //0xb8
    ULONGLONG R9;                                                           //0xc0
    ULONGLONG R10;                                                          //0xc8
    ULONGLONG R11;                                                          //0xd0
    ULONGLONG R12;                                                          //0xd8
    ULONGLONG R13;                                                          //0xe0
    ULONGLONG R14;                                                          //0xe8
    ULONGLONG R15;                                                          //0xf0
    ULONGLONG Rip;                                                          //0xf8
    union
    {
        struct _XSAVE_FORMAT FltSave;                                       //0x100
        struct
        {
            struct _M128A Header[2];                                        //0x100
            struct _M128A Legacy[8];                                        //0x120
            struct _M128A Xmm0;                                             //0x1a0
            struct _M128A Xmm1;                                             //0x1b0
            struct _M128A Xmm2;                                             //0x1c0
            struct _M128A Xmm3;                                             //0x1d0
            struct _M128A Xmm4;                                             //0x1e0
            struct _M128A Xmm5;                                             //0x1f0
            struct _M128A Xmm6;                                             //0x200
            struct _M128A Xmm7;                                             //0x210
            struct _M128A Xmm8;                                             //0x220
            struct _M128A Xmm9;                                             //0x230
            struct _M128A Xmm10;                                            //0x240
            struct _M128A Xmm11;                                            //0x250
            struct _M128A Xmm12;                                            //0x260
            struct _M128A Xmm13;                                            //0x270
            struct _M128A Xmm14;                                            //0x280
            struct _M128A Xmm15;                                            //0x290
        };
    };
    struct _M128A VectorRegister[26];                                       //0x300
    ULONGLONG VectorControl;                                                //0x4a0
    ULONGLONG DebugControl;                                                 //0x4a8
    ULONGLONG LastBranchToRip;                                              //0x4b0
    ULONGLONG LastBranchFromRip;                                            //0x4b8
    ULONGLONG LastExceptionToRip;                                           //0x4c0
    ULONGLONG LastExceptionFromRip;                                         //0x4c8
};

struct kirql_t {
    static constexpr std::uint8_t m_passive_level = 0x00;
    static constexpr std::uint8_t m_apc_level = 0x01;
    static constexpr std::uint8_t m_dispatch_level = 0x02;
    static constexpr std::uint8_t m_cmci_level = 0x03;
    static constexpr std::uint8_t m_clock_level = 0x0D;
    static constexpr std::uint8_t m_ipi_level = 0x0E;
    static constexpr std::uint8_t m_dpc_level = 0x02;
    static constexpr std::uint8_t m_power_level = 0x0D;
    static constexpr std::uint8_t m_profile_level = 0x0F;
    static constexpr std::uint8_t m_device0_level = 0x03;
    static constexpr std::uint8_t m_device1_level = 0x04;
    static constexpr std::uint8_t m_device2_level = 0x05;
    static constexpr std::uint8_t m_device3_level = 0x06;
    static constexpr std::uint8_t m_device4_level = 0x07;
    static constexpr std::uint8_t m_device5_level = 0x08;
    static constexpr std::uint8_t m_device6_level = 0x09;
    static constexpr std::uint8_t m_device7_level = 0x0A;
    static constexpr std::uint8_t m_device8_level = 0x0B;
    static constexpr std::uint8_t m_device9_level = 0x0C;
    static constexpr std::uint8_t m_device10_level = 0x0D;
    static constexpr std::uint8_t m_device11_level = 0x0E;
    static constexpr std::uint8_t m_device12_level = 0x0F;
    static constexpr std::uint8_t m_device13_level = 0x10;
    static constexpr std::uint8_t m_device14_level = 0x11;
    static constexpr std::uint8_t m_device15_level = 0x12;
    static constexpr std::uint8_t m_high_level = 0x1F;
}; // Size: 0x020

//0x700 bytes (sizeof)
struct kpcrb_t
{
    ULONG MxCsr;                                                            //0x0
    UCHAR LegacyNumber;                                                     //0x4
    UCHAR ReservedMustBeZero;                                               //0x5
    UCHAR InterruptRequest;                                                 //0x6
    UCHAR IdleHalt;                                                         //0x7
    struct kthread_t* CurrentThread;                                         //0x8
    struct kthread_t* NextThread;                                            //0x10
    struct kthread_t* IdleThread;                                            //0x18
    UCHAR NestingLevel;                                                     //0x20
    UCHAR ClockOwner;                                                       //0x21
    union
    {
        UCHAR PendingTickFlags;                                             //0x22
        struct
        {
            UCHAR PendingTick : 1;                                            //0x22
            UCHAR PendingBackupTick : 1;                                      //0x22
        };
    };
    UCHAR IdleState;                                                        //0x23
    ULONG Number;                                                           //0x24
    ULONGLONG RspBase;                                                      //0x28
    ULONGLONG PrcbLock;                                                     //0x30
    CHAR* PriorityState;                                                    //0x38
    CHAR CpuType;                                                           //0x40
    CHAR CpuID;                                                             //0x41
    union
    {
        USHORT CpuStep;                                                     //0x42
        struct
        {
            UCHAR CpuStepping;                                              //0x42
            UCHAR CpuModel;                                                 //0x43
        };
    };
    ULONG MHz;                                                              //0x44
    ULONGLONG HalReserved[8];                                               //0x48
    USHORT MinorVersion;                                                    //0x88
    USHORT MajorVersion;                                                    //0x8a
    UCHAR BuildType;                                                        //0x8c
    UCHAR CpuVendor;                                                        //0x8d
    UCHAR LegacyCoresPerPhysicalProcessor;                                  //0x8e
    UCHAR LegacyLogicalProcessorsPerCore;                                   //0x8f
    ULONGLONG TscFrequency;                                                 //0x90
    ULONG CoresPerPhysicalProcessor;                                        //0x98
    ULONG LogicalProcessorsPerCore;                                         //0x9c
    ULONGLONG PrcbPad04[4];                                                 //0xa0
    struct _KNODE* ParentNode;                                              //0xc0
    ULONGLONG GroupSetMember;                                               //0xc8
    UCHAR Group;                                                            //0xd0
    UCHAR GroupIndex;                                                       //0xd1
    UCHAR PrcbPad05[2];                                                     //0xd2
    ULONG InitialApicId;                                                    //0xd4
    ULONG ScbOffset;                                                        //0xd8
    ULONG ApicMask;                                                         //0xdc
    VOID* AcpiReserved;                                                     //0xe0
    ULONG CFlushSize;                                                       //0xe8
    ULONGLONG PrcbPad11[2];                                                 //0xf0
    struct _XSAVE_AREA_HEADER* ExtendedSupervisorState;                     //0x6c0
    ULONG ProcessorSignature;                                               //0x6c8
    ULONG ProcessorFlags;                                                   //0x6cc
    ULONGLONG PrcbPad12a;                                                   //0x6d0
    ULONGLONG PrcbPad12[3];                                                 //0x6d8
};





enum class system_information_class_t : std::uint32_t {
    basic_information = 0,
    performance_information = 2,
    time_of_day_information = 3,
    process_information = 5,
    processor_performance_information = 8,
    interrupt_information = 23,
    exception_information = 33,
    registry_quota_information = 37,
    lookaside_information = 45
};

struct system_basic_information_t {
    std::uint32_t m_reserved;
    std::uint32_t m_timer_resolution;
    std::uint32_t m_page_size;
    std::uint32_t m_number_of_physical_pages;
    std::uint32_t m_lowest_physical_page_number;
    std::uint32_t m_highest_physical_page_number;
    std::uint32_t m_allocation_granularity;
    std::uintptr_t m_minimum_user_mode_address;
    std::uintptr_t m_maximum_user_mode_address;
    std::uintptr_t m_active_processors_affinity_mask;
    std::int8_t m_number_of_processors;
};

struct rtl_balanced_node_t {
    union {
        rtl_balanced_node_t* m_children[2];
        struct {
            rtl_balanced_node_t* m_left;
            rtl_balanced_node_t* m_right;
        };
    };
    union {
        std::uint8_t m_red : 1;
        rtl_balanced_node_t* m_parent;
        std::uint64_t m_value;
    };
};






struct mipfnblink_t {
    union {
        std::uint64_t m_blink : 40;
        std::uint64_t m_type_size : 24;
    };
};

struct rtl_process_module_info_t {
    void* m_section;
    void* m_mapped_base;
    void* m_image_base;
    std::uint32_t   m_image_size;
    std::uint32_t   m_flags;
    std::uint16_t   m_load_order_index;
    std::uint16_t   m_init_order_index;
    std::uint16_t   m_load_count;
    std::uint16_t   m_offset_to_filename;
    std::uint8_t    m_full_path_name[256];
};

struct rtl_process_modules_t {
    std::uint32_t               m_number_of_modules;
    rtl_process_module_info_t   m_modules[1];
};

struct mmpfnentry1_t {
    std::uint8_t m_page_color : 6;
    std::uint8_t m_modified : 1;
    std::uint8_t m_read_in_progress : 1;
};

struct mmpfnentry3_t {
    std::uint8_t m_write_in_progress : 1;
    std::uint8_t m_protection_code : 5;
    std::uint8_t m_modified_write : 1;
    std::uint8_t m_read_in_progress : 1;
};

struct mi_pfn_ulong5_t {
    union {
        struct {
            std::uint32_t m_modified_write_count : 16;
            std::uint32_t m_shared_count : 16;
        };
        std::uint32_t m_entire_field;
    };
};

//0x8 bytes (sizeof)
struct mi_active_pfn_t
{
    union
    {
        struct
        {
            ULONGLONG Tradable : 1;                                           //0x0
            ULONGLONG NonPagedBuddy : 43;                                     //0x0
        } Leaf;                                                             //0x0
        struct
        {
            ULONGLONG Tradable : 1;                                           //0x0
            ULONGLONG WsleAge : 3;                                            //0x0
            ULONGLONG OldestWsleLeafEntries : 10;                             //0x0
            ULONGLONG OldestWsleLeafAge : 3;                                  //0x0
            ULONGLONG NonPagedBuddy : 43;                                     //0x0
        } PageTable;                                                        //0x0
        ULONGLONG EntireActiveField;                                        //0x0
    };
};

//0x8 bytes (sizeof)
struct mmpte_hardware_t
{
    ULONGLONG Valid : 1;                                                      //0x0
    ULONGLONG Dirty1 : 1;                                                     //0x0
    ULONGLONG Owner : 1;                                                      //0x0
    ULONGLONG WriteThrough : 1;                                               //0x0
    ULONGLONG CacheDisable : 1;                                               //0x0
    ULONGLONG Accessed : 1;                                                   //0x0
    ULONGLONG Dirty : 1;                                                      //0x0
    ULONGLONG LargePage : 1;                                                  //0x0
    ULONGLONG Global : 1;                                                     //0x0
    ULONGLONG CopyOnWrite : 1;                                                //0x0
    ULONGLONG Unused : 1;                                                     //0x0
    ULONGLONG Write : 1;                                                      //0x0
    ULONGLONG PageFrameNumber : 36;                                           //0x0
    ULONGLONG ReservedForHardware : 4;                                        //0x0
    ULONGLONG ReservedForSoftware : 4;                                        //0x0
    ULONGLONG WsleAge : 4;                                                    //0x0
    ULONGLONG WsleProtection : 3;                                             //0x0
    ULONGLONG NoExecute : 1;                                                  //0x0
};

//0x8 bytes (sizeof)
struct mmpte_prototype_t
{
    ULONGLONG Valid : 1;                                                      //0x0
    ULONGLONG DemandFillProto : 1;                                            //0x0
    ULONGLONG HiberVerifyConverted : 1;                                       //0x0
    ULONGLONG ReadOnly : 1;                                                   //0x0
    ULONGLONG SwizzleBit : 1;                                                 //0x0
    ULONGLONG Protection : 5;                                                 //0x0
    ULONGLONG Prototype : 1;                                                  //0x0
    ULONGLONG Combined : 1;                                                   //0x0
    ULONGLONG Unused1 : 4;                                                    //0x0
    LONGLONG ProtoAddress : 48;                                               //0x0
};

//0x8 bytes (sizeof)
struct mmpte_software_t
{
    ULONGLONG Valid : 1;                                                      //0x0
    ULONGLONG PageFileReserved : 1;                                           //0x0
    ULONGLONG PageFileAllocated : 1;                                          //0x0
    ULONGLONG ColdPage : 1;                                                   //0x0
    ULONGLONG SwizzleBit : 1;                                                 //0x0
    ULONGLONG Protection : 5;                                                 //0x0
    ULONGLONG Prototype : 1;                                                  //0x0
    ULONGLONG Transition : 1;                                                 //0x0
    ULONGLONG PageFileLow : 4;                                                //0x0
    ULONGLONG UsedPageTableEntries : 10;                                      //0x0
    ULONGLONG ShadowStack : 1;                                                //0x0
    ULONGLONG Unused : 5;                                                     //0x0
    ULONGLONG PageFileHigh : 32;                                              //0x0
};

//0x8 bytes (sizeof)
struct mmpte_timestamp_t
{
    ULONGLONG MustBeZero : 1;                                                 //0x0
    ULONGLONG Unused : 3;                                                     //0x0
    ULONGLONG SwizzleBit : 1;                                                 //0x0
    ULONGLONG Protection : 5;                                                 //0x0
    ULONGLONG Prototype : 1;                                                  //0x0
    ULONGLONG Transition : 1;                                                 //0x0
    ULONGLONG PageFileLow : 4;                                                //0x0
    ULONGLONG Reserved : 16;                                                  //0x0
    ULONGLONG GlobalTimeStamp : 32;                                           //0x0
};

//0x8 bytes (sizeof)
struct mmpte_trans_t
{
    ULONGLONG Valid : 1;                                                      //0x0
    ULONGLONG Write : 1;                                                      //0x0
    ULONGLONG Spare : 1;                                                      //0x0
    ULONGLONG IoTracker : 1;                                                  //0x0
    ULONGLONG SwizzleBit : 1;                                                 //0x0
    ULONGLONG Protection : 5;                                                 //0x0
    ULONGLONG Prototype : 1;                                                  //0x0
    ULONGLONG Transition : 1;                                                 //0x0
    ULONGLONG PageFrameNumber : 36;                                           //0x0
    ULONGLONG Unused : 16;                                                    //0x0
};

//0x8 bytes (sizeof)
struct mmpte_subsection_t
{
    ULONGLONG Valid : 1;                                                      //0x0
    ULONGLONG Unused0 : 3;                                                    //0x0
    ULONGLONG SwizzleBit : 1;                                                 //0x0
    ULONGLONG Protection : 5;                                                 //0x0
    ULONGLONG Prototype : 1;                                                  //0x0
    ULONGLONG ColdPage : 1;                                                   //0x0
    ULONGLONG Unused1 : 3;                                                    //0x0
    ULONGLONG ExecutePrivilege : 1;                                           //0x0
    LONGLONG SubsectionAddress : 48;                                          //0x0
};

//0x8 bytes (sizeof)
struct mmpte_list_t
{
    ULONGLONG Valid : 1;                                                      //0x0
    ULONGLONG OneEntry : 1;                                                   //0x0
    ULONGLONG filler0 : 2;                                                    //0x0
    ULONGLONG SwizzleBit : 1;                                                 //0x0
    ULONGLONG Protection : 5;                                                 //0x0
    ULONGLONG Prototype : 1;                                                  //0x0
    ULONGLONG Transition : 1;                                                 //0x0
    ULONGLONG filler1 : 16;                                                   //0x0
    ULONGLONG NextEntry : 36;                                                 //0x0
};

//0x8 bytes (sizeof)
struct mmpte_t
{
    union
    {
        ULONGLONG Long;                                                     //0x0
        volatile ULONGLONG VolatileLong;                                    //0x0
        struct mmpte_hardware_t Hard;                                        //0x0
        struct mmpte_prototype_t Proto;                                      //0x0
        struct mmpte_software_t Soft;                                        //0x0
        struct mmpte_timestamp_t TimeStamp;                                  //0x0
        struct mmpte_trans_t Trans;                                     //0x0
        struct mmpte_subsection_t Subsect;                                   //0x0
        struct mmpte_list_t List;                                            //0x0
    } u;                                                                    //0x0
};

//0x30 bytes (sizeof)
struct mmpfn_t
{
    union
    {
        struct list_entry_t ListEntry;                                       //0x0
        struct _RTL_BALANCED_NODE TreeNode;                                 //0x0
        struct
        {
            union
            {
                struct single_list_entry_t NextSlistPfn;                     //0x0
                VOID* Next;                                                 //0x0
                ULONGLONG Flink : 36;                                         //0x0
                ULONGLONG NodeFlinkHigh : 28;                                 //0x0
                struct mi_active_pfn_t Active;                               //0x0
            } u1;                                                           //0x0
            union
            {
                struct mmpte_t* PteAddress;                                  //0x8
                ULONGLONG PteLong;                                          //0x8
            };
            struct mmpte_t OriginalPte;                                      //0x10
        };
    };
    union
    {
        struct
        {
            USHORT ReferenceCount;                                          //0x20
        };
        struct
        {
            struct
            {
                USHORT ReferenceCount;                                          //0x20
            } e2;                                                               //0x20
        };
        struct
        {
            ULONG EntireField;                                              //0x20
        } e4;                                                               //0x20
    } u3;                                                                   //0x20
    USHORT NodeBlinkLow;                                                    //0x24
    UCHAR Unused : 4;                                                         //0x26
    UCHAR Unused2 : 4;                                                        //0x26
    union
    {
        UCHAR ViewCount;                                                    //0x27
        UCHAR NodeFlinkLow;                                                 //0x27
        struct
        {
            UCHAR ModifiedListBucketIndex : 4;                                //0x27
            UCHAR AnchorLargePageSize : 2;                                    //0x27
        };
    };
    union
    {
        ULONGLONG PteFrame : 36;                                              //0x28
        ULONGLONG ResidentPage : 1;                                           //0x28
        ULONGLONG Unused1 : 1;                                                //0x28
        ULONGLONG Unused2 : 1;                                                //0x28
        ULONGLONG Partition : 10;                                             //0x28
        ULONGLONG FileOnly : 1;                                               //0x28
        ULONGLONG PfnExists : 1;                                              //0x28
        ULONGLONG Spare : 9;                                                  //0x28
        ULONGLONG PageIdentity : 3;                                           //0x28
        ULONGLONG PrototypePte : 1;                                           //0x28
        ULONGLONG EntireField;                                              //0x28
    } u4;                                                                   //0x28
};

struct handle_table_entry_info_t {
    std::uint32_t m_audit_mask;                     // +0x000
    std::uint32_t m_max_relative_access_mask;       // +0x004
}; // Size: 0x008


//0x8 bytes (sizeof)
struct exhandle_t
{
    union
    {
        struct
        {
            ULONG TagBits : 2;                                                //0x0
            ULONG Index : 30;                                                 //0x0
        };
        VOID* GenericHandleOverlay;                                         //0x0
        ULONGLONG Value;                                                    //0x0
    };
};

//0x10 bytes (sizeof)
struct handle_table_entry_t
{
    union  // ADD UNION HERE
    {
        volatile LONGLONG VolatileLowValue;                                 //0x0
        LONGLONG LowValue;                                                  //0x0
        LONGLONG RefCountField;                                             //0x0
        struct _HANDLE_TABLE_ENTRY_INFO* volatile InfoTable;                //0x0

        struct  // All bitfields for low value in ONE struct
        {
            ULONGLONG Unlocked : 1;                                         //0x0 Bit 0
            ULONGLONG RefCnt : 16;                                          //0x0 Bits 1-16
            ULONGLONG Attributes : 3;                                       //0x0 Bits 17-19
            ULONGLONG ObjectPointerBits : 44;                               //0x0 Bits 20-63
        };
    };

    union  // ADD UNION HERE
    {
        LONGLONG HighValue;                                                 //0x8
        struct handle_table_entry_t* NextFreeHandleEntry;                   //0x8
        struct exhandle_t LeafHandleValue;                                  //0x8

        struct  // All bitfields for high value in ONE struct
        {
            ULONG GrantedAccessBits : 25;                                   //0x8 Bits 0-24
            ULONG NoRightsUpgrade : 1;                                      //0x8 Bit 25
            ULONG Spare1 : 6;                                               //0x8 Bits 26-31
        };
    };

    ULONG Spare2;                                                           //0xc
};

//0x8 bytes (sizeof)


//0x40 bytes (sizeof)
struct handle_table_free_list_t
{
    struct ex_push_lock_t FreeListLock;                                      //0x0
    union _HANDLE_TABLE_ENTRY* FirstFreeHandleEntry;                        //0x8
    union _HANDLE_TABLE_ENTRY* LastFreeHandleEntry;                         //0x10
    LONG HandleCount;                                                       //0x18
    ULONG HighWaterMark;                                                    //0x1c
};

//0x80 bytes (sizeof)
struct handle_table_t
{
    ULONG NextHandleNeedingPool;                                            //0x0
    LONG ExtraInfoPages;                                                    //0x4
    volatile ULONGLONG TableCode;                                           //0x8
    struct eprocess_t* QuotaProcess;                                         //0x10
    struct list_entry_t HandleTableList;                                     //0x18
    ULONG UniqueProcessId;                                                  //0x28
    union
    {
        ULONG Flags;                                                        //0x2c
        struct
        {
            UCHAR StrictFIFO : 1;                                             //0x2c
            UCHAR EnableHandleExceptions : 1;                                 //0x2c
            UCHAR Rundown : 1;                                                //0x2c
            UCHAR Duplicated : 1;                                             //0x2c
            UCHAR RaiseUMExceptionOnInvalidHandleClose : 1;                   //0x2c
        };
    };
    struct ex_push_lock_t HandleContentionEvent;                             //0x30
    struct ex_push_lock_t HandleTableLock;                                   //0x38
    union
    {
        struct handle_table_free_list_t FreeLists[1];                        //0x40
        struct
        {
            UCHAR ActualEntry[32];                                          //0x40
            struct _HANDLE_TRACE_DEBUG_INFO* DebugInfo;                     //0x60
        };
    };
};
struct nmi_handler_callback_t {
    nmi_handler_callback_t* m_next;     // +0x000 Points to next entry in list
    void* m_callback;  // +0x008 NMI callback routine
    void* m_context;   // +0x010 Context passed to callback
    void* m_handle;    // +0x018 Registration handle (points to self)
};

struct physical_memory_range_t {
    union {
        std::uint64_t m_base_page;              // +0x000
        struct {
            std::uint64_t m_page_offset : 12;   // Bits 0-11
            std::uint64_t m_base_address : 52;  // Bits 12-63
        };
    };
    union {
        std::uint64_t m_page_count;             // +0x008
        struct {
            std::uint64_t m_unused : 12;        // Bits 0-11
            std::uint64_t m_count : 52;         // Bits 12-63
        };
    };
}; // Size: 0x010

struct physical_address_t {
    union {
        struct {
            std::uint32_t m_low_part;      // +0x000
            std::int32_t m_high_part;      // +0x004
        };
        struct {
            std::uint64_t m_quad_part;     // +0x000
        };
    };
}; // Size: 0x008

struct mm_copy_address_t {
    union {
        std::uint64_t m_virtual_address;    // +0x000
        physical_address_t m_physical_address;   // +0x000
    };
}; // Size: 0x008

struct object_type_initializer_t {
    std::uint16_t m_length;
    std::uint8_t m_unused;
    std::uint8_t m_object_type_flags;
    std::uint32_t m_object_type_code;
    std::uint32_t m_invalid_attributes;
    std::uint32_t m_generic_mapping;
    std::uint32_t m_valid_access;
    std::uint8_t m_retain_access;
    std::uint8_t m_pool_type;
    std::uint32_t m_default_page_charge;
    std::uint32_t m_security_required;
    void* m_security_procedure;
    void* m_delete_procedure;
    void* m_close_procedure;
    void* m_parse_procedure;
    void* m_security_procedure2;
    void* m_query_name_procedure;
    void* m_okayto_close_procedure;
};

struct object_type_t {
    list_entry_t m_type_list;                          // 0x00
    unicode_string_t m_name;                           // 0x10
    void* m_default_object;                            // 0x20
    std::uint8_t m_index;                             // 0x28
    std::uint8_t m_pad0[3];                          // 0x29
    std::uint32_t m_total_number_of_objects;          // 0x2C
    std::uint32_t m_total_number_of_handles;          // 0x30
    std::uint32_t m_high_water_number_of_objects;     // 0x34
    std::uint32_t m_high_water_number_of_handles;     // 0x38
    std::uint8_t m_pad1[4];                          // 0x3C
    object_type_initializer_t m_type_info;            // 0x40
    std::uint64_t m_type_lock;                        // 0xB8
    std::uint32_t m_key;                              // 0xC0
    std::uint8_t m_pad2[4];                          // 0xC4
    list_entry_t m_callback_list;                     // 0xC8
};

using p_nmi_callback = void (*)(
    void* context,                   // Context passed during registration
    void* register_area              // CPU register state during NMI
    );

enum class ps_create_state_t : std::uint32_t {
    ps_create_initial = 0,
    ps_create_failed = 1,
    ps_create_success = 2,
    // Add any additional states if needed
};

struct ps_create_initial_t {
    std::uint32_t m_output_flags;                    // +0x000
    std::uint32_t m_file_handle;                     // +0x004
    std::uint32_t m_section_handle;                  // +0x008
    std::uint64_t m_user_process_parameters;         // +0x010
    std::uint32_t m_create_flags;                    // +0x018
    std::uint32_t m_reserved;                        // +0x01C
}; // Size: 0x020

struct ps_create_success_t {
    void* m_kernel_handle;                        // +0x000
    void* m_user_process_parameters;              // +0x008
    void* m_kernel_thread;                        // +0x010
    void* m_kernel_process;                       // +0x018
    void* m_thread_info;                          // +0x020
    void* m_process_info;                         // +0x028
}; // Size: 0x030

struct ps_create_failure_t {
    nt_status_t m_error_code;                          // +0x000
    std::uint32_t m_padding;                        // +0x004
    void* m_failed_handle;                       // +0x008
}; // Size: 0x010

struct ps_create_info_t {
    std::uint32_t m_size;                          // +0x000
    ps_create_state_t m_state;                     // +0x004
    union {
        ps_create_success_t m_success;              // +0x008
        ps_create_failure_t m_failure;              // +0x008
        ps_create_initial_t m_initial;              // +0x008
    };
}; // Size: 0x038

struct ps_attribute_t {
    std::uint32_t m_attribute;              // +0x000
    std::size_t m_size;                          // +0x004
    union {
        std::addr_t m_value;                     // +0x008
        void* m_value_ptr;                  // +0x008
    };
    std::size_t* m_return_length;                // +0x010
}; // Size: 0x018

struct ps_attribute_list_t {
    std::size_t m_total_length;                  // +0x000
    ps_attribute_t m_attributes[2];         // +0x008
}; // Size: 0x038

struct section_image_information_t {
    std::addr_t m_entry_point;                   // +0x000
    std::uint32_t m_stack_zero_bits;        // +0x008
    std::uint32_t m_stack_commit_size;      // +0x00C
    std::uint32_t m_stack_reserve_size;     // +0x010
    std::uint64_t m_subsystem_version;             // +0x018
    std::uint32_t m_dll_characteristics;    // +0x020
    std::uint16_t m_machine;                // +0x024
    std::uint8_t m_image_contains_code;     // +0x026
    std::uint8_t m_image_flags;             // +0x027
    std::uint16_t m_system_dll;             // +0x028
    std::uint16_t m_dll_count;              // +0x02A
    std::uint32_t m_lock_prefix_table;      // +0x02C
    std::uint32_t m_lock_prefix_count;      // +0x030
}; // Size: 0x034

struct object_attributes_t {
    std::uint32_t m_length;                  // +0x000
    void* m_root_directory;               // +0x008
    unicode_string_t* m_object_name;         // +0x010
    std::uint32_t m_attributes;              // +0x018
    void* m_security_descriptor;             // +0x020
    void* m_security_qos;                    // +0x028
}; // Size: 0x030

enum pool_type
{
    nonpaged_pool,
    nonpaged_pool_execute = nonpaged_pool,
    paged_pool,
    nonpaged_pool_must_succeed = nonpaged_pool + 2,
    dont_use_this_type,
    nonpaged_pool_cache_aligned = nonpaged_pool + 4,
    paged_pool_cache_aligned,
    nonpaged_pool_cache_aligned_must_s = nonpaged_pool + 6,
    max_pool_type,

    nonpaged_pool_base = 0,
    nonpaged_pool_base_must_succeed = nonpaged_pool_base + 2,
    nonpaged_pool_base_cache_aligned = nonpaged_pool_base + 4,
    nonpaged_pool_base_cache_aligned_must_s = nonpaged_pool_base + 6,

    nonpaged_pool_session = 32,
    paged_pool_session = nonpaged_pool_session + 1,
    nonpaged_pool_must_succeed_session = paged_pool_session + 1,
    dont_use_this_type_session = nonpaged_pool_must_succeed_session + 1,
    nonpaged_pool_cache_aligned_session = dont_use_this_type_session + 1,
    paged_pool_cache_aligned_session = nonpaged_pool_cache_aligned_session + 1,
    nonpaged_pool_cache_aligned_must_s_session = paged_pool_cache_aligned_session + 1,

    nonpaged_pool_nx = 512,
    nonpaged_pool_nx_cache_aligned = nonpaged_pool_nx + 4,
    nonpaged_pool_session_nx = nonpaged_pool_nx + 32,
};



#endif // !IA32_H

