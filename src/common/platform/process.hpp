#pragma once

// NOLINTBEGIN(modernize-use-using,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-use-enum-class)

#ifndef OS_WINDOWS
#define CREATE_SUSPENDED 0x00000004
#endif

#define CONTEXT_X86_MAIN              0x00010000
#define CONTEXT_AMD64_MAIN            0x100000
#define CONTEXT_CONTROL_32            (CONTEXT_X86_MAIN | 0x1L)
#define CONTEXT_CONTROL_64            (CONTEXT_AMD64_MAIN | 0x1L)
#define CONTEXT_INTEGER_32            (CONTEXT_X86_MAIN | 0x2L)
#define CONTEXT_INTEGER_64            (CONTEXT_AMD64_MAIN | 0x2L)
#define CONTEXT_SEGMENTS_32           (CONTEXT_X86_MAIN | 0x4L)
#define CONTEXT_SEGMENTS_64           (CONTEXT_AMD64_MAIN | 0x4L)
#define CONTEXT_FLOATING_POINT_32     (CONTEXT_X86_MAIN | 0x8L)
#define CONTEXT_FLOATING_POINT_64     (CONTEXT_AMD64_MAIN | 0x8L)
#define CONTEXT_DEBUG_REGISTERS_32    (CONTEXT_X86_MAIN | 0x10L)
#define CONTEXT_DEBUG_REGISTERS_64    (CONTEXT_AMD64_MAIN | 0x10L)
#define CONTEXT_EXTENDED_REGISTERS_32 (CONTEXT_X86_MAIN | 0x20L)
#define CONTEXT_XSTATE_32             (CONTEXT_X86_MAIN | 0x40L)
#define CONTEXT_XSTATE_64             (CONTEXT_AMD64_MAIN | 0x40L)

#define CONTEXT64_ALL \
    (CONTEXT_CONTROL_64 | CONTEXT_INTEGER_64 | CONTEXT_SEGMENTS_64 | CONTEXT_FLOATING_POINT_64 | CONTEXT_DEBUG_REGISTERS_64)

#define CONTEXT32_ALL                                                                                                         \
    (CONTEXT_CONTROL_32 | CONTEXT_INTEGER_32 | CONTEXT_SEGMENTS_32 | CONTEXT_FLOATING_POINT_32 | CONTEXT_DEBUG_REGISTERS_32 | \
     CONTEXT_EXTENDED_REGISTERS_32)

#include "system_enums.hpp"

#ifndef OS_WINDOWS
typedef enum _TOKEN_INFORMATION_CLASS
{
    TokenUser = 1,                        // q: TOKEN_USER, SE_TOKEN_USER
    TokenGroups,                          // q: TOKEN_GROUPS
    TokenPrivileges,                      // q: TOKEN_PRIVILEGES
    TokenOwner,                           // q; s: TOKEN_OWNER
    TokenPrimaryGroup,                    // q; s: TOKEN_PRIMARY_GROUP
    TokenDefaultDacl,                     // q; s: TOKEN_DEFAULT_DACL
    TokenSource,                          // q: TOKEN_SOURCE
    TokenType,                            // q: TOKEN_TYPE
    TokenImpersonationLevel,              // q: SECURITY_IMPERSONATION_LEVEL
    TokenStatistics,                      // q: TOKEN_STATISTICS // 10
    TokenRestrictedSids,                  // q: TOKEN_GROUPS
    TokenSessionId,                       // q; s: ULONG (requires SeTcbPrivilege)
    TokenGroupsAndPrivileges,             // q: TOKEN_GROUPS_AND_PRIVILEGES
    TokenSessionReference,                // s: ULONG (requires SeTcbPrivilege)
    TokenSandBoxInert,                    // q: ULONG
    TokenAuditPolicy,                     // q; s: TOKEN_AUDIT_POLICY (requires SeSecurityPrivilege/SeTcbPrivilege)
    TokenOrigin,                          // q; s: TOKEN_ORIGIN (requires SeTcbPrivilege)
    TokenElevationType,                   // q: TOKEN_ELEVATION_TYPE
    TokenLinkedToken,                     // q; s: TOKEN_LINKED_TOKEN (requires SeCreateTokenPrivilege)
    TokenElevation,                       // q: TOKEN_ELEVATION // 20
    TokenHasRestrictions,                 // q: ULONG
    TokenAccessInformation,               // q: TOKEN_ACCESS_INFORMATION
    TokenVirtualizationAllowed,           // q; s: ULONG (requires SeCreateTokenPrivilege)
    TokenVirtualizationEnabled,           // q; s: ULONG
    TokenIntegrityLevel,                  // q; s: TOKEN_MANDATORY_LABEL
    TokenUIAccess,                        // q; s: ULONG (requires SeTcbPrivilege)
    TokenMandatoryPolicy,                 // q; s: TOKEN_MANDATORY_POLICY (requires SeTcbPrivilege)
    TokenLogonSid,                        // q: TOKEN_GROUPS
    TokenIsAppContainer,                  // q: ULONG // since WIN8
    TokenCapabilities,                    // q: TOKEN_GROUPS // 30
    TokenAppContainerSid,                 // q: TOKEN_APPCONTAINER_INFORMATION
    TokenAppContainerNumber,              // q: ULONG
    TokenUserClaimAttributes,             // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
    TokenDeviceClaimAttributes,           // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
    TokenRestrictedUserClaimAttributes,   // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
    TokenRestrictedDeviceClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
    TokenDeviceGroups,                    // q: TOKEN_GROUPS
    TokenRestrictedDeviceGroups,          // q: TOKEN_GROUPS
    TokenSecurityAttributes,              // q; s: TOKEN_SECURITY_ATTRIBUTES_[AND_OPERATION_]INFORMATION (requires SeTcbPrivilege)
    TokenIsRestricted,                    // q: ULONG // 40
    TokenProcessTrustLevel,               // q: TOKEN_PROCESS_TRUST_LEVEL // since WINBLUE
    TokenPrivateNameSpace,                // q; s: ULONG  (requires SeTcbPrivilege) // since THRESHOLD
    TokenSingletonAttributes,             // q: TOKEN_SECURITY_ATTRIBUTES_INFORMATION // since REDSTONE
    TokenBnoIsolation,                    // q: TOKEN_BNO_ISOLATION_INFORMATION // since REDSTONE2
    TokenChildProcessFlags,               // s: ULONG  (requires SeTcbPrivilege) // since REDSTONE3
    TokenIsLessPrivilegedAppContainer,    // q: ULONG // since REDSTONE5
    TokenIsSandboxed,                     // q: ULONG // since 19H1
    TokenIsAppSilo,                       // q: ULONG // since WIN11 22H2 // previously TokenOriginatingProcessTrustLevel // q:
                                          // TOKEN_PROCESS_TRUST_LEVEL
    TokenLoggingInformation,              // TOKEN_LOGGING_INFORMATION // since 24H2
    MaxTokenInfoClass
} TOKEN_INFORMATION_CLASS, *PTOKEN_INFORMATION_CLASS;

#endif

using PROCESSINFOCLASS = enum _PROCESSINFOCLASS
{
    ProcessBasicInformation,                // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
    ProcessQuotaLimits,                     // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
    ProcessIoCounters,                      // q: IO_COUNTERS
    ProcessVmCounters,                      // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
    ProcessTimes,                           // q: KERNEL_USER_TIMES
    ProcessBasePriority,                    // s: KPRIORITY
    ProcessRaisePriority,                   // s: ULONG
    ProcessDebugPort,                       // q: HANDLE
    ProcessExceptionPort,                   // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
    ProcessAccessToken,                     // s: PROCESS_ACCESS_TOKEN
    ProcessLdtInformation,                  // qs: PROCESS_LDT_INFORMATION // 10
    ProcessLdtSize,                         // s: PROCESS_LDT_SIZE
    ProcessDefaultHardErrorMode,            // qs: ULONG
    ProcessIoPortHandlers,                  // (kernel-mode only) // s: PROCESS_IO_PORT_HANDLER_INFORMATION
    ProcessPooledUsageAndLimits,            // q: POOLED_USAGE_AND_LIMITS
    ProcessWorkingSetWatch,                 // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
    ProcessUserModeIOPL,                    // qs: ULONG (requires SeTcbPrivilege)
    ProcessEnableAlignmentFaultFixup,       // s: BOOLEAN
    ProcessPriorityClass,                   // qs: PROCESS_PRIORITY_CLASS
    ProcessWx86Information,                 // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
    ProcessHandleCount,                     // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
    ProcessAffinityMask,                    // (q >WIN7)s: KAFFINITY, qs: GROUP_AFFINITY
    ProcessPriorityBoost,                   // qs: ULONG
    ProcessDeviceMap,                       // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
    ProcessSessionInformation,              // q: PROCESS_SESSION_INFORMATION
    ProcessForegroundInformation,           // s: PROCESS_FOREGROUND_BACKGROUND
    ProcessWow64Information,                // q: ULONG_PTR
    ProcessImageFileName,                   // q: UNICODE_STRING
    ProcessLUIDDeviceMapsEnabled,           // q: ULONG
    ProcessBreakOnTermination,              // qs: ULONG
    ProcessDebugObjectHandle,               // q: HANDLE // 30
    ProcessDebugFlags,                      // qs: ULONG
    ProcessHandleTracing,                   // q: PROCESS_HANDLE_TRACING_QUERY; s: PROCESS_HANDLE_TRACING_ENABLE[_EX] or void to disable
    ProcessIoPriority,                      // qs: IO_PRIORITY_HINT
    ProcessExecuteFlags,                    // qs: ULONG (MEM_EXECUTE_OPTION_*)
    ProcessTlsInformation,                  // PROCESS_TLS_INFORMATION // ProcessResourceManagement
    ProcessCookie,                          // q: ULONG
    ProcessImageInformation,                // q: SECTION_IMAGE_INFORMATION
    ProcessCycleTime,                       // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
    ProcessPagePriority,                    // qs: PAGE_PRIORITY_INFORMATION
    ProcessInstrumentationCallback,         // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
    ProcessThreadStackAllocation,           // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
    ProcessWorkingSetWatchEx,               // q: PROCESS_WS_WATCH_INFORMATION_EX[]; s: void
    ProcessImageFileNameWin32,              // q: UNICODE_STRING
    ProcessImageFileMapping,                // q: HANDLE (input)
    ProcessAffinityUpdateMode,              // qs: PROCESS_AFFINITY_UPDATE_MODE
    ProcessMemoryAllocationMode,            // qs: PROCESS_MEMORY_ALLOCATION_MODE
    ProcessGroupInformation,                // q: USHORT[]
    ProcessTokenVirtualizationEnabled,      // s: ULONG
    ProcessConsoleHostProcess,              // qs: ULONG_PTR // ProcessOwnerInformation
    ProcessWindowInformation,               // q: PROCESS_WINDOW_INFORMATION // 50
    ProcessHandleInformation,               // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    ProcessMitigationPolicy,                // s: PROCESS_MITIGATION_POLICY_INFORMATION
    ProcessDynamicFunctionTableInformation, // s: PROCESS_DYNAMIC_FUNCTION_TABLE_INFORMATION
    ProcessHandleCheckingMode,              // qs: ULONG; s: 0 disables, otherwise enables
    ProcessKeepAliveCount,                  // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
    ProcessRevokeFileHandles,               // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
    ProcessWorkingSetControl,               // s: PROCESS_WORKING_SET_CONTROL (requires SeDebugPrivilege)
    ProcessHandleTable,                     // q: ULONG[] // since WINBLUE
    ProcessCheckStackExtentsMode,           // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
    ProcessCommandLineInformation,          // q: UNICODE_STRING // 60
    ProcessProtectionInformation,           // q: PS_PROTECTION
    ProcessMemoryExhaustion,                // s: PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
    ProcessFaultInformation,                // s: PROCESS_FAULT_INFORMATION
    ProcessTelemetryIdInformation,          // q: PROCESS_TELEMETRY_ID_INFORMATION
    ProcessCommitReleaseInformation,        // qs: PROCESS_COMMIT_RELEASE_INFORMATION
    ProcessDefaultCpuSetsInformation,       // qs: SYSTEM_CPU_SET_INFORMATION[5]
    ProcessAllowedCpuSetsInformation,       // qs: SYSTEM_CPU_SET_INFORMATION[5]
    ProcessSubsystemProcess,
    ProcessJobMemoryInformation,                 // q: PROCESS_JOB_MEMORY_INFO
    ProcessInPrivate,                            // q: BOOLEAN; s: void // ETW // since THRESHOLD2 // 70
    ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessIumChallengeResponse,
    ProcessChildProcessInformation,         // q: PROCESS_CHILD_PROCESS_INFORMATION
    ProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
    ProcessSubsystemInformation,            // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ProcessEnergyValues,                    // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
    ProcessPowerThrottlingState,            // qs: POWER_THROTTLING_PROCESS_STATE
    ProcessReserved3Information,            // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
    ProcessWin32kSyscallFilterInformation,  // q: WIN32K_SYSCALL_FILTER
    ProcessDisableSystemAllowedCpuSets,     // s: BOOLEAN // 80
    ProcessWakeInformation,                 // q: PROCESS_WAKE_INFORMATION
    ProcessEnergyTrackingState,             // qs: PROCESS_ENERGY_TRACKING_STATE
    ProcessManageWritesToExecutableMemory,  // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ProcessCaptureTrustletLiveDump,
    ProcessTelemetryCoverage, // q: TELEMETRY_COVERAGE_HEADER; s: TELEMETRY_COVERAGE_POINT
    ProcessEnclaveInformation,
    ProcessEnableReadWriteVmLogging,           // qs: PROCESS_READWRITEVM_LOGGING_INFORMATION
    ProcessUptimeInformation,                  // q: PROCESS_UPTIME_INFORMATION
    ProcessImageSection,                       // q: HANDLE
    ProcessDebugAuthInformation,               // since REDSTONE4 // 90
    ProcessSystemResourceManagement,           // s: PROCESS_SYSTEM_RESOURCE_MANAGEMENT
    ProcessSequenceNumber,                     // q: ULONGLONG
    ProcessLoaderDetour,                       // since REDSTONE5
    ProcessSecurityDomainInformation,          // q: PROCESS_SECURITY_DOMAIN_INFORMATION
    ProcessCombineSecurityDomainsInformation,  // s: PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
    ProcessEnableLogging,                      // qs: PROCESS_LOGGING_INFORMATION
    ProcessLeapSecondInformation,              // qs: PROCESS_LEAP_SECOND_INFORMATION
    ProcessFiberShadowStackAllocation,         // s: PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
    ProcessFreeFiberShadowStackAllocation,     // s: PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
    ProcessAltSystemCallInformation,           // s: PROCESS_SYSCALL_PROVIDER_INFORMATION // since 20H1 // 100
    ProcessDynamicEHContinuationTargets,       // s: PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
    ProcessDynamicEnforcedCetCompatibleRanges, // s: PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
    ProcessCreateStateChange,                  // since WIN11
    ProcessApplyStateChange,
    ProcessEnableOptionalXStateFeatures, // s: ULONG64 // optional XState feature bitmask
    ProcessAltPrefetchParam,             // qs: OVERRIDE_PREFETCH_PARAMETER // App Launch Prefetch (ALPF) // since 22H1
    ProcessAssignCpuPartitions,
    ProcessPriorityClassEx,       // s: PROCESS_PRIORITY_CLASS_EX
    ProcessMembershipInformation, // q: PROCESS_MEMBERSHIP_INFORMATION
    ProcessEffectiveIoPriority,   // q: IO_PRIORITY_HINT // 110
    ProcessEffectivePagePriority, // q: ULONG
    ProcessSchedulerSharedData,   // since 24H2
    ProcessSlistRollbackInformation,
    ProcessNetworkIoCounters,         // q: PROCESS_NETWORK_COUNTERS
    ProcessFindFirstThreadByTebValue, // PROCESS_TEB_VALUE_INFORMATION
    MaxProcessInfoClass
};

using PS_ATTRIBUTE_NUM = enum _PS_ATTRIBUTE_NUM
{
    PsAttributeParentProcess,      // in HANDLE
    PsAttributeDebugObject,        // in HANDLE
    PsAttributeToken,              // in HANDLE
    PsAttributeClientId,           // out PCLIENT_ID
    PsAttributeTebAddress,         // out PTEB *
    PsAttributeImageName,          // in PWSTR
    PsAttributeImageInfo,          // out PSECTION_IMAGE_INFORMATION
    PsAttributeMemoryReserve,      // in PPS_MEMORY_RESERVE
    PsAttributePriorityClass,      // in UCHAR
    PsAttributeErrorMode,          // in ULONG
    PsAttributeStdHandleInfo,      // 10, in PPS_STD_HANDLE_INFO
    PsAttributeHandleList,         // in HANDLE[]
    PsAttributeGroupAffinity,      // in PGROUP_AFFINITY
    PsAttributePreferredNode,      // in PUSHORT
    PsAttributeIdealProcessor,     // in PPROCESSOR_NUMBER
    PsAttributeUmsThread,          // ? in PUMS_CREATE_THREAD_ATTRIBUTES
    PsAttributeMitigationOptions,  // in PPS_MITIGATION_OPTIONS_MAP (PROCESS_CREATION_MITIGATION_POLICY_*) // since WIN8
    PsAttributeProtectionLevel,    // in PS_PROTECTION // since WINBLUE
    PsAttributeSecureProcess,      // in PPS_TRUSTLET_CREATE_ATTRIBUTES, since THRESHOLD
    PsAttributeJobList,            // in HANDLE[]
    PsAttributeChildProcessPolicy, // 20, in PULONG (PROCESS_CREATION_CHILD_PROCESS_*) // since THRESHOLD2
    PsAttributeAllApplicationPackagesPolicy,
    // in PULONG (PROCESS_CREATION_ALL_APPLICATION_PACKAGES_*) // since REDSTONE
    PsAttributeWin32kFilter,              // in PWIN32K_SYSCALL_FILTER
    PsAttributeSafeOpenPromptOriginClaim, // in SE_SAFE_OPEN_PROMPT_RESULTS
    PsAttributeBnoIsolation,              // in PPS_BNO_ISOLATION_PARAMETERS // since REDSTONE2
    PsAttributeDesktopAppPolicy,          // in PULONG (PROCESS_CREATION_DESKTOP_APP_*)
    PsAttributeChpe,                      // in BOOLEAN // since REDSTONE3
    PsAttributeMitigationAuditOptions,
    // in PPS_MITIGATION_AUDIT_OPTIONS_MAP (PROCESS_CREATION_MITIGATION_AUDIT_POLICY_*) // since 21H1
    PsAttributeMachineType, // in USHORT // since 21H2
    PsAttributeComponentFilter,
    PsAttributeEnableOptionalXStateFeatures, // since WIN11
    PsAttributeSupportedMachines,            // since 24H2
    PsAttributeSveVectorLength,              // PPS_PROCESS_CREATION_SVE_VECTOR_LENGTH
    PsAttributeMax
};

struct SYSTEM_PROCESSOR_INFORMATION64
{
    USHORT ProcessorArchitecture;
    USHORT ProcessorLevel;
    USHORT ProcessorRevision;
    USHORT MaximumProcessors;
    ULONG ProcessorFeatureBits;
};

#if !defined(OS_WINDOWS) || !defined(_WIN64)

#if !defined(OS_WINDOWS)
typedef struct _M128A
{
    ULONGLONG Low;
    LONGLONG High;
} M128A, *PM128A;
#endif

typedef struct _XMM_SAVE_AREA32
{
    WORD ControlWord;
    WORD StatusWord;
    BYTE TagWord;
    BYTE Reserved1;
    WORD ErrorOpcode;
    DWORD ErrorOffset;
    WORD ErrorSelector;
    WORD Reserved2;
    DWORD DataOffset;
    WORD DataSelector;
    WORD Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    M128A FloatRegisters[8];
    M128A XmmRegisters[16];
    BYTE Reserved4[96];
} XMM_SAVE_AREA32, *PXMM_SAVE_AREA32;

#endif

using NEON128 = struct _NEON128
{
    ULONGLONG Low;
    LONGLONG High;
};

typedef struct
#if !defined(__MINGW64__)
    DECLSPEC_ALIGN(16)
#endif
        _CONTEXT64
{
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD ContextFlags;
    DWORD MxCsr;
    WORD SegCs;
    WORD SegDs;
    WORD SegEs;
    WORD SegFs;
    WORD SegGs;
    WORD SegSs;
    DWORD EFlags;
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    DWORD64 Rip;

    union
    {
        XMM_SAVE_AREA32 FltSave;
        NEON128 Q[16];
        ULONGLONG D[32];

        struct
        {
            M128A Header[2];
            M128A Legacy[8];
            M128A Xmm0;
            M128A Xmm1;
            M128A Xmm2;
            M128A Xmm3;
            M128A Xmm4;
            M128A Xmm5;
            M128A Xmm6;
            M128A Xmm7;
            M128A Xmm8;
            M128A Xmm9;
            M128A Xmm10;
            M128A Xmm11;
            M128A Xmm12;
            M128A Xmm13;
            M128A Xmm14;
            M128A Xmm15;
        };

        DWORD S[32];
    };

    M128A VectorRegister[26];
    DWORD64 VectorControl;
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
} CONTEXT64, *PCONTEXT64;

typedef struct _CONTEXT_CHUNK
{
    LONG Offset; // Offset may be negative.
    ULONG Length;
} CONTEXT_CHUNK, *PCONTEXT_CHUNK;

typedef struct _CONTEXT_EX
{
    CONTEXT_CHUNK All;
    CONTEXT_CHUNK Legacy;
    CONTEXT_CHUNK XState;
    CONTEXT_CHUNK KernelCet;
} CONTEXT_EX, *PCONTEXT_EX;

template <typename Traits>
struct EMU_EXCEPTION_RECORD
{
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    EMULATOR_CAST(typename Traits::PVOID, struct EMU_EXCEPTION_RECORD*) ExceptionRecord;
    typename Traits::PVOID ExceptionAddress;
    DWORD NumberParameters;
    typename Traits::ULONG_PTR ExceptionInformation[15];
};

template <typename Traits>
struct EMU_EXCEPTION_POINTERS
{
    EMULATOR_CAST(typename Traits::PVOID, EMU_EXCEPTION_RECORD*) ExceptionRecord;
    EMULATOR_CAST(typename Traits::PVOID, CONTEXT64* or CONTEXT32*) ContextRecord;
};

#define MAXIMUM_NODE_COUNT64 0x40
#define MAXIMUM_NODE_COUNT32 0x10

struct EMU_GROUP_AFFINITY64
{
    EMULATOR_CAST(std::uint64_t, KAFFINITY) Mask;
    WORD Group;
    WORD Reserved[3];
};

typedef struct _SYSTEM_NUMA_INFORMATION64
{
    ULONG HighestNodeNumber;
    ULONG Reserved;

    union
    {
        EMU_GROUP_AFFINITY64 ActiveProcessorsGroupAffinity[MAXIMUM_NODE_COUNT64];
        ULONGLONG AvailableMemory[MAXIMUM_NODE_COUNT64];
        ULONGLONG Pad[MAXIMUM_NODE_COUNT64 * 2];
    };
} SYSTEM_NUMA_INFORMATION64, *PSYSTEM_NUMA_INFORMATION64;

typedef struct _SYSTEM_ERROR_PORT_TIMEOUTS
{
    ULONG StartTimeout;
    ULONG CommTimeout;
} SYSTEM_ERROR_PORT_TIMEOUTS, *PSYSTEM_ERROR_PORT_TIMEOUTS;

typedef struct _SYSTEM_BASIC_INFORMATION64
{
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    EMULATOR_CAST(EmulatorTraits<Emu64>::PVOID, ULONG_PTR) MinimumUserModeAddress;
    EMULATOR_CAST(EmulatorTraits<Emu64>::PVOID, ULONG_PTR) MaximumUserModeAddress;
    EMULATOR_CAST(EmulatorTraits<Emu64>::PVOID, KAFFINITY) ActiveProcessorsAffinityMask;
    char NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION64, *PSYSTEM_BASIC_INFORMATION64;

typedef struct _SYSTEM_RANGE_START_INFORMATION64
{
    EmulatorTraits<Emu64>::SIZE_T SystemRangeStart;
} SYSTEM_RANGE_START_INFORMATION64, *PSYSTEM_RANGE_START_INFORMATION64;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

#ifndef OS_WINDOWS
struct SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION
{
    DWORD Machine : 16;
    DWORD KernelMode : 1;
    DWORD UserMode : 1;
    DWORD Native : 1;
    DWORD Process : 1;
    DWORD WoW64Container : 1;
    DWORD ReservedZero0 : 11;
};

struct SID_IDENTIFIER_AUTHORITY
{
    BYTE Value[6];
};

#define SID_REVISION                    (1)
#define SID_MAX_SUB_AUTHORITIES         (15)
#define SID_RECOMMENDED_SUB_AUTHORITIES (1)

struct SID
{
    BYTE Revision;
    BYTE SubAuthorityCount;
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    DWORD SubAuthority[ANYSIZE_ARRAY];
};
#endif

struct SID_AND_ATTRIBUTES64
{
    EMULATOR_CAST(EmulatorTraits<Emu64>::PVOID, PSID) Sid;
    DWORD Attributes;
};

struct TOKEN_USER64
{
    SID_AND_ATTRIBUTES64 User;
};

struct TOKEN_GROUPS64
{
    ULONG GroupCount;
    SID_AND_ATTRIBUTES64 Groups[1];
};

struct TOKEN_OWNER64
{
    EMULATOR_CAST(EmulatorTraits<Emu64>::PVOID, PSID) Owner;
};

struct TOKEN_PRIMARY_GROUP64
{
    EMULATOR_CAST(EmulatorTraits<Emu64>::PVOID, PSID) PrimaryGroup;
};

#ifndef OS_WINDOWS
struct ACL
{
    BYTE AclRevision;
    BYTE Sbz1;
    WORD AclSize;
    WORD AceCount;
    WORD Sbz2;
};

struct ACE_HEADER
{
    BYTE AceType;
    BYTE AceFlags;
    WORD AceSize;
};

typedef DWORD ACCESS_MASK;

struct ACCESS_ALLOWED_ACE
{
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD SidStart;
};
#endif

struct TOKEN_DEFAULT_DACL64
{
    EMULATOR_CAST(EmulatorTraits<Emu64>::PVOID, PACL) DefaultDacl;
};

struct TOKEN_BNO_ISOLATION_INFORMATION64
{
    EmulatorTraits<Emu64>::PVOID IsolationPrefix;
    BOOLEAN IsolationEnabled;
};

struct TOKEN_MANDATORY_LABEL64
{
    SID_AND_ATTRIBUTES64 Label;
};

struct TOKEN_PROCESS_TRUST_LEVEL64
{
    EMULATOR_CAST(EmulatorTraits<Emu64>::PVOID, PSID) TrustLevelSid;
};

#ifndef OS_WINDOWS

typedef enum _TOKEN_TYPE
{
    TokenPrimary = 1,
    TokenImpersonation
} TOKEN_TYPE;
typedef TOKEN_TYPE* PTOKEN_TYPE;

typedef struct _TOKEN_ELEVATION
{
    DWORD TokenIsElevated;
} TOKEN_ELEVATION, *PTOKEN_ELEVATION;

typedef enum _SECURITY_IMPERSONATION_LEVEL
{
    SecurityAnonymous,
    SecurityIdentification,
    SecurityImpersonation,
    SecurityDelegation
} SECURITY_IMPERSONATION_LEVEL, *PSECURITY_IMPERSONATION_LEVEL;

typedef struct _LUID
{
    DWORD LowPart;
    LONG HighPart;
} LUID, *PLUID;

typedef struct _TOKEN_STATISTICS
{
    LUID TokenId;
    LUID AuthenticationId;
    LARGE_INTEGER ExpirationTime;
    TOKEN_TYPE TokenType;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    DWORD DynamicCharged;
    DWORD DynamicAvailable;
    DWORD GroupCount;
    DWORD PrivilegeCount;
    LUID ModifiedId;
} TOKEN_STATISTICS, *PTOKEN_STATISTICS;

#endif

typedef struct _TOKEN_SECURITY_ATTRIBUTES_INFORMATION
{
    USHORT Version;
    USHORT Reserved;
    ULONG AttributeCount;

    union
    {
        EmulatorTraits<Emu64>::PVOID pAttributeV1;
    } Attribute;
} TOKEN_SECURITY_ATTRIBUTES_INFORMATION, *PTOKEN_SECURITY_ATTRIBUTES_INFORMATION;

#ifndef OS_WINDOWS
#define SECURITY_DESCRIPTOR_REVISION  1
#define SECURITY_DESCRIPTOR_REVISION1 1

typedef WORD SECURITY_DESCRIPTOR_CONTROL, *PSECURITY_DESCRIPTOR_CONTROL;

#define SE_OWNER_DEFAULTED       0x0001
#define SE_GROUP_DEFAULTED       0x0002
#define SE_DACL_PRESENT          0x0004
#define SE_DACL_DEFAULTED        0x0008
#define SE_SACL_PRESENT          0x0010
#define SE_SACL_DEFAULTED        0x0020
#define SE_DACL_AUTO_INHERIT_REQ 0x0100
#define SE_SACL_AUTO_INHERIT_REQ 0x0200
#define SE_DACL_AUTO_INHERITED   0x0400
#define SE_SACL_AUTO_INHERITED   0x0800
#define SE_DACL_PROTECTED        0x1000
#define SE_SACL_PROTECTED        0x2000
#define SE_RM_CONTROL_VALID      0x4000
#define SE_SELF_RELATIVE         0x8000

struct SECURITY_DESCRIPTOR_RELATIVE
{
    BYTE Revision;
    BYTE Sbz1;
    SECURITY_DESCRIPTOR_CONTROL Control;
    DWORD Owner;
    DWORD Group;
    DWORD Sacl;
    DWORD Dacl;
};

typedef DWORD SECURITY_INFORMATION, *PSECURITY_INFORMATION;

#define OWNER_SECURITY_INFORMATION               0x00000001L
#define GROUP_SECURITY_INFORMATION               0x00000002L
#define DACL_SECURITY_INFORMATION                0x00000004L
#define SACL_SECURITY_INFORMATION                0x00000008L
#define LABEL_SECURITY_INFORMATION               0x00000010L
#define ATTRIBUTE_SECURITY_INFORMATION           0x00000020L
#define SCOPE_SECURITY_INFORMATION               0x00000040L
#define PROCESS_TRUST_LABEL_SECURITY_INFORMATION 0x00000080L
#define ACCESS_FILTER_SECURITY_INFORMATION       0x00000100L
#define BACKUP_SECURITY_INFORMATION              0x00010000L
#endif

struct GDI_HANDLE_ENTRY64
{
    union
    {
        EmulatorTraits<Emu64>::PVOID Object;
        EmulatorTraits<Emu64>::PVOID NextFree;
    };

    union
    {
        struct
        {
            USHORT ProcessId;
            USHORT Lock : 1;
            USHORT Count : 15;
        };

        ULONG Value;
    } Owner;

    USHORT Unique;
    UCHAR Type;
    UCHAR Flags;
    EmulatorTraits<Emu64>::PVOID UserPointer;
};

#define GDI_MAX_HANDLE_COUNT 0xFFFF // 0x4000

struct GDI_SHARED_MEMORY64
{
    GDI_HANDLE_ENTRY64 Handles[GDI_MAX_HANDLE_COUNT];
    char pad[0xC8];
    uint64_t Objects[0x20];
    uint64_t Data[0x200]; // ?
};

static_assert(offsetof(GDI_SHARED_MEMORY64, Objects) == 0x1800B0);

struct CLIENT_ID32
{
    ULONG UniqueProcess;
    ULONG UniqueThread;
};

struct CLIENT_ID64
{
    DWORD64 UniqueProcess;
    DWORD64 UniqueThread;
};

template <typename Traits>
struct EMU_RTL_SRWLOCK
{
    typename Traits::PVOID Ptr;
};

#ifndef OS_WINDOWS
typedef enum _PROCESSOR_CACHE_TYPE
{
    CacheUnified,
    CacheInstruction,
    CacheData,
    CacheTrace
} PROCESSOR_CACHE_TYPE;

typedef enum _LOGICAL_PROCESSOR_RELATIONSHIP
{
    RelationProcessorCore,
    RelationNumaNode,
    RelationCache,
    RelationProcessorPackage,
    RelationGroup,
    RelationProcessorDie,
    RelationNumaNodeEx,
    RelationProcessorModule,
    RelationAll = 0xffff
} LOGICAL_PROCESSOR_RELATIONSHIP;
#endif

struct EMU_NUMA_NODE_RELATIONSHIP64
{
    DWORD NodeNumber;
    BYTE Reserved[18];
    WORD GroupCount;
    union
    {
        EMU_GROUP_AFFINITY64 GroupMask;
        _Field_size_(GroupCount) EMU_GROUP_AFFINITY64 GroupMasks[ANYSIZE_ARRAY];
    };
};

struct EMU_CACHE_RELATIONSHIP64
{
    BYTE Level;
    BYTE Associativity;
    WORD LineSize;
    DWORD CacheSize;
    PROCESSOR_CACHE_TYPE Type;
    BYTE Reserved[18];
    WORD GroupCount;
    union
    {
        EMU_GROUP_AFFINITY64 GroupMask;
        _Field_size_(GroupCount) EMU_GROUP_AFFINITY64 GroupMasks[ANYSIZE_ARRAY];
    };
};

struct EMU_PROCESSOR_GROUP_INFO64
{
    BYTE MaximumProcessorCount;
    BYTE ActiveProcessorCount;
    BYTE Reserved[38];
    EMULATOR_CAST(std::uint64_t, KAFFINITY) ActiveProcessorMask;
};

struct EMU_GROUP_RELATIONSHIP64
{
    WORD MaximumGroupCount;
    WORD ActiveGroupCount;
    BYTE Reserved[20];
    _Field_size_(ActiveGroupCount) EMU_PROCESSOR_GROUP_INFO64 GroupInfo[ANYSIZE_ARRAY];
};

struct EMU_PROCESSOR_RELATIONSHIP64
{
    BYTE Flags;
    BYTE EfficiencyClass;
    BYTE Reserved[20];
    WORD GroupCount;
    _Field_size_(GroupCount) EMU_GROUP_AFFINITY64 GroupMask[ANYSIZE_ARRAY];
};

_Struct_size_bytes_(Size) struct EMU_SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX64
{
    LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
    DWORD Size;
    union
    {
        EMU_PROCESSOR_RELATIONSHIP64 Processor;
        EMU_NUMA_NODE_RELATIONSHIP64 NumaNode;
        EMU_CACHE_RELATIONSHIP64 Cache;
        EMU_GROUP_RELATIONSHIP64 Group;
    };
};

struct EMU_CACHE_DESCRIPTOR
{
    BYTE Level;
    BYTE Associativity;
    WORD LineSize;
    DWORD Size;
    PROCESSOR_CACHE_TYPE Type;
};

template <typename Traits>
struct EMU_SYSTEM_LOGICAL_PROCESSOR_INFORMATION
{
    typename Traits::ULONG_PTR ProcessorMask;
    LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
    union
    {
        struct
        {
            BYTE Flags;
        } ProcessorCore;
        struct
        {
            DWORD NodeNumber;
        } NumaNode;
        EMU_CACHE_DESCRIPTOR Cache;
        ULONGLONG Reserved[2];
    } DUMMYUNIONNAME;
};

struct PROCESS_PRIORITY_CLASS
{
    BOOLEAN Foreground;
    UCHAR PriorityClass;
};

struct PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
    ULONG Version;
    ULONG Reserved;
    uint64_t Callback;
};

struct EMU_RTL_PROCESS_MODULE_INFORMATION64
{
    uint64_t Section;
    uint64_t MappedBase;
    uint64_t ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
};

struct EMU_RTL_PROCESS_MODULE_INFORMATION_EX64
{
    USHORT NextOffset;
    EMU_RTL_PROCESS_MODULE_INFORMATION64 BaseInfo;
    ULONG ImageChecksum;
    ULONG TimeDateStamp;
    uint64_t DefaultBase;
};
// NOLINTEND(modernize-use-using,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-use-enum-class)
