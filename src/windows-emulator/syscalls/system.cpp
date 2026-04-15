#include "../std_include.hpp"
#include "../emulator_utils.hpp"
#include "../syscall_utils.hpp"

#include <magic_enum/magic_enum.hpp>

namespace syscalls
{
    namespace
    {
        NTSTATUS handle_logical_processor_and_group_information(const syscall_context& c, const uint64_t input_buffer,
                                                                const uint32_t input_buffer_length, const uint64_t system_information,
                                                                const uint32_t system_information_length,
                                                                const emulator_object<uint32_t> return_length)
        {
            if (input_buffer_length != sizeof(LOGICAL_PROCESSOR_RELATIONSHIP))
            {
                return STATUS_INVALID_PARAMETER;
            }

            const auto request = c.emu.read_memory<LOGICAL_PROCESSOR_RELATIONSHIP>(input_buffer);

            if (request == RelationGroup)
            {
                constexpr auto root_size = offsetof(EMU_SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX64, Group);
                constexpr auto required_size = root_size + sizeof(EMU_GROUP_RELATIONSHIP64);

                if (return_length)
                {
                    return_length.write(required_size);
                }

                if (system_information_length < required_size)
                {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }

                EMU_SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX64 proc_info{};
                proc_info.Size = required_size;
                proc_info.Relationship = RelationGroup;

                c.emu.write_memory(system_information, &proc_info, root_size);

                EMU_GROUP_RELATIONSHIP64 group{};
                group.ActiveGroupCount = 1;
                group.MaximumGroupCount = 1;

                auto& group_info = group.GroupInfo[0];
                group_info.ActiveProcessorCount = static_cast<uint8_t>(c.proc.kusd.get().ActiveProcessorCount);
                group_info.ActiveProcessorMask = (1 << group_info.ActiveProcessorCount) - 1;
                group_info.MaximumProcessorCount = group_info.ActiveProcessorCount;

                c.emu.write_memory(system_information + root_size, group);
                return STATUS_SUCCESS;
            }

            if (request == RelationNumaNode || request == RelationNumaNodeEx)
            {
                constexpr auto root_size = offsetof(EMU_SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX64, NumaNode);
                constexpr auto required_size = root_size + sizeof(EMU_NUMA_NODE_RELATIONSHIP64);

                if (return_length)
                {
                    return_length.write(required_size);
                }

                if (system_information_length < required_size)
                {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }

                EMU_SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX64 proc_info{};
                proc_info.Size = required_size;
                proc_info.Relationship = RelationNumaNode;

                c.emu.write_memory(system_information, &proc_info, root_size);

                EMU_NUMA_NODE_RELATIONSHIP64 numa_node{};
                memset(&numa_node, 0, sizeof(numa_node));

                c.emu.write_memory(system_information + root_size, numa_node);
                return STATUS_SUCCESS;
            }

            c.win_emu.log.error("Unsupported processor relationship: %X\n", request);
            c.emu.stop();
            return STATUS_NOT_SUPPORTED;
        }
    }

    NTSTATUS handle_NtQuerySystemInformationEx(const syscall_context& c, const SYSTEM_INFORMATION_CLASS info_class, const uint64_t input_buffer,
                                               const uint32_t input_buffer_length, const uint64_t system_information,
                                               const uint32_t system_information_length, const emulator_object<uint32_t> return_length)
    {
        switch (info_class)
        {
        case SystemControlFlowTransition:
            c.win_emu.callbacks.on_suspicious_activity("Warbird control flow transition");
            return STATUS_NOT_SUPPORTED;

        // Set-only info classes — querying them is invalid.
        case SystemActivityModerationExeState:
        case SystemAitSamplingValue:
        case SystemAllowedCpuSetsInformation:
        case SystemCombinePhysicalMemoryInformation:
        case SystemCrashDumpStateInformation:
        case SystemDifClearRuleClassInformation:
        case SystemDifPoolTrackingInformation:
        case SystemDifSetRuleClassInformation:
        case SystemElamCertificateInformation:
        case SystemErrorPortInformation:
        case SystemExtendServiceTableInformation:
        case SystemImageFileExecutionOptionsInformation:
        case SystemIntegrityQuotaInformation:
        case SystemKernelDebuggingAllowed:
        case SystemLoadGdiDriverInformation:
        case SystemPrioritySeparation:
        case SystemProcessorMicrocodeUpdateInformation:
        case SystemRegisterFirmwareTableInformationHandler:
        case SystemRegistryAppendString:
        case SystemRegistryReconciliationInformation:
        case SystemThreadPriorityClientIdInformation:
        case SystemTimeSlipNotification:
        case SystemUnloadGdiDriverInformation:
        case SystemVerifierAddDriverInformation:
        case SystemVerifierFaultsInformation:
        case SystemVerifierRemoveDriverInformation:
        case SystemVmGenerationCountInformation:
        case SystemWatchdogTimerHandler:
        case SystemWin32WerStartCallout:
            return STATUS_INVALID_INFO_CLASS;

        // Classes documented as "not implemented" in Windows — return the same status so
        // callers can fall back without observing a bogus success.
        case SystemPathInformation:
        case SystemCallTimeInformation:
        case SystemPagedPoolInformation:
        case SystemNonPagedPoolInformation:
        case SystemVdmBopInformation:
        case SystemFullMemoryInformation:
        case SystemSummaryMemoryInformation:
        case SystemObsolete0:
        case SystemSessionCreate:
        case SystemSessionDetach:
        case SystemSessionInformation:
        case SystemWow64SharedInformationObsolete:
        case SystemVerifierTriageInformation:
        case SystemProcessorPowerInformationEx:
            return STATUS_NOT_SUPPORTED;

        // Simple ULONG-valued queries.
        case SystemRecommendedSharedDataAlignment:
            return handle_query<ULONG>(c.emu,
                                       system_information,
                                       system_information_length,
                                       return_length,
                                       [](ULONG& v) { v = 64; });

        case SystemLostDelayedWriteInformation:
        case SystemObjectSecurityMode:
        case SystemSoftRebootInformation:
        case SystemResourceDeadlockTimeout:
        case SystemBreakOnContextUnwindFailureInformation:
            return handle_query<ULONG>(c.emu,
                                       system_information,
                                       system_information_length,
                                       return_length,
                                       [](ULONG& v) { v = 0; });

        // Everything else that callers may query: accept whatever buffer length they provide,
        // zero it out, report the same length as "required", and return success. This lets
        // software that only cares about probing surfaces proceed without a crash.
        case SystemPerformanceInformation:
        case SystemProcessInformation:
        case SystemCallCountInformation:
        case SystemDeviceInformation:
        case SystemProcessorPerformanceInformation:
        case SystemFlagsInformation:
        case SystemModuleInformation:
        case SystemLocksInformation:
        case SystemStackTraceInformation:
        case SystemHandleInformation:
        case SystemObjectInformation:
        case SystemPageFileInformation:
        case SystemVdmInstemulInformation:
        case SystemFileCacheInformation:
        case SystemPoolTagInformation:
        case SystemInterruptInformation:
        case SystemDpcBehaviorInformation:
        case SystemMirrorMemoryInformation:
        case SystemPerformanceTraceInformation:
        case SystemExceptionInformation:
        case SystemContextSwitchInformation:
        case SystemRegistryQuotaInformation:
        case SystemProcessorIdleInformation:
        case SystemLegacyDriverInformation:
        case SystemLookasideInformation:
        case SystemVerifierInformation:
        case SystemVerifierThunkExtend:
        case SystemSessionProcessInformation:
        case SystemLoadGdiDriverInSystemSpace:
        case SystemNumaAvailableMemory:
        case SystemExtendedProcessInformation:
        case SystemComPlusPackage:
        case SystemProcessorPowerInformation:
        case SystemExtendedHandleInformation:
        case SystemBigPoolInformation:
        case SystemSessionPoolTagInformation:
        case SystemSessionMappedViewInformation:
        case SystemHotpatchInformation:
        case SystemWatchdogTimerInformation:
        case SystemFirmwareTableInformation:
        case SystemSuperfetchInformation:
        case SystemMemoryListInformation:
        case SystemFileCacheInformationEx:
        case SystemProcessorIdleCycleTimeInformation:
        case SystemVerifierCancellationInformation:
        case SystemRefTraceInformation:
        case SystemSpecialPoolInformation:
        case SystemProcessIdInformation:
        case SystemBootEnvironmentInformation:
        case SystemHypervisorInformation:
        case SystemVerifierInformationEx:
        case SystemCoverageInformation:
        case SystemPrefetchPatchInformation:
        case SystemSystemPartitionInformation:
        case SystemSystemDiskInformation:
        case SystemProcessorPerformanceDistribution:
        case SystemVirtualAddressInformation:
        case SystemProcessorCycleTimeInformation:
        case SystemStoreInformation:
        case SystemVhdBootInformation:
        case SystemCpuQuotaInformation:
        case SystemNativeBasicInformation:
        case SystemLowPriorityIoInformation:
        case SystemTpmBootEntropyInformation:
        case SystemVerifierCountersInformation:
        case SystemPagedPoolInformationEx:
        case SystemSystemPtesInformationEx:
        case SystemNodeDistanceInformation:
        case SystemAcpiAuditInformation:
        case SystemBasicPerformanceInformation:
        case SystemQueryPerformanceCounterInformation:
        case SystemSessionBigPoolInformation:
        case SystemBootGraphicsInformation:
        case SystemScrubPhysicalMemoryInformation:
        case SystemBadPageInformation:
        case SystemProcessorProfileControlArea:
        case SystemEntropyInterruptTimingInformation:
        case SystemConsoleInformation:
        case SystemPlatformBinaryInformation:
        case SystemPolicyInformation:
        case SystemHypervisorProcessorCountInformation:
        case SystemDeviceDataInformation:
        case SystemDeviceDataEnumerationInformation:
        case SystemMemoryTopologyInformation:
        case SystemMemoryChannelInformation:
        case SystemBootLogoInformation:
        case SystemProcessorPerformanceInformationEx:
        case SystemCriticalProcessErrorLogInformation:
        case SystemSecureBootPolicyInformation:
        case SystemPageFileInformationEx:
        case SystemSecureBootInformation:
        case SystemEntropyInterruptTimingRawInformation:
        case SystemPortableWorkspaceEfiLauncherInformation:
        case SystemFullProcessInformation:
        case SystemKernelDebuggerInformationEx:
        case SystemBootMetadataInformation:
        case SystemOfflineDumpConfigInformation:
        case SystemProcessorFeaturesInformation:
        case SystemEdidInformation:
        case SystemManufacturingInformation:
        case SystemEnergyEstimationConfigInformation:
        case SystemHypervisorDetailInformation:
        case SystemProcessorCycleStatsInformation:
        case SystemTrustedPlatformModuleInformation:
        case SystemKernelDebuggerFlags:
        case SystemCodeIntegrityPolicyInformation:
        case SystemIsolatedUserModeInformation:
        case SystemHardwareSecurityTestInterfaceResultsInformation:
        case SystemSingleModuleInformation:
        case SystemVsmProtectionInformation:
        case SystemInterruptCpuSetsInformation:
        case SystemSecureBootPolicyFullInformation:
        case SystemCodeIntegrityPolicyFullInformation:
        case SystemAffinitizedInterruptProcessorInformation:
        case SystemRootSiloInformation:
        case SystemCpuSetInformation:
        case SystemCpuSetTagInformation:
        case SystemSecureKernelProfileInformation:
        case SystemCodeIntegrityPlatformManifestInformation:
        case SystemInterruptSteeringInformation:
        case SystemMemoryUsageInformation:
        case SystemCodeIntegrityCertificateInformation:
        case SystemPhysicalMemoryInformation:
        case SystemActivityModerationUserSettings:
        case SystemCodeIntegrityPoliciesFullInformation:
        case SystemCodeIntegrityUnlockInformation:
        case SystemFlushInformation:
        case SystemProcessorIdleMaskInformation:
        case SystemWriteConstraintInformation:
        case SystemKernelVaShadowInformation:
        case SystemHypervisorSharedPageInformation:
        case SystemFirmwareBootPerformanceInformation:
        case SystemCodeIntegrityVerificationInformation:
        case SystemFirmwarePartitionInformation:
        case SystemSpeculationControlInformation:
        case SystemDmaGuardPolicyInformation:
        case SystemEnclaveLaunchControlInformation:
        case SystemWorkloadAllowedCpuSetsInformation:
        case SystemCodeIntegrityUnlockModeInformation:
        case SystemLeapSecondInformation:
        case SystemFlags2Information:
        case SystemSecurityModelInformation:
        case SystemCodeIntegritySyntheticCacheInformation:
        case SystemFeatureConfigurationInformation:
        case SystemFeatureConfigurationSectionInformation:
        case SystemFeatureUsageSubscriptionInformation:
        case SystemSecureSpeculationControlInformation:
        case SystemSpacesBootInformation:
        case SystemFwRamdiskInformation:
        case SystemWheaIpmiHardwareInformation:
        case SystemDifApplyPluginVerificationOnDriver:
        case SystemDifRemovePluginVerificationOnDriver:
        case SystemShadowStackInformation:
        case SystemBuildVersionInformation:
        case SystemPoolLimitInformation:
        case SystemCodeIntegrityAddDynamicStore:
        case SystemCodeIntegrityClearDynamicStores:
        case SystemPoolZeroingInformation:
        case SystemDpcWatchdogInformation:
        case SystemDpcWatchdogInformation2:
        case SystemSupportedProcessorArchitectures2:
        case SystemSingleProcessorRelationshipInformation:
        case SystemXfgCheckFailureInformation:
        case SystemIommuStateInformation:
        case SystemHypervisorMinrootInformation:
        case SystemHypervisorBootPagesInformation:
        case SystemPointerAuthInformation:
        case SystemSecureKernelDebuggerInformation:
        case SystemOriginalImageFeatureInformation:
        case SystemMemoryNumaInformation:
        case SystemMemoryNumaPerformanceInformation:
        case SystemCodeIntegritySignedPoliciesFullInformation:
        case SystemSecureCoreInformation:
        case SystemTrustedAppsRuntimeInformation:
        case SystemBadPageInformationEx:
        case SystemOslRamdiskInformation:
        case SystemCodeIntegrityPolicyManagementInformation:
        case SystemMemoryNumaCacheInformation:
        case SystemProcessorFeaturesBitMapInformation:
        case SystemRefTraceInformationEx:
        case SystemBasicProcessInformation:
        case SystemHandleCountInformation:
        case SystemRuntimeAttestationReport:
        case SystemPoolTagInformation2:
        case SystemCodeIntegrityInformation:
        case SystemNumaProximityNodeInformation:
        case SystemProcessorBrandString:
        case SystemPrefetcherInformation:
        case SystemSecureDumpEncryptionInformation:
        case SystemTimeAdjustmentInformation: {
            if (system_information_length > 0 && system_information != 0)
            {
                const std::vector<uint8_t> zeros(system_information_length, 0);
                c.emu.write_memory(system_information, zeros.data(), system_information_length);
            }
            if (return_length)
            {
                return_length.write(system_information_length);
            }
            return STATUS_SUCCESS;
        }

        case SystemTimeOfDayInformation:
            return handle_query<SYSTEM_TIMEOFDAY_INFORMATION64>(c.emu, system_information, system_information_length, return_length,
                                                                [&](SYSTEM_TIMEOFDAY_INFORMATION64& info) {
                                                                    memset(&info, 0, sizeof(info));
                                                                    info.BootTime.QuadPart = 0;
                                                                    info.TimeZoneId = 0x00000002;
                                                                    // TODO: Fill
                                                                });

        case SystemTimeZoneInformation:
        case SystemCurrentTimeZoneInformation:
            return handle_query<SYSTEM_TIMEZONE_INFORMATION>(
                c.emu, system_information, system_information_length, return_length, [&](SYSTEM_TIMEZONE_INFORMATION& tzi) {
                    memset(&tzi, 0, sizeof(tzi));

                    tzi.Bias = -60;
                    tzi.StandardBias = 0;
                    tzi.DaylightBias = -60;

                    constexpr std::u16string_view std_name{u"W. Europe Standard Time"};
                    memcpy(&tzi.StandardName.arr[0], std_name.data(), std_name.size() * sizeof(char16_t));

                    constexpr std::u16string_view dlt_name{u"W. Europe Daylight Time"};
                    memcpy(&tzi.DaylightName.arr[0], dlt_name.data(), dlt_name.size() * sizeof(char16_t));

                    // Standard Time: Last Sunday in October, 03:00
                    tzi.StandardDate.wMonth = 10;
                    tzi.StandardDate.wDayOfWeek = 0;
                    tzi.StandardDate.wDay = 5;
                    tzi.StandardDate.wHour = 3;
                    tzi.StandardDate.wMinute = 0;
                    tzi.StandardDate.wSecond = 0;
                    tzi.StandardDate.wMilliseconds = 0;

                    // Daylight Time: Last Sunday in March, 02:00
                    tzi.DaylightDate.wMonth = 3;
                    tzi.DaylightDate.wDayOfWeek = 0;
                    tzi.DaylightDate.wDay = 5;
                    tzi.DaylightDate.wHour = 2;
                    tzi.DaylightDate.wMinute = 0;
                    tzi.DaylightDate.wSecond = 0;
                    tzi.DaylightDate.wMilliseconds = 0;
                });

        case SystemDynamicTimeZoneInformation:
            return handle_query<SYSTEM_DYNAMIC_TIMEZONE_INFORMATION>(
                c.emu, system_information, system_information_length, return_length, [&](SYSTEM_DYNAMIC_TIMEZONE_INFORMATION& dtzi) {
                    memset(&dtzi, 0, sizeof(dtzi));

                    dtzi.Bias = -60;
                    dtzi.StandardBias = 0;
                    dtzi.DaylightBias = -60;

                    constexpr std::u16string_view std_name{u"W. Europe Standard Time"};
                    memcpy(&dtzi.StandardName.arr[0], std_name.data(), std_name.size() * sizeof(char16_t));

                    constexpr std::u16string_view dlt_name{u"W. Europe Daylight Time"};
                    memcpy(&dtzi.DaylightName.arr[0], dlt_name.data(), dlt_name.size() * sizeof(char16_t));

                    constexpr std::u16string_view key_name{u"W. Europe Standard Time"};
                    memcpy(&dtzi.TimeZoneKeyName.arr[0], key_name.data(), key_name.size() * sizeof(char16_t));

                    // Standard Time: Last Sunday in October, 03:00
                    dtzi.StandardDate.wMonth = 10;
                    dtzi.StandardDate.wDayOfWeek = 0;
                    dtzi.StandardDate.wDay = 5;
                    dtzi.StandardDate.wHour = 3;
                    dtzi.StandardDate.wMinute = 0;
                    dtzi.StandardDate.wSecond = 0;
                    dtzi.StandardDate.wMilliseconds = 0;

                    // Daylight Time: Last Sunday in March, 02:00
                    dtzi.DaylightDate.wMonth = 3;
                    dtzi.DaylightDate.wDayOfWeek = 0;
                    dtzi.DaylightDate.wDay = 5;
                    dtzi.DaylightDate.wHour = 2;
                    dtzi.DaylightDate.wMinute = 0;
                    dtzi.DaylightDate.wSecond = 0;
                    dtzi.DaylightDate.wMilliseconds = 0;

                    dtzi.DynamicDaylightTimeDisabled = FALSE;
                });

        case SystemRangeStartInformation:
            return handle_query<SYSTEM_RANGE_START_INFORMATION64>(c.emu, system_information, system_information_length, return_length,
                                                                  [&](SYSTEM_RANGE_START_INFORMATION64& info) {
                                                                      info.SystemRangeStart = 0xFFFF800000000000; //
                                                                  });

        case SystemProcessorInformation:
        case SystemEmulationProcessorInformation:
            return handle_query<SYSTEM_PROCESSOR_INFORMATION64>(
                c.emu, system_information, system_information_length, return_length, [&](SYSTEM_PROCESSOR_INFORMATION64& info) {
                    memset(&info, 0, sizeof(info));
                    info.MaximumProcessors = 2;
                    info.ProcessorArchitecture =
                        (info_class == SystemProcessorInformation ? PROCESSOR_ARCHITECTURE_AMD64 : PROCESSOR_ARCHITECTURE_INTEL);
                });

        case SystemNumaProcessorMap:
            return handle_query<SYSTEM_NUMA_INFORMATION64>(c.emu, system_information, system_information_length, return_length,
                                                           [&](SYSTEM_NUMA_INFORMATION64& info) {
                                                               memset(&info, 0, sizeof(info));
                                                               info.ActiveProcessorsGroupAffinity->Mask = 0xFFF;
                                                               info.AvailableMemory[0] = 0xFFF;
                                                               info.Pad[0] = 0xFFF;
                                                           });

        case SystemErrorPortTimeouts:
            return handle_query<SYSTEM_ERROR_PORT_TIMEOUTS>(c.emu, system_information, system_information_length, return_length,
                                                            [&](SYSTEM_ERROR_PORT_TIMEOUTS& info) {
                                                                info.StartTimeout = 0;
                                                                info.CommTimeout = 0;
                                                            });

        case SystemKernelDebuggerInformation:
            return handle_query<SYSTEM_KERNEL_DEBUGGER_INFORMATION>(c.emu, system_information, system_information_length, return_length,
                                                                    [&](SYSTEM_KERNEL_DEBUGGER_INFORMATION& info) {
                                                                        info.KernelDebuggerEnabled = FALSE;
                                                                        info.KernelDebuggerNotPresent = TRUE;
                                                                    });

        case SystemLogicalProcessorAndGroupInformation:
            return handle_logical_processor_and_group_information(c, input_buffer, input_buffer_length, system_information,
                                                                  system_information_length, return_length);

        case SystemLogicalProcessorInformation: {
            if (!input_buffer || input_buffer_length != sizeof(USHORT))
            {
                return STATUS_INVALID_PARAMETER;
            }

            using info_type = EMU_SYSTEM_LOGICAL_PROCESSOR_INFORMATION<EmulatorTraits<Emu64>>;

            const auto processor_group = c.emu.read_memory<USHORT>(input_buffer);

            return handle_query<info_type>(c.emu, system_information, system_information_length, return_length, [&](info_type& info) {
                info.Relationship = RelationProcessorCore;

                if (processor_group == 0)
                {
                    using mask_type = decltype(info.ProcessorMask);
                    const auto active_processor_count = c.proc.kusd.get().ActiveProcessorCount;
                    info.ProcessorMask = (static_cast<mask_type>(1) << active_processor_count) - 1;
                }
            });
        }

        case SystemBasicInformation:
        case SystemEmulationBasicInformation:
            return handle_query<SYSTEM_BASIC_INFORMATION64>(c.emu, system_information, system_information_length, return_length,
                                                            [&](SYSTEM_BASIC_INFORMATION64& basic_info) {
                                                                basic_info.Reserved = 0;
                                                                basic_info.TimerResolution = 0x0002625a;
                                                                basic_info.PageSize = 0x1000;
                                                                basic_info.LowestPhysicalPageNumber = 0x00000001;
                                                                basic_info.HighestPhysicalPageNumber = 0x00c9c7ff;
                                                                basic_info.AllocationGranularity = ALLOCATION_GRANULARITY;
                                                                basic_info.MinimumUserModeAddress = MIN_ALLOCATION_ADDRESS;
                                                                basic_info.MaximumUserModeAddress = MAX_ALLOCATION_ADDRESS;
                                                                basic_info.ActiveProcessorsAffinityMask = 0x0000000000000f;
                                                                basic_info.NumberOfProcessors = 4;
                                                            });

        case SystemModuleInformationEx: {
            constexpr auto entry_size = sizeof(EMU_RTL_PROCESS_MODULE_INFORMATION_EX64);
            constexpr auto required_size = entry_size * 2;

            if (return_length)
            {
                return_length.write(static_cast<uint32_t>(required_size));
            }

            if (system_information_length < required_size)
            {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            const auto make_entry = [](const USHORT next_offset,
                                       const uint64_t image_base,
                                       const uint32_t image_size,
                                       const USHORT load_order,
                                       const char* full_path) {
                EMU_RTL_PROCESS_MODULE_INFORMATION_EX64 entry{};
                entry.NextOffset = next_offset;
                entry.BaseInfo.Section = 0;
                entry.BaseInfo.MappedBase = image_base;
                entry.BaseInfo.ImageBase = image_base;
                entry.BaseInfo.ImageSize = image_size;
                entry.BaseInfo.Flags = 0x08804000;
                entry.BaseInfo.LoadOrderIndex = load_order;
                entry.BaseInfo.InitOrderIndex = load_order;
                entry.BaseInfo.LoadCount = 0xFFFF;

                const auto path_len = strlen(full_path);
                const auto copy_len = std::min<size_t>(path_len, sizeof(entry.BaseInfo.FullPathName) - 1);
                memcpy(entry.BaseInfo.FullPathName, full_path, copy_len);

                const auto* last_slash = strrchr(full_path, '\\');
                entry.BaseInfo.OffsetToFileName =
                    last_slash ? static_cast<USHORT>((last_slash - full_path) + 1) : static_cast<USHORT>(0);

                entry.ImageChecksum = 0;
                entry.TimeDateStamp = 0;
                entry.DefaultBase = image_base;
                return entry;
            };

            const auto ntoskrnl = make_entry(static_cast<USHORT>(entry_size),
                                             0xfffff80000000000ull,
                                             0x00800000,
                                             0,
                                             "\\SystemRoot\\system32\\ntoskrnl.exe");
            const auto hal = make_entry(static_cast<USHORT>(0),
                                        0xfffff80000800000ull,
                                        0x00080000,
                                        1,
                                        "\\SystemRoot\\system32\\hal.dll");

            c.emu.write_memory(system_information, ntoskrnl);
            c.emu.write_memory(system_information + entry_size, hal);

            return STATUS_SUCCESS;
        }

        case SystemSupportedProcessorArchitectures: {
            constexpr auto num_arch = 2;

            const auto required_length = sizeof(SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION) * (num_arch + 1);
            if (system_information_length < required_length)
            {
                if (return_length)
                {
                    return_length.try_write(required_length);
                }

                return STATUS_BUFFER_TOO_SMALL;
            }

            std::array<SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION, num_arch + 1> supported_arch{};
            supported_arch[0].Machine = IMAGE_FILE_MACHINE_AMD64;
            supported_arch[0].KernelMode = 1;
            supported_arch[0].UserMode = 1;
            supported_arch[0].Native = 1;
            supported_arch[1].Machine = IMAGE_FILE_MACHINE_I386;
            supported_arch[1].UserMode = 1;

            c.emu.write_memory(system_information, supported_arch);
            return STATUS_SUCCESS;
        }

        default:
            c.win_emu.log.error("Unsupported system info class: %X (%s)\n", info_class, magic_enum::enum_name(info_class).data());
            c.emu.stop();
            return STATUS_NOT_SUPPORTED;
        }
    }

    NTSTATUS handle_NtQuerySystemInformation(const syscall_context& c, const uint32_t info_class, const uint64_t system_information,
                                             const uint32_t system_information_length, const emulator_object<uint32_t> return_length)
    {
        return handle_NtQuerySystemInformationEx(
            c,
            static_cast<SYSTEM_INFORMATION_CLASS>(info_class),
            0,
            0,
            system_information,
            system_information_length,
            return_length);
    }

    NTSTATUS handle_NtSetSystemInformation()
    {
        return STATUS_NOT_SUPPORTED;
    }
}
