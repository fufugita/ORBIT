param(
    [ValidateSet('Foundation', 'Confinement', 'RegistryDiagnostic', 'RegistryWitness', 'HostCapabilities')]
    [string] $Group = 'Confinement',
    [string] $EvidenceDir = 'platform-results'
)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'Native Windows is required' }
New-Item -ItemType Directory -Force $EvidenceDir | Out-Null
if ($Group -eq 'HostCapabilities') {
    # Observational only. Return before all test setup and fake registry fixtures.
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $script:hostCollectionFailed = $false
    $queries = [Collections.Generic.List[object]]::new()
    $report = [ordered]@{
        source=$env:GITHUB_SHA; observation_complete=$false; support_proven=$false
        daemon_usability='unknown_not_contacted'; nested_virtualization_proven=$false
        actual_standard_user_journey_tested=$false; query_timeout_seconds=5
        optional_feature_timeout_seconds=20; service_query_timeout_seconds=20; collection_deadline_seconds=60
    }
    function HostError($record) {
        $cause=$record.Exception
        for($i=0;$i -lt 7 -and $null -ne $cause.InnerException;$i++){$cause=$cause.InnerException}
        $errorData=[ordered]@{type=$cause.GetType().FullName;hresult=$cause.HResult}
        if($cause -is [Microsoft.Management.Infrastructure.CimException]){
            # StatusCode is UInt32; NativeErrorCode is the documented named enum.
            $errorData.cim_status_code=[uint32]$cause.StatusCode
            $errorData.cim_status_type=$cause.StatusCode.GetType().FullName
            $errorData.cim_native_error_code=[int]$cause.NativeErrorCode
            $errorData.cim_native_error_name=$cause.NativeErrorCode.ToString()
            $errorData.cim_native_error_type=$cause.NativeErrorCode.GetType().FullName
        }
        [pscustomobject]$errorData
    }
    function ReadHostCim([string]$class,[string[]]$properties,[string]$filter='',
        [ValidateRange(1,20)][int]$timeoutSeconds=5) {
        $remaining=60-$watch.Elapsed.TotalSeconds
        if($remaining -lt $timeoutSeconds){
            $script:hostCollectionFailed=$true
            $queries.Add([pscustomobject]@{class=$class;status='insufficient_remaining_deadline';elapsed_seconds=0;
                requested_timeout_seconds=$timeoutSeconds;remaining_seconds=[math]::Round([math]::Max(0,$remaining),2)})
            return [pscustomobject]@{status='query_error';rows=@()}
        }
        $queryWatch=[Diagnostics.Stopwatch]::StartNew()
        try {
            $arguments=@{ClassName=$class;Namespace='root/cimv2';Property=$properties;OperationTimeoutSec=$timeoutSeconds;ErrorAction='Stop'}
            if($filter){$arguments.Filter=$filter}
            $rows=@(Get-CimInstance @arguments)
            $queries.Add([pscustomobject]@{class=$class;status='observed';row_count=$rows.Count;
                timeout_seconds=$timeoutSeconds;elapsed_seconds=[math]::Round($queryWatch.Elapsed.TotalSeconds,3)})
            [pscustomobject]@{status='observed';rows=$rows}
        }catch{
            $details=HostError $_
            $status=if($details.cim_native_error_name -in @('InvalidClass','InvalidNamespace','NotSupported')){'unsupported_provider'}else{'query_error'}
            if($status -eq 'query_error'){$script:hostCollectionFailed=$true}
            $queries.Add([pscustomobject]@{class=$class;status=$status;error=$details;
                timeout_seconds=$timeoutSeconds;elapsed_seconds=[math]::Round($queryWatch.Elapsed.TotalSeconds,3)})
            [pscustomobject]@{status=$status;rows=@()}
        }
    }
    function HostBoolean($instance,[string]$property) {
        $value=if($null -eq $instance){$null}else{$instance.CimInstanceProperties[$property]}
        if($null -eq $value -or $null -eq $value.Value){return [pscustomobject]@{status='unknown';value=$null}}
        [pscustomobject]@{status='observed';value=[bool]$value.Value}
    }
    try {
        $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
        $impersonated=[Security.Principal.WindowsIdentity]::GetCurrent($true)
        try {
            $report.privilege=[ordered]@{
                effective_administrator=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                thread_impersonation_present=$null -ne $impersonated
                membership_context=$(if($null -eq $impersonated){'current_process_token'}else{'effective_thread_token_process_authority_unknown'})
                standard_user_support_proven=$false
            }
        }finally{if($null -ne $impersonated){$impersonated.Dispose()};$identity.Dispose()}
        $osQuery=ReadHostCim 'Win32_OperatingSystem' @('Caption','Version','BuildNumber','OSArchitecture','OperatingSystemSKU','ProductType')
        if($osQuery.status -eq 'observed' -and $osQuery.rows.Count -eq 1){
            $os=$osQuery.rows[0]
            if(-not $os.Caption -or -not $os.Version -or -not $os.BuildNumber -or -not $os.OSArchitecture){throw 'Required OS identity properties unavailable'}
            $report.os=[ordered]@{status='observed';edition=$os.Caption;version=$os.Version;build=$os.BuildNumber
                architecture=$os.OSArchitecture;edition_sku=$os.OperatingSystemSKU
                family=$(if($os.ProductType -eq 1){'client'}elseif($os.ProductType -in @(2,3)){'server'}else{'unknown'})}
        }else{$report.os=@{status='unavailable_or_unexpected_result';query_status=$osQuery.status};$script:hostCollectionFailed=$true}
        $systemQuery=ReadHostCim 'Win32_ComputerSystem' @('HypervisorPresent')
        $system=if($systemQuery.rows.Count -eq 1){$systemQuery.rows[0]}else{$null}
        $report.hypervisor_present=HostBoolean $system 'HypervisorPresent'
        if($systemQuery.status -eq 'observed' -and $systemQuery.rows.Count -ne 1){$script:hostCollectionFailed=$true}
        $cpuQuery=ReadHostCim 'Win32_Processor' @('VMMonitorModeExtensions','SecondLevelAddressTranslationExtensions','VirtualizationFirmwareEnabled')
        $report.cpu_virtualization=@(foreach($cpu in $cpuQuery.rows){
            [ordered]@{vm_monitor_mode_extensions=(HostBoolean $cpu 'VMMonitorModeExtensions')
                slat=(HostBoolean $cpu 'SecondLevelAddressTranslationExtensions')
                firmware_virtualization=(HostBoolean $cpu 'VirtualizationFirmwareEnabled')}
        })
        $report.cpu_query_status=$cpuQuery.status
        if($cpuQuery.status -eq 'observed' -and $cpuQuery.rows.Count -eq 0){$script:hostCollectionFailed=$true;$report.cpu_query_status='unexpected_empty_result'}
        $report.nested_exposure_indicator='unknown'
        if($report.hypervisor_present.value -eq $true -and $report.cpu_virtualization.Count -gt 0){
            $flags=@($report.cpu_virtualization | ForEach-Object { $_.vm_monitor_mode_extensions.value; $_.slat.value; $_.firmware_virtualization.value })
            $unknown=@($report.cpu_virtualization | Where-Object {
                $_.vm_monitor_mode_extensions.status -ne 'observed' -or $_.slat.status -ne 'observed' -or $_.firmware_virtualization.status -ne 'observed'
            })
            if($unknown.Count -eq 0){
                $report.nested_exposure_indicator=if(@($flags | Where-Object {$_ -ne $true}).Count -eq 0){'reported_cpu_flags_exposed_under_hypervisor'}else{'not_indicated_by_reported_flags'}
            }
        }
        # This documented provider supports both client and server editions.
        # A name outside this image's catalog is distinct from Disabled/Absent.
        $featureNames=@('Microsoft-Hyper-V-All','Microsoft-Hyper-V','Hyper-V','Containers','Containers-DisposableClientVM')
        $featureQuery=ReadHostCim 'Win32_OptionalFeature' @('Name','InstallState') (($featureNames | ForEach-Object {"Name='$_'"}) -join ' OR ') -timeoutSeconds 20
        $report.feature_query_path='root/cimv2:Win32_OptionalFeature (documented client/server provider)'
        $report.features=@(foreach($name in $featureNames){
            $matches=@($featureQuery.rows | Where-Object {$_.Name -ceq $name})
            if($featureQuery.status -ne 'observed'){@{name=$name;status=$featureQuery.status;state='unknown'}}
            elseif($matches.Count -eq 0){@{name=$name;status='not_catalogued_on_this_image';state='unknown'}}
            elseif($matches.Count -eq 1){
                $state=switch([int]$matches[0].InstallState){1{'enabled'}2{'disabled'}3{'absent'}4{'unknown'}default{'unknown'}}
                @{name=$name;status='observed';state=$state;raw_install_state=$matches[0].InstallState}
            }else{$script:hostCollectionFailed=$true;@{name=$name;status='unexpected_duplicate_result';state='unknown'}}
        })
        $serviceNames=@('vmcompute','hns','docker')
        $serviceQuery=ReadHostCim 'Win32_Service' @('Name','State','StartMode') (($serviceNames | ForEach-Object {"Name='$_'"}) -join ' OR ') -timeoutSeconds 20
        $report.services=@(foreach($name in $serviceNames){
            $matches=@($serviceQuery.rows | Where-Object {$_.Name -ieq $name})
            if($serviceQuery.status -ne 'observed'){@{name=$name;status=$serviceQuery.status}}
            elseif($matches.Count -eq 0){@{name=$name;status='not_installed'}}
            elseif($matches.Count -eq 1){@{name=$name;status='observed';state=$matches[0].State;start_mode=$matches[0].StartMode}}
            else{$script:hostCollectionFailed=$true;@{name=$name;status='unexpected_duplicate_result'}}
        })
        $systemRoot=[Environment]::GetFolderPath([Environment+SpecialFolder]::System)
        $programFiles=[Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
        $roots=@($systemRoot,$programFiles) | Where-Object {$_ -and [IO.Path]::IsPathFullyQualified($_) -and -not $_.StartsWith('\\')}
        if($roots.Count -ne 2){throw 'Expected local system/program installation roots unavailable'}
        $files=@(
            @{name='docker.exe';paths=@((Join-Path $programFiles 'Docker\docker.exe'),(Join-Path $programFiles 'Docker\Docker\resources\bin\docker.exe'),(Join-Path $systemRoot 'docker.exe'))},
            @{name='WindowsSandbox.exe';paths=@((Join-Path $systemRoot 'WindowsSandbox.exe'))},
            @{name='wsb.exe';paths=@((Join-Path $systemRoot 'wsb.exe'))}
        )
        $report.executable_search_scope='fixed local System/ProgramFiles installation locations; no PATH/user-directory scan'
        $report.executables=@(foreach($file in $files){
            $found=$false
            foreach($candidate in $file.paths){
                try{
                    $path=[IO.Path]::GetFullPath($candidate)
                    for($depth=0;$depth -lt 8;$depth++){
                        $permitted=@($roots | Where-Object {$path.StartsWith(($_.TrimEnd('\')+'\'),[StringComparison]::OrdinalIgnoreCase)}).Count -gt 0
                        if(-not $permitted){throw 'Executable link leaves scoped local installation roots'}
                        try{$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop}
                        catch{
                            if($_.FullyQualifiedErrorId -eq 'PathNotFound,Microsoft.PowerShell.Commands.GetItemCommand'){break}
                            throw
                        }
                        if($item -isnot [IO.FileInfo]){throw 'Expected installed executable is not a file'}
                        if(-not $item.LinkTarget){
                            $version=[Diagnostics.FileVersionInfo]::GetVersionInfo($item.FullName)
                            @{name=$file.name;status='observed';canonical_path=$item.FullName;canonicalization='absolute_normalized_leaf_links_resolved';file_version=$version.FileVersion;product_version=$version.ProductVersion}
                            $found=$true;break
                        }
                        $path=if([IO.Path]::IsPathFullyQualified($item.LinkTarget)){$item.LinkTarget}else{[IO.Path]::GetFullPath((Join-Path $item.DirectoryName $item.LinkTarget))}
                    }
                    if($depth -ge 8){throw 'Executable link depth exceeded'}
                }catch{$found=$true;$script:hostCollectionFailed=$true;@{name=$file.name;status='query_error';error=(HostError $_)}}
            }
            if(-not $found){@{name=$file.name;status='not_found_in_scoped_locations';systemwide_absence_proven=$false}}
        })
    }catch{$script:hostCollectionFailed=$true;$report.collection_error=HostError $_}
    $report.queries=@($queries.ToArray())
    $report.elapsed_seconds=[math]::Round($watch.Elapsed.TotalSeconds,2)
    if($watch.Elapsed.TotalSeconds -gt 60){$script:hostCollectionFailed=$true;$report.collection_deadline_exceeded=$true}
    $report.observation_complete=-not $script:hostCollectionFailed
    $report | ConvertTo-Json -Depth 10 | Out-File (Join-Path $EvidenceDir 'host-capabilities.json')
    if($script:hostCollectionFailed){throw 'Host capability collection incomplete; inspect bounded query statuses'}
    return
}
$env:CARGO_BUILD_JOBS = '1'
$env:CARGO_TERM_COLOR = 'never'
$env:NO_COLOR = '1'
if ($Group -eq 'Foundation') {
    $log = Join-Path $EvidenceDir 'foundation.log'
    cargo +1.99.0 test --locked --no-fail-fast -p orbit-platform --lib --test windows_foundation -- --test-threads=1 --show-output 2>&1 |
        Tee-Object -FilePath $log
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $required = @(
        'ambiguous_components_are_rejected',
        'lock_namespace_is_reserved_consistently',
        'windows::unicode_private_create_reopen_and_read_bounds',
        'windows::absolute_drive_and_verbatim_aliases_keep_identity',
        'windows::held_root_and_ancestor_cannot_be_swapped',
        'windows::file_keeps_ancestor_handles_after_directory_drop',
        'windows::hardlinks_and_junctions_are_rejected',
        'windows::file_symlink_is_not_followed',
        'windows::permissive_dacl_is_rejected_by_held_and_reopened_checks',
        'windows::wrong_owner_is_rejected',
        'windows::publication_does_not_clobber_and_replace_retains_original',
        'windows::replacement_requires_expected_identity_and_exclusive_lock',
        'windows::exclusive_lock_excludes_other_processes_and_releases',
        'windows::missing_existing_lock_does_not_create_state',
        'windows::existing_lock_fixed_buffer_snapshot_and_cursor',
        'windows::file_snapshot_detects_content_change',
        'windows::existing_lock_rejects_nonempty_and_unsafe_without_repair',
        'windows::existing_only_locks_observe_cross_process_contention',
        'windows::shared_readers_coexist_but_exclude_writer',
        'fs::windows::tests::private_storage_works_without_admin_group_or_privileges',
        'fs::windows::tests::flush_failure_preserves_original_and_unpublished_candidate',
        'fs::windows::tests::prepublication_failure_restores_expected_original',
        'fs::windows::tests::postpublication_flush_failure_retains_original_backup',
        'fs::windows::tests::inspection_rechecks_acl_after_snapshot',
        'fs::windows::tests::inspection_revalidates_full_identity_after_replacement',
        'windows::inspection_empty_root_is_no_effect',
        'windows::source_directory_reads_public_unicode_file_without_private_authority',
        'windows::source_directory_rejects_replaced_full_identity',
        'windows::source_file_rejects_reads_over_the_requested_bound',
        'windows::owned_container_accepts_owner_safe_readable_root',
        'windows::inspection_observes_existing_shared_lock_and_nested_files',
        'windows::inspection_rejects_permissive_and_wrong_owner_entries_without_repair',
        'windows::inspection_rejects_reparse_and_hardlink_entries',
        'windows::inspection_limits_reject_extra_entry_path_and_depth_without_changes',
        'windows::inspection_holds_root_and_ancestors_while_walking',
        'windows::locked_update_has_explicit_cursor_append_length_and_truncate',
        'windows::lifecycle_rejects_wrong_identity_shared_and_foreign_guards',
        'windows::checked_backup_restore_and_cleanup_preserve_identity',
        'windows::restore_refuses_occupied_target_and_reparse_sources',
        'windows::enumeration_is_bounded_and_revalidates_entries',
        'windows::empty_child_cleanup_refuses_live_anchors_nonempty_and_wrong_identity',
        'windows::stable_lock_names_cannot_enter_data_mutation_routes',
        'fs::windows::tests::removal_faults_report_preserved_or_disposition_acknowledged_state',
        'fs::windows::tests::shared_reader_is_excluded_from_actual_two_rename_gap',
        'windows::published_candidate_cannot_be_republished_without_a_guard',
        'windows::ntfs_short_alias_cannot_bypass_reserved_lock_policy',
        'windows::simultaneous_publication_preserves_the_only_successful_name',
        'windows::owned_container_accepts_system_admin_and_inherited_effective_read_grants',
        'windows::owned_container_excludes_valid_inherit_only_grants_from_current_policy',
        'windows::owned_container_rejects_dangerous_generic_concrete_and_unknown_rights',
        'windows::owned_container_rejects_null_dacl_and_wrong_owner',
        'windows::owned_container_rechecks_identity_and_dacl_without_repair',
        'windows::source_directory_enumerates_nested_unicode_and_preserves_metadata',
        'windows::source_directory_carries_depth_budget_and_rejects_stale_child_identity',
        'windows::source_directory_rejects_hardlinks_and_reparse_entries_without_following_them',
        'windows::source_directory_holds_root_and_ancestors_while_walking',
        'windows::source_directory_enumeration_enforces_entry_and_name_bounds_without_changes',
        'fs::windows::tests::container_ace_layout_parser_only_rejects_malformed_unknown_and_callback_forms',
        'fs::windows::tests::source_component_policy_is_separate_from_private_names',
        'fs::windows::tests::source_snapshot_rejects_link_added_after_initial_kind_check',
        'fs::windows::tests::staged_directory_child_keeper_rename_prerequisite',
        'fs::windows::tests::staged_directory_delete_child_reacquisition_prerequisite',
        'windows::source_execution_permission_matches_native_r_rx_and_full_control',
        'windows::source_execution_permission_denial_is_extension_independent',
        'windows::staged_package_seals_and_publishes_one_file',
        'windows::staged_package_discard_removes_one_sealed_file',
        'windows::staged_package_requires_matching_exclusive_parent_guard',
        'windows::staged_package_no_clobber_preserves_file_empty_and_populated_targets',
        'fs::windows::tests::staged_package_live_views_refuse_publication_and_cleanup',
        'windows::published_package_read_seam_reopens_expected_identity'
    )
    if ($required.Count -ne 70 -or @($required | Select-Object -Unique).Count -ne 70) {
        throw "Foundation's exact required-name manifest must contain 70 unique cases; found $($required.Count)"
    }
    $report = Get-Content $log -Raw
    foreach ($case in $required) {
        if ($report -notmatch ('(?m)^test ' + [regex]::Escape($case) + ' \.\.\. ok\r?$')) {
            throw "Required native foundation case did not pass: $case"
        }
    }
    if ($report -match '\b[1-9][0-9]* (ignored|filtered out)\b') { throw 'Foundation cases were skipped' }
    @{ required_cases = $required.Count; status = 'passed'; source = $env:GITHUB_SHA } |
        ConvertTo-Json | Out-File (Join-Path $EvidenceDir 'foundation.json')
    return
}
if ($Group -eq 'RegistryWitness') {
    # This opt-in experiment writes disposable fake values only on the exact
    # GitHub-hosted proof ref. Local/operator registry state is never a fixture.
    $requiredFixture = @{
        GITHUB_ACTIONS = 'true'
        RUNNER_ENVIRONMENT = 'github-hosted'
        RUNNER_OS = 'Windows'
        GITHUB_REF = 'refs/heads/codex/platform-first-run-windows-proof-20261105'
        ORBIT_REGISTRY_WITNESS_FIXTURE = 'github-hosted-fake-data-only-v1'
        ORBIT_REGISTRY_WITNESS_NORMAL_CONTROLS = '37-v1'
    }
    foreach ($entry in $requiredFixture.GetEnumerator()) {
        if ([Environment]::GetEnvironmentVariable($entry.Key) -cne $entry.Value) {
            throw 'Registry witness requires the declared disposable Windows CI fixture'
        }
    }
    if ($env:GITHUB_RUN_ID -notmatch '^[0-9]+$' -or $env:GITHUB_SHA -notmatch '^[0-9a-f]{40}$') {
        throw 'Registry witness run identity missing'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $threadIdentity = [Security.Principal.WindowsIdentity]::GetCurrent($true)
    try {
        $administrator = [Security.Principal.WindowsPrincipal]::new($identity).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
        $parentIdentity = [ordered]@{
            source=$env:GITHUB_SHA;run=$env:GITHUB_RUN_ID;user_sid=$identity.User.Value
            elevated=$administrator;thread_impersonation_present=($null -ne $threadIdentity)
            fixture_context='github-hosted-disposable-runner';ordinary_user_support_proven=$false
            production_policy_unchanged=$true;credential_values_enumerated=$false
            cleanup_negative_controls='PENDING_NATIVE_ORACLES'
        }
    } finally {
        if ($null -ne $threadIdentity) { $threadIdentity.Dispose() }
        $identity.Dispose()
    }
    if (-not $administrator -or $parentIdentity.thread_impersonation_present) {
        throw 'Registry witness fixture requires its declared primary-token administrator without thread impersonation'
    }
    $keys = [Collections.Generic.List[Microsoft.Win32.RegistryKey]]::new()
    $created = [Collections.Generic.List[object]]::new()
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class OrbitRegistryWitnessFixture {
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
 public static extern int RegQueryValueExW(SafeRegistryHandle key,string name,IntPtr reserved,
     out uint type,IntPtr data,ref uint size);
}
'@
    function AssertMarkerAbsent($key,[string]$name) {
        [uint32]$kind=0; [uint32]$size=0
        $status=[OrbitRegistryWitnessFixture]::RegQueryValueExW($key.Handle,$name,[IntPtr]::Zero,
            [ref]$kind,[IntPtr]::Zero,[ref]$size)
        if ($status -ne 2) { throw "Marker precondition is not exact-name absence: status $status" }
    }
    $nonce = $null
    $failure = $null
    $cleanupComplete = $false
    try {
        $machineRoot = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
        $userRoot = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::Users,[Microsoft.Win32.RegistryView]::Registry64)
        $keys.Add($machineRoot); $keys.Add($userRoot)
        $machine = $machineRoot.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment',$true)
        $user = $userRoot.OpenSubKey(($parentIdentity.user_sid+'\Environment'),$true)
        if ($null -eq $machine -or $null -eq $user) { throw 'Required existing registry marker targets unavailable' }
        $keys.Add($machine); $keys.Add($user)
        for ($attempt=0; $attempt -lt 32; $attempt++) {
            $candidate = [guid]::NewGuid().ToString('N')
            $machineName = 'ORBIT_WITNESS_MACHINE_'+$candidate
            $userName = 'ORBIT_WITNESS_USER_'+$candidate
            try { AssertMarkerAbsent $machine $machineName; AssertMarkerAbsent $user $userName; $nonce=$candidate; break }
            catch { if ($_.Exception.Message -notlike 'Marker precondition is not exact-name absence:*') { throw } }
        }
        if (-not $nonce) { throw 'Could not allocate collision-free marker names' }
        $machineName = 'ORBIT_WITNESS_MACHINE_'+$nonce
        $userName = 'ORBIT_WITNESS_USER_'+$nonce
        $machineValue = [guid]::NewGuid().ToString('N')
        $userValue = [guid]::NewGuid().ToString('N')
        foreach ($row in @(
            @{key=$machine;name=$machineName;value=$machineValue;target='machine'},
            @{key=$user;name=$userName;value=$userValue;target='user'}
        )) {
            # Recheck immediately before a create-only write; never replace a collision.
            AssertMarkerAbsent $row.key $row.name
            $created.Add($row)
            $row.key.SetValue($row.name,$row.value,[Microsoft.Win32.RegistryValueKind]::String)
            if ($row.key.GetValueKind($row.name) -ne [Microsoft.Win32.RegistryValueKind]::String -or
                $row.key.GetValue($row.name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) -cne $row.value) {
                throw 'Known-present fake marker control failed'
            }
        }
        $parentIdentity.nonce=$nonce
        $parentIdentity.marker_names=@($machineName,$userName)
        $parentIdentity.marker_sha256=@(
            [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($machineValue))),
            [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($userValue)))
        )
        $parentIdentity | ConvertTo-Json -Depth 5 | Out-File (Join-Path $EvidenceDir 'registry-witness-parent.json')
        $env:ORBIT_REGISTRY_WITNESS_NONCE=$nonce
        $env:ORBIT_REGISTRY_WITNESS_USER_SID=$parentIdentity.user_sid
        $env:ORBIT_REGISTRY_WITNESS_MACHINE_MARKER=$machineName
        $env:ORBIT_REGISTRY_WITNESS_USER_MARKER=$userName
        $env:ORBIT_REGISTRY_WITNESS_MACHINE_HASH=$parentIdentity.marker_sha256[0]
        $env:ORBIT_REGISTRY_WITNESS_USER_HASH=$parentIdentity.marker_sha256[1]
        $case='process::windows::registry_witness_tests::registry_witness_stage_a'
        $log=Join-Path $EvidenceDir 'registry-witness.log'
        cargo +1.99.0 test --locked -p orbit-platform --features registry-witness --lib $case -- --exact --test-threads=1 --nocapture 2>&1 |
            Tee-Object -FilePath $log
        $code=$LASTEXITCODE
        $report=Get-Content $log -Raw
        $frames=[Collections.Generic.List[string]]::new()
        $cursor=0
        $frameStart=[string][char]0x1e+'ORBITW1:'
        while (($start=$report.IndexOf($frameStart,$cursor,[StringComparison]::Ordinal)) -ge 0) {
            $lengthStart=$start+$frameStart.Length
            $colon=$report.IndexOf(':',$lengthStart)
            if ($colon -lt 0 -or $colon-$lengthStart -lt 1 -or $colon-$lengthStart -gt 4) { throw 'Malformed registry witness frame length' }
            $lengthText=$report.Substring($lengthStart,$colon-$lengthStart)
            if ($lengthText -notmatch '^\d{1,4}$') { throw 'Non-numeric registry witness frame length' }
            $length=[int]$lengthText
            if ($length -gt 8192) { throw 'Oversized registry witness frame' }
            $payloadStart=$colon+1
            $payloadEnd=$payloadStart+$length
            if ($payloadEnd -ge $report.Length -or [int][char]$report[$payloadEnd] -ne 0x1f) { throw 'Truncated registry witness frame' }
            $payload=$report.Substring($payloadStart,$length)
            if ($payload -match '[^\x20-\x7e]') { throw 'Registry witness frame payload is not printable ASCII' }
            if ($payload -notmatch '^(registry_witness_probe|registry_witness_parent_binding|registry_witness_helper_directory_access|registry_witness_helper_directory_descriptor|registry_witness_child_result|registry_witness_diagnostic|registry_witness_child_admission|registry_witness_child_complete|registry_witness_status|registry_witness_finalization|registry_witness_incomplete|registry_witness_setup_cleanup|registry_witness_control)(?: |$)') {
                throw 'Unknown framed registry witness record type'
            }
            $frames.Add($payload)
            $cursor=$payloadEnd+1
        }
        $frames | Out-File (Join-Path $EvidenceDir 'registry-witness-records.txt') -Encoding ascii
        $expected=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($timing in @('before','after')) { foreach ($api in @('win32','nt')) { foreach ($target in @('machine','user')) { [void]$expected.Add("parent_present/$timing/$api/$target") } } }
        foreach ($phase in @('baseline','reset')) { foreach ($api in @('win32','nt')) { foreach ($target in @('machine','user')) { [void]$expected.Add("$phase/host_denied/$api/$target") } } }
        foreach ($phase in @('inherited','mapped','remapped')) { foreach ($view in @('machine_view','user_view')) { [void]$expected.Add("$phase/public_read/$view") } }
        foreach ($view in @('machine_view','user_view')) { [void]$expected.Add("mapped/private_absent/$view") }
        foreach ($target in @('machine','user')) { [void]$expected.Add("mapped/host_denied/nt/$target") }
        [void]$expected.Add('mapped/host_denied/win32/user')
        foreach ($operation in @('set_value','delete_value','create_subkey','delete_leaf','set_dacl','set_owner','reopen_write','reopen_delete','reopen_write_dac','reopen_write_owner','duplicate_mutation')) { foreach ($view in @('machine_view','user_view')) { [void]$expected.Add("mutation/$operation/$view") } }
        foreach ($view in @('machine_view','user_view')) { [void]$expected.Add("duplicate_read/$view") }
        foreach ($right in @('dup_handle','vm_write','vm_operation','create_thread','write_dac','write_owner','vm_read')) { [void]$expected.Add("parent_authority/$right") }
        [void]$expected.Add('parent_token/process_query_limited')
        foreach ($right in @('token_duplicate','write_dac','write_owner','token_impersonate','token_assign_primary')) { [void]$expected.Add("parent_token/$right") }
        foreach ($view in @('machine_view','user_view')) { [void]$expected.Add("parent_recovery/$view") }
        foreach ($life in @('normal_job_zero','cancel_ready_mapped','cancel_job_zero','cleanup_absent')) { [void]$expected.Add("lifetime/$life") }
        if ($expected.Count -ne 70) { throw "Internal closed probe manifest has $($expected.Count) IDs" }
        $actual=[Collections.Generic.List[string]]::new()
        foreach ($frame in $frames) {
            if($frame.StartsWith('registry_witness_probe ') -and $frame -notmatch '^registry_witness_probe id=([^ ]+) .+$'){
                throw 'Malformed framed registry witness probe'
            }
            if ($frame -match '^registry_witness_probe id=([^ ]+) ') { $actual.Add($Matches[1]) }
        }
        if (@($actual | Select-Object -Unique).Count -ne $actual.Count) { throw 'Duplicate framed registry witness probe ID' }
        foreach ($id in $actual) { if (-not $expected.Contains($id)) { throw "Unexpected registry witness probe ID: $id" } }
        function WitnessField([string]$record,[string]$name) {
            $pattern='(?:^|\s)'+[regex]::Escape($name)+'=([^\s]+)'
            $found=[regex]::Matches($record,$pattern)
            if($found.Count -ne 1){throw "Missing or duplicate witness field: $name"}
            $found[0].Groups[1].Value
        }
        function WitnessExactFields([string]$record,[string[]]$required,[string[]]$allowed=$required) {
            $fields=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
            $tokens=$record -split ' '
            foreach($token in $tokens | Select-Object -Skip 1){
                $separator=$token.IndexOf('=')
                if($separator -le 0){throw 'Malformed witness key/value field'}
                $name=$token.Substring(0,$separator)
                $value=$token.Substring($separator+1)
                if($name -notmatch '^[a-z_][a-z0-9_]*$' -or [string]::IsNullOrEmpty($value)){
                    throw "Malformed witness field: $name"
                }
                if(-not $fields.TryAdd($name,$value)){throw "Duplicate witness field: $name"}
            }
            foreach($name in $required){if(-not $fields.ContainsKey($name)){throw "Missing witness field: $name"}}
            foreach($name in $fields.Keys){if($name -notin $allowed){throw "Unknown witness field: $name"}}
            if($fields.Count -ne $required.Count){throw 'Unexpected witness field count'}
        }
        function WitnessHex([string]$value) {
            if($value -notmatch '^0x[0-9a-fA-F]{1,8}$'){throw "Invalid hexadecimal witness status: $value"}
            [Convert]::ToUInt32($value.Substring(2),16)
        }
        $cleanupCaseManifest=@(
            'wrong_image_id','wrong_directory_id','wrong_profile_id','wrong_image_hash',
            'changed_image_dacl','unknown_registry_key','unknown_registry_value',
            'unknown_helper_entry','unknown_profile_entry','profile_enumeration_limit',
            'held_reader_sharing','image_leaf_swap','directory_swap','image_hardlink',
            'missing_job_fence','live_nonzero_job','job_query_error','reader_close_error',
            'profile_anchor_close_error','observation_parent_close_error','job_fence_close_error',
            'image_disposition_noeffect','directory_disposition_noeffect','sdk_error',
            'sdk_s_ok_noeffect'
        )
        if($cleanupCaseManifest.Count -ne 25 -or
            @($cleanupCaseManifest | Select-Object -Unique).Count -ne 25){
            throw 'Internal closed cleanup-control manifest must contain 25 unique cases'
        }
        $cleanupImplemented=@(
            'wrong_image_hash','unknown_registry_key','wrong_image_id','wrong_directory_id',
            'wrong_profile_id','changed_image_dacl','unknown_registry_value',
            'unknown_helper_entry','unknown_profile_entry','profile_enumeration_limit',
            'image_leaf_swap','directory_swap','image_hardlink','missing_job_fence',
            'live_nonzero_job','job_query_error'
        )
        $cleanupLate=@{
            held_reader_sharing=@{r='-';i='+';d='+';p='+';di='0';dd='0';sdk='0';native_executed='1';injected='false';native_domain='ntstatus';native_result='0xC0000043';reported_result='native_status';fault='held_reader_open';target='image_delete_open';domain='ntstatus';code='0xC0000043';win32='32';owner='none';image_native='not_called';image_reported='not_called';directory_native='not_called';directory_reported='not_called';sdk_native='not_called';sdk_reported='not_called';profile_probe='relative_success'}
            reader_close_error=@{r='-';i='+';d='+';p='+';di='0';dd='0';sdk='0';native_executed='1';injected='true';native_domain='close';native_result='close_succeeded';reported_result='injected_close_error';fault='image_reader_close';target='image_reader_close';domain='receipt';code='injected_close';win32='not_applicable';owner='helper_image_reader';image_native='not_called';image_reported='not_called';directory_native='not_called';directory_reported='not_called';sdk_native='not_called';sdk_reported='not_called';profile_probe='relative_success'}
            profile_anchor_close_error=@{r='-';i='-';d='-';p='+';di='1';dd='1';sdk='0';native_executed='1';injected='true';native_domain='close';native_result='close_succeeded';reported_result='injected_close_error';fault='profile_ac_anchor_close';target='sdk_suppressed_profile_present';domain='receipt';code='injected_close';win32='not_applicable';owner='profile_ac_anchor';image_native='STATUS_SUCCESS';image_reported='STATUS_SUCCESS';directory_native='STATUS_SUCCESS';directory_reported='STATUS_SUCCESS';sdk_native='not_called';sdk_reported='not_called';profile_probe='relative_success'}
            observation_parent_close_error=@{r='-';i='-';d='-';p='-';di='1';dd='1';sdk='1';native_executed='1';injected='true';native_domain='close';native_result='close_succeeded';reported_result='injected_close_error';fault='packages_observer_close';target='packages_observer_close';domain='receipt';code='injected_close';win32='not_applicable';owner='packages_observer';image_native='STATUS_SUCCESS';image_reported='STATUS_SUCCESS';directory_native='STATUS_SUCCESS';directory_reported='STATUS_SUCCESS';sdk_native='0x00000000';sdk_reported='0x00000000';profile_probe='relative_not_found'}
            job_fence_close_error=@{r='-';i='-';d='-';p='-';di='1';dd='1';sdk='1';native_executed='1';injected='true';native_domain='close';native_result='close_succeeded';reported_result='injected_close_error';fault='normal_job_fence_close';target='normal_job_fence_close';domain='receipt';code='injected_close';win32='not_applicable';owner='normal_job_fence';image_native='STATUS_SUCCESS';image_reported='STATUS_SUCCESS';directory_native='STATUS_SUCCESS';directory_reported='STATUS_SUCCESS';sdk_native='0x00000000';sdk_reported='0x00000000';profile_probe='relative_not_found'}
            image_disposition_noeffect=@{r='-';i='+';d='+';p='+';di='0';dd='0';sdk='0';native_executed='0';injected='true';native_domain='ntstatus';native_result='not_called';reported_result='success';fault='image_disposition';target='image_presence_postprobe';domain='receipt';code='image_present';win32='not_applicable';owner='none';image_native='not_called';image_reported='success';directory_native='not_called';directory_reported='not_called';sdk_native='not_called';sdk_reported='not_called';profile_probe='relative_success'}
            directory_disposition_noeffect=@{r='-';i='-';d='+';p='+';di='1';dd='0';sdk='0';native_executed='0';injected='true';native_domain='ntstatus';native_result='not_called';reported_result='success';fault='directory_disposition';target='directory_presence_postprobe';domain='receipt';code='dir_present';win32='not_applicable';owner='none';image_native='STATUS_SUCCESS';image_reported='STATUS_SUCCESS';directory_native='not_called';directory_reported='success';sdk_native='not_called';sdk_reported='not_called';profile_probe='relative_success'}
            sdk_error=@{r='-';i='-';d='-';p='+';di='1';dd='1';sdk='0';native_executed='0';injected='true';native_domain='hresult';native_result='not_called';reported_result='0x80004005';fault='sdk_call';target='sdk_reported_result';domain='hresult';code='fixed_non_s_ok';win32='not_applicable';owner='none';image_native='STATUS_SUCCESS';image_reported='STATUS_SUCCESS';directory_native='STATUS_SUCCESS';directory_reported='STATUS_SUCCESS';sdk_native='not_called';sdk_reported='0x80004005';profile_probe='relative_success'}
            sdk_s_ok_noeffect=@{r='-';i='-';d='-';p='+';di='1';dd='1';sdk='0';native_executed='0';injected='true';native_domain='hresult';native_result='not_called';reported_result='0x00000000';fault='sdk_call';target='profile_presence_postprobe';domain='hresult';code='S_OK';win32='not_applicable';owner='none';image_native='STATUS_SUCCESS';image_reported='STATUS_SUCCESS';directory_native='STATUS_SUCCESS';directory_reported='STATUS_SUCCESS';sdk_native='not_called';sdk_reported='0x00000000';profile_probe='relative_success'}
        }
        $cleanupLateOrder=@('held_reader_sharing','reader_close_error','profile_anchor_close_error',
            'observation_parent_close_error','job_fence_close_error','image_disposition_noeffect',
            'directory_disposition_noeffect','sdk_error','sdk_s_ok_noeffect')
        if($cleanupLate.Count -ne 9 -or @($cleanupLateOrder | Select-Object -Unique).Count -ne 9 -or
            @($cleanupLateOrder | Where-Object {$_ -notin $cleanupCaseManifest}).Count -ne 0 -or
            @($cleanupImplemented | Where-Object {$_ -in $cleanupLateOrder}).Count -ne 0){
            throw 'Internal late cleanup-control table is not the exact disjoint nine-case set'
        }
        $cleanupPending=@($cleanupCaseManifest | Where-Object {$_ -notin $cleanupImplemented -and $_ -notin $cleanupLateOrder})
        if($cleanupImplemented.Count -ne 16 -or $cleanupLate.Count -ne 9 -or $cleanupPending.Count -ne 0){throw 'Expected all 25 cleanup controls in exact early/late sets'}
        function Get-CleanupControlMode([string]$CaseName) {
            if($CaseName -in $cleanupImplemented){return 'retained'}
            if($cleanupLate.ContainsKey($CaseName)){return 'partial'}
            throw "Cleanup control is not implemented: $CaseName"
        }
function Get-LateDetailRequiredFields {
    $required=@('case','nonce','source','run','selected_unit','parent_pid','parent_creation',
        'setup_verified','target_reached','partial_verified','fault_phase','target_refusal_phase',
        'target_count','unexpected_error_count','native_executed','native_domain','native_result',
        'reported_result','injected','registry_fixture_id','registry_root_state',
        'registry_key_leaf_utf8_bytes','registry_key_leaf_utf8_hex','registry_native_key_name_utf8_bytes',
        'registry_native_key_name_utf8_hex','registry_software_parent_native_name_utf8_bytes',
        'registry_software_parent_native_name_utf8_hex','registry_parent_hkey_provenance',
        'registry_software_hkey_handle_value','registry_software_hkey_before_native_name_utf8_bytes',
        'registry_software_hkey_before_native_name_utf8_hex','registry_software_hkey_before_result',
        'registry_software_hkey_after_native_name_utf8_bytes','registry_software_hkey_after_native_name_utf8_hex',
        'registry_software_hkey_after_result','registry_preclose_absence_result',
        'registry_predelete_machine_view_sha256','registry_predelete_user_view_sha256',
        'registry_key_descriptor_sha256')
    foreach($object in @('image','helper_directory','profile_entry')){
        foreach($suffix in @('state','expected_volume_id','expected_file_id','observed_volume_id',
            'observed_file_id','observed_kind','observed_content_sha256','observed_descriptor_sha256',
            'held_parent_volume_id','held_parent_file_id','relative_probe_result','inventory_count','inventory_sha256')){
            $required+=($object+'_'+$suffix)
        }
    }
    $required+=@('image_disposition_executed','image_disposition_native_result',
        'image_disposition_reported_result','directory_disposition_executed',
        'directory_disposition_native_result','directory_disposition_reported_result',
        'sdk_executed','sdk_native_hresult','sdk_reported_hresult','profile_absence_probe',
        'control_directory_volume_id','control_directory_file_id','control_directory_descriptor_sha256',
        'foreign_canary_name_utf8_bytes','foreign_canary_name_utf8_hex',
        'foreign_canary_expected_volume_id','foreign_canary_expected_file_id',
        'foreign_canary_observed_volume_id','foreign_canary_observed_file_id',
        'foreign_canary_expected_content_sha256','foreign_canary_observed_content_sha256',
        'foreign_canary_expected_descriptor_sha256','foreign_canary_observed_descriptor_sha256',
        'foreign_canary_setup_result','foreign_canary_preimage_matches','foreign_canary_postimage_matches')
    foreach($owner in @('helper_image_reader','held_reader_blocker','image_delete_handle',
        'helper_directory_keeper','profile_ac_anchor','profile_entry_anchor','packages_observer',
        'software_registry_parent_hkey','registry_fixture_hkey','normal_job_fence','cancel_job_fence')){
        $required+=@("${owner}_state","${owner}_close_native_result","${owner}_close_reported_result")
    }
    $required+='held_reader_blocker_open_native_result'
    $required+='errors'
    return ,$required
}

function Assert-LateErrorGrammar([string]$Value,[hashtable]$Expected) {
    if($Value -notmatch '^v1\|([0-9]|1[0-6])\|(.*)$'){throw 'Late error list is malformed or exceeds 16 events'}
    $count=[int]$Matches[1];$body=$Matches[2]
    $events=@(if($count -eq 0){@()}else{@($body -split ';',-1)})
    if($events.Count -ne $count -or $count -ne 1){throw 'Late control requires one exact target event and zero unexpected events'}
    if($events[0] -cnotmatch '^([a-z_]+),([a-z_]+),([A-Za-z0-9_]{1,16}|0x[0-9A-F]{8}),([0-9A-F]*)$'){
        throw 'Late target event does not match the closed ASCII error grammar'
    }
    $hex=$Matches[4]
    if(($hex.Length % 2) -ne 0 -or $hex.Length -gt 192){throw 'Late target event message exceeds the fixed 96-byte bound'}
    $message=[Text.Encoding]::UTF8.GetString([Convert]::FromHexString($hex))
    $bytes=[Text.Encoding]::UTF8.GetBytes($message)
    if([Convert]::ToHexString($bytes) -cne $hex){throw 'Late event message is not canonical lossless UTF-8'}
    if($Matches[1] -cne $Expected.target -or $Matches[2] -cne $Expected.domain -or
        $Matches[3] -cne $Expected.code){throw 'Late event phase/domain/code differs from the fixed case table'}
}

function Test-LateErrorGrammarParser([hashtable]$CaseTable,[string[]]$CaseOrder) {
    if($CaseOrder.Count -ne 9 -or @($CaseOrder | Select-Object -Unique).Count -ne 9){
        throw 'Parser regression requires the fixed nine late cases'
    }
    $positive=0;$negative=0
    foreach($caseName in $CaseOrder){
        if(-not $CaseTable.ContainsKey($caseName)){throw 'Parser regression case is missing'}
        $want=$CaseTable[$caseName]
        $eventPrefix=$want.target+','+$want.domain+','+$want.code+','
        $entry=$eventPrefix+'74657374'
        Assert-LateErrorGrammar ('v1|1|'+$entry) $want
        $positive++
        $badValues=@(
            'v1|0|',
            ('v1|2|'+$entry+';'+$entry),
            ('v1|1|unexpected_phase,'+$want.domain+','+$want.code+',74657374'),
            ('v1|1|'+$eventPrefix+'FF'),
            ('v1|1|'+$eventPrefix+'A'),
            ('v1|1|'+$eventPrefix+('41'*97)),
            ('v1|1|'+$eventPrefix+'7a')
        )
        foreach($badValue in $badValues){
            $rejected=$false
            try { Assert-LateErrorGrammar $badValue $want } catch { $rejected=$true }
            if(-not $rejected){throw "Parser regression admitted an invalid event for $caseName"}
            $negative++
        }
    }
    if($positive -ne 9 -or $negative -ne 63){throw 'Parser regression did not execute every assertion'}
    return [pscustomobject][ordered]@{
        kind='parser_only';status='passed';positive_cases=$positive;negative_cases=$negative
        source=$env:GITHUB_SHA;run=$env:GITHUB_RUN_ID
    }
}

function Assert-LateUtf8Pair([string]$Frame,[string]$Stem) {
    $countText=WitnessField $Frame ($Stem+'_bytes')
    $hex=WitnessField $Frame ($Stem+'_hex')
    if($countText -notmatch '^(0|[1-9][0-9]{0,3})$' -or
        $hex -cnotmatch '^(?:[0-9A-F]{2})*$' -or
        [int]$countText -ne ($hex.Length/2)){
        throw "Measured UTF-8 length/hex mismatch: $Stem"
    }
}

function Assert-LateControlDetail([string]$Frame,[string]$CaseName,[string]$Nonce,
    [string]$Source,[string]$Run,[string]$Unit,[string]$ParentPid,[string]$ParentCreation,
    [string]$FixtureId,[string]$UserSid,[string]$NormalResult,[hashtable]$Expected) {
    $fields=Get-LateDetailRequiredFields
    if($fields.Count -ne 139){throw 'Internal late-detail parser field set is not exactly 139 fields'}
    WitnessExactFields $Frame $fields
    foreach($name in @('case','nonce','source','run','selected_unit','parent_pid','parent_creation','registry_fixture_id')){
        $want=$null
        if($name -ceq 'case'){$want=$CaseName}
        elseif($name -ceq 'nonce'){$want=$Nonce}
        elseif($name -ceq 'source'){$want=$Source}
        elseif($name -ceq 'run'){$want=$Run}
        elseif($name -ceq 'selected_unit'){$want=$Unit}
        elseif($name -ceq 'parent_pid'){$want=$ParentPid}
        elseif($name -ceq 'parent_creation'){$want=$ParentCreation}
        elseif($name -ceq 'registry_fixture_id'){$want=$FixtureId}
        if((WitnessField $Frame $name) -cne $want){throw "Late detail binding mismatch: $name"}
    }
    foreach($name in @('setup_verified','target_reached','partial_verified')){
        if((WitnessField $Frame $name) -cne 'true'){throw "Late case did not prove $name"}
    }
    if((WitnessField $Frame 'registry_root_state') -cne '-'){
        throw 'Late cleanup did not prove the nonce registry root absent'
    }
    foreach($stem in @('registry_key_leaf_utf8','registry_native_key_name_utf8',
        'registry_software_parent_native_name_utf8','registry_software_hkey_before_native_name_utf8',
        'registry_software_hkey_after_native_name_utf8','foreign_canary_name_utf8')){
        Assert-LateUtf8Pair $Frame $stem
    }
    foreach($field in @('registry_key_descriptor_sha256','registry_predelete_machine_view_sha256',
        'registry_predelete_user_view_sha256','control_directory_descriptor_sha256',
        'foreign_canary_expected_content_sha256','foreign_canary_observed_content_sha256',
        'foreign_canary_expected_descriptor_sha256','foreign_canary_observed_descriptor_sha256')){
        if((WitnessField $Frame $field) -cnotmatch '^[0-9A-F]{64}$'){throw "Late measured digest is malformed: $field"}
    }
    $leafBytes=[Convert]::FromHexString((WitnessField $Frame 'registry_key_leaf_utf8_hex'))
    $fullNameBytes=[Convert]::FromHexString((WitnessField $Frame 'registry_native_key_name_utf8_hex'))
    $parentNameBytes=[Convert]::FromHexString((WitnessField $Frame 'registry_software_parent_native_name_utf8_hex'))
    $beforeNameBytes=[Convert]::FromHexString((WitnessField $Frame 'registry_software_hkey_before_native_name_utf8_hex'))
    $afterNameBytes=[Convert]::FromHexString((WitnessField $Frame 'registry_software_hkey_after_native_name_utf8_hex'))
    $utf8=[Text.UTF8Encoding]::new($false,$true)
    $leafName=$utf8.GetString($leafBytes)
    $fullName=$utf8.GetString($fullNameBytes)
    $parentName=$utf8.GetString($parentNameBytes)
    $expectedLeaf='ORBIT_WITNESS_'+$Nonce
    $expectedSoftwareName='\REGISTRY\USER\'+$UserSid+'\Software'
    $expectedFixtureId=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($expectedLeaf)))
    $normalFixtureId=WitnessField $NormalResult 'fixture_id'
    if($leafName -cne $expectedLeaf -or
        [Convert]::ToHexString($leafBytes) -cne [Convert]::ToHexString([Text.Encoding]::UTF8.GetBytes($expectedLeaf)) -or
        $FixtureId -cne $normalFixtureId -or $FixtureId -cne $expectedFixtureId -or
        (WitnessField $Frame 'registry_fixture_id') -cne $expectedFixtureId -or
        $parentName -ine $expectedSoftwareName -or
        $fullName -ine ($expectedSoftwareName+'\'+$expectedLeaf) -or
        [Convert]::ToHexString($beforeNameBytes) -cne [Convert]::ToHexString($parentNameBytes) -or
        [Convert]::ToHexString($afterNameBytes) -cne [Convert]::ToHexString($parentNameBytes) -or
        (WitnessField $Frame 'registry_parent_hkey_provenance') -cne 'software_hkey_relative_probe_succeeded' -or
        (WitnessField $Frame 'registry_software_hkey_before_result') -cne 'native_query_success' -or
        (WitnessField $Frame 'registry_software_hkey_after_result') -cne 'native_query_success' -or
        (WitnessField $Frame 'registry_preclose_absence_result') -cne '2' -or
        (WitnessField $Frame 'registry_software_hkey_handle_value') -cnotmatch '^[1-9A-F][0-9A-F]{0,15}$'){
        throw 'Late fixture/Software HKEY measured-name or preclose-absence binding failed'
    }
    if((WitnessField $Frame 'target_count') -cne '1' -or
        (WitnessField $Frame 'unexpected_error_count') -cne '0' -or
        (WitnessField $Frame 'fault_phase') -cne $Expected.fault -or
        (WitnessField $Frame 'target_refusal_phase') -cne $Expected.target){
        throw 'Late detail phase/count binding mismatch'
    }
    Assert-LateErrorGrammar (WitnessField $Frame 'errors') $Expected
    foreach($fieldPair in @(
        @('image_disposition_native_result','image_native'),
        @('image_disposition_reported_result','image_reported'),
        @('directory_disposition_native_result','directory_native'),
        @('directory_disposition_reported_result','directory_reported'),
        @('sdk_native_hresult','sdk_native'),
        @('sdk_reported_hresult','sdk_reported'),
        @('profile_absence_probe','profile_probe')
    )){
        if((WitnessField $Frame $fieldPair[0]) -cne $Expected[$fieldPair[1]]){
            throw "Late native/reported action tuple mismatch: $($fieldPair[0])"
        }
    }
    if((WitnessField $Frame 'native_executed') -cne $(if($Expected.native_executed -ceq '1'){'true'}else{'false'}) -or
        (WitnessField $Frame 'injected') -cne $Expected.injected -or
        (WitnessField $Frame 'native_domain') -cne $Expected.native_domain -or
        (WitnessField $Frame 'native_result') -cne $Expected.native_result -or
        (WitnessField $Frame 'reported_result') -cne $Expected.reported_result){
        throw 'Late fault execution/injection flags do not match the fixed case row'
    }
    if($Expected.native_executed -ceq '0' -and (WitnessField $Frame 'native_result') -cne 'not_called'){
        throw 'Skipped native operation must report native_result=not_called'
    }
    $objectStateKeys=@{image='i';helper_directory='d';profile_entry='p'}
    foreach($object in @('image','helper_directory','profile_entry')){
        if((WitnessField $Frame ($object+'_state')) -cne $Expected[$objectStateKeys[$object]]){
            throw "Late observed state differs from fixed table: $object"
        }
        $state=WitnessField $Frame ($object+'_state')
        $expectedKind=if($object -ceq 'image'){'regular_file'}else{'directory'}
        if((WitnessField $Frame ($object+'_expected_volume_id')) -cnotmatch '^[0-9A-F]{16}$' -or
            (WitnessField $Frame ($object+'_expected_file_id')) -cnotmatch '^[0-9A-F]{32}$' -or
            (WitnessField $Frame ($object+'_held_parent_volume_id')) -cnotmatch '^[0-9A-F]{16}$' -or
            (WitnessField $Frame ($object+'_held_parent_file_id')) -cnotmatch '^[0-9A-F]{32}$'){
            throw "Late expected/parent full identity is malformed: $object"
        }
        foreach($suffix in @('observed_volume_id','observed_file_id','observed_kind',
            'observed_content_sha256','observed_descriptor_sha256')){
            $value=WitnessField $Frame ($object+'_'+$suffix)
            if($state -ceq '-'){
                if($value -cne 'not_observed_absent'){throw "Absent $object contains an asserted observed fact"}
            } elseif([string]::IsNullOrEmpty($value) -or $value -ceq 'not_observed_absent'){
                throw "Present $object lacks an observed fact"
            }
        }
        if($state -ceq '+'){
            if((WitnessField $Frame ($object+'_observed_volume_id')) -cne (WitnessField $Frame ($object+'_expected_volume_id')) -or
                (WitnessField $Frame ($object+'_observed_file_id')) -cne (WitnessField $Frame ($object+'_expected_file_id')) -or
                (WitnessField $Frame ($object+'_observed_kind')) -cne $expectedKind -or
                (WitnessField $Frame ($object+'_relative_probe_result')) -cne 'relative_success' -or
                (WitnessField $Frame ($object+'_observed_content_sha256')) -cnotmatch '^[0-9A-F]{64}$' -or
                (WitnessField $Frame ($object+'_observed_descriptor_sha256')) -cnotmatch '^[0-9A-F]{64}$'){
                throw "Present $object full ID/content/DACL observation differs from its captured preimage"
            }
        } elseif((WitnessField $Frame ($object+'_relative_probe_result')) -cne 'relative_not_found'){
            throw "Absent $object lacks a native relative not-found result"
        }
        $inventoryCountText=WitnessField $Frame ($object+'_inventory_count')
        $inventoryHash=WitnessField $Frame ($object+'_inventory_sha256')
        if($object -in @('image','profile_entry')){
            if($inventoryCountText -cne 'not_applicable_fixed_case' -or
                $inventoryHash -cne 'not_applicable_fixed_case'){
                throw "Fixed inventory sentinels changed for $object"
            }
        } elseif($state -ceq '-') {
            if($inventoryCountText -cne 'not_observed_absent' -or
                $inventoryHash -cne 'not_observed_absent'){
                throw 'Absent helper directory must use fixed not-observed inventory sentinels'
            }
        }
        if($object -ceq 'helper_directory' -and $state -ceq '+'){
            if($inventoryCountText -cnotmatch '^(0|[1-9][0-9]*)$' -or
                $inventoryCountText -cne $(if($CaseName -ceq 'directory_disposition_noeffect'){'0'}else{'1'}) -or
                $inventoryHash -cnotmatch '^[0-9A-F]{64}$' -or
                $inventoryHash -cne (WitnessField $Frame 'helper_directory_observed_content_sha256')){
                throw 'Helper-directory inventory differs from the exact partial residue'
            }
        }
    }
    $normalImageId=WitnessField $NormalResult 'image_id'
    $normalImageMatch=[regex]::Match($normalImageId,'^([0-9A-F]{16}):([0-9A-F]{32})$')
    if(-not $normalImageMatch.Success){throw 'Shared normal child image ID is not canonical uppercase full identity'}
    $imageExpectedVolume=WitnessField $Frame 'image_expected_volume_id'
    $imageExpectedFile=WitnessField $Frame 'image_expected_file_id'
    $imageParentVolume=WitnessField $Frame 'image_held_parent_volume_id'
    $imageParentFile=WitnessField $Frame 'image_held_parent_file_id'
    $helperExpectedVolume=WitnessField $Frame 'helper_directory_expected_volume_id'
    $helperExpectedFile=WitnessField $Frame 'helper_directory_expected_file_id'
    $helperParentVolume=WitnessField $Frame 'helper_directory_held_parent_volume_id'
    $helperParentFile=WitnessField $Frame 'helper_directory_held_parent_file_id'
    $profileExpectedVolume=WitnessField $Frame 'profile_entry_expected_volume_id'
    $profileParentVolume=WitnessField $Frame 'profile_entry_held_parent_volume_id'
    if($imageExpectedVolume -cne $normalImageMatch.Groups[1].Value -or
        $imageExpectedFile -cne $normalImageMatch.Groups[2].Value -or
        $imageParentVolume -cne $helperExpectedVolume -or $imageParentFile -cne $helperExpectedFile -or
        $profileExpectedVolume -cne $profileParentVolume){
        throw 'Late filesystem identities do not bind to the shared normal image and held parent hierarchy'
    }
    if((WitnessField $Frame 'image_state') -ceq '+' -and
        (WitnessField $Frame 'image_observed_content_sha256') -cne (WitnessField $NormalResult 'image_sha256')){
        throw 'Present late image content hash differs from the shared normal child image hash'
    }
    foreach($field in @('control_directory_volume_id','foreign_canary_expected_volume_id','foreign_canary_observed_volume_id')){
        if((WitnessField $Frame $field) -cnotmatch '^[0-9A-F]{16}$'){throw "Late canary volume ID malformed: $field"}
    }
    foreach($field in @('control_directory_file_id','foreign_canary_expected_file_id','foreign_canary_observed_file_id')){
        if((WitnessField $Frame $field) -cnotmatch '^[0-9A-F]{32}$'){throw "Late canary file ID malformed: $field"}
    }
    $expectedForeignName='ORBIT-FOREIGN-'+$Nonce.Substring(0,8)
    $foreignNameBytes=[Convert]::FromHexString((WitnessField $Frame 'foreign_canary_name_utf8_hex'))
    $foreignName=$utf8.GetString($foreignNameBytes)
    $fixedCanaryPayloadHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes('ORBIT-LATE-CLEANUP-CANARY-V1')))
    if($foreignName -cne $expectedForeignName -or
        [Convert]::ToHexString($foreignNameBytes) -cne [Convert]::ToHexString([Text.Encoding]::UTF8.GetBytes($expectedForeignName)) -or
        (WitnessField $Frame 'foreign_canary_expected_content_sha256') -cne $fixedCanaryPayloadHash -or
        (WitnessField $Frame 'control_directory_volume_id') -cne (WitnessField $Frame 'foreign_canary_expected_volume_id') -or
        (WitnessField $Frame 'foreign_canary_expected_volume_id') -cne (WitnessField $Frame 'foreign_canary_observed_volume_id') -or
        (WitnessField $Frame 'foreign_canary_expected_file_id') -cne (WitnessField $Frame 'foreign_canary_observed_file_id') -or
        (WitnessField $Frame 'foreign_canary_expected_content_sha256') -cne (WitnessField $Frame 'foreign_canary_observed_content_sha256') -or
        (WitnessField $Frame 'foreign_canary_expected_descriptor_sha256') -cne (WitnessField $Frame 'foreign_canary_observed_descriptor_sha256') -or
        (WitnessField $Frame 'foreign_canary_setup_result') -cne 'created_and_verified_on_ntfs' -or
        (WitnessField $Frame 'foreign_canary_preimage_matches') -cne 'true' -or
        (WitnessField $Frame 'foreign_canary_postimage_matches') -cne 'true'){
        throw 'External NTFS canary full identity/content/DACL did not match its captured preimage'
    }
    foreach($pair in @(@('image_disposition_executed','di'),@('directory_disposition_executed','dd'),@('sdk_executed','sdk'))){
        if((WitnessField $Frame $pair[0]) -cne $(if($Expected[$pair[1]] -ceq '1'){'true'}else{'false'})){
            throw "Late actual-call flag mismatch: $($pair[0])"
        }
    }
    foreach($owner in @('helper_image_reader','held_reader_blocker','image_delete_handle',
        'helper_directory_keeper','profile_ac_anchor','profile_entry_anchor','packages_observer',
        'software_registry_parent_hkey','registry_fixture_hkey','normal_job_fence','cancel_job_fence')){
        $ownerState=WitnessField $Frame ($owner+'_state')
        $nativeClose=WitnessField $Frame ($owner+'_close_native_result')
        $reportedClose=WitnessField $Frame ($owner+'_close_reported_result')
        if([string]::IsNullOrEmpty($ownerState) -or [string]::IsNullOrEmpty($nativeClose) -or
            [string]::IsNullOrEmpty($reportedClose)) {throw "Missing physical owner outcome: $owner"}
        $expectedState=if($owner -ceq 'held_reader_blocker'){
            if($CaseName -ceq 'held_reader_sharing'){'opened_retained_then_closed'}else{'not_opened'}
        } elseif($owner -ceq 'image_delete_handle' -and $CaseName -in @('held_reader_sharing','reader_close_error')){
            'not_opened'
        } else {'closed'}
        $expectedNativeClose=if($expectedState -ceq 'not_opened'){'not_opened'}else{'success'}
        $expectedReportedClose=if($expectedState -ceq 'not_opened'){'not_opened'}else{'not_injected'}
        if($CaseName -ceq 'reader_close_error' -and $owner -ceq 'helper_image_reader'){$expectedReportedClose='injected_close_error'}
        if($CaseName -ceq 'profile_anchor_close_error' -and $owner -ceq 'profile_ac_anchor'){$expectedReportedClose='injected_close_error'}
        if($CaseName -ceq 'observation_parent_close_error' -and $owner -ceq 'packages_observer'){$expectedReportedClose='injected_close_error'}
        if($CaseName -ceq 'job_fence_close_error' -and $owner -ceq 'normal_job_fence'){$expectedReportedClose='injected_close_error'}
        if($ownerState -cne $expectedState -or $nativeClose -cne $expectedNativeClose -or
            $reportedClose -cne $expectedReportedClose){throw "Physical owner outcome differs from fixed case table: $owner"}
        if($nativeClose -ceq 'not_opened' -and
            ($ownerState -cne 'not_opened' -or $reportedClose -cne 'not_opened')){
            throw "Unopened owner has fabricated close state: $owner"
        }
    }
    if($CaseName -ceq 'held_reader_sharing'){
        if((WitnessField $Frame 'held_reader_blocker_open_native_result') -cne 'success' -or
            (WitnessField $Frame 'held_reader_blocker_state') -cne 'opened_retained_then_closed'){
            throw 'Held-reader setup/close was not physically accounted'
        }
    } elseif((WitnessField $Frame 'held_reader_blocker_open_native_result') -cne 'not_opened' -or
        (WitnessField $Frame 'held_reader_blocker_state') -cne 'not_opened'){
        throw 'Unexpected held-reader blocker was opened'
    }
    if([Text.Encoding]::ASCII.GetByteCount($Frame) -gt 8192){throw 'Late detail frame exceeds existing 8192-byte cap'}
}

function Assert-LateFinalization([string]$Frame,[string]$CaseName,[hashtable]$Expected) {
    $fields=@('status','control','registry_absent','image_absent','directory_absent',
        'profile_absent','image_disposition_executed','directory_disposition_executed',
        'sdk_executed','normal_job_zero','cancel_job_zero','cleanup_errors')
    WitnessExactFields $Frame $fields
    if((WitnessField $Frame 'status') -cne 'partial' -or
        (WitnessField $Frame 'control') -cne $CaseName -or
        (WitnessField $Frame 'registry_absent') -cne 'true' -or
        (WitnessField $Frame 'image_absent') -cne $(if($Expected.i -ceq '-'){'true'}else{'false'}) -or
        (WitnessField $Frame 'directory_absent') -cne $(if($Expected.d -ceq '-'){'true'}else{'false'}) -or
        (WitnessField $Frame 'profile_absent') -cne $(if($Expected.p -ceq '-'){'true'}else{'false'}) -or
        (WitnessField $Frame 'image_disposition_executed') -cne $(if($Expected.di -ceq '1'){'true'}else{'false'}) -or
        (WitnessField $Frame 'directory_disposition_executed') -cne $(if($Expected.dd -ceq '1'){'true'}else{'false'}) -or
        (WitnessField $Frame 'sdk_executed') -cne $(if($Expected.sdk -ceq '1'){'true'}else{'false'}) -or
        (WitnessField $Frame 'normal_job_zero') -cne 'true' -or
        (WitnessField $Frame 'cancel_job_zero') -cne 'true' -or
        (WitnessField $Frame 'cleanup_errors') -cne '1'){
        throw "$CaseName finalization does not match its exact partial residue and actual-action vector"
    }
}

        function InvokeCleanupControl([string]$controlName) {
            $controlMode=Get-CleanupControlMode $controlName
            $caseName='process::windows::registry_witness_tests::registry_witness_cleanup_control_'+$controlName
            $controlDir=Join-Path $EvidenceDir 'registry-cleanup-controls'
            $controlLog=Join-Path $controlDir ($controlName+'.log')
            $controlRecordsPath=Join-Path $controlDir ($controlName+'.records.txt')
            $controlMetadataPath=Join-Path $controlDir ($controlName+'.json')
            $caseContext=[ordered]@{
                case=$controlName;source=$env:GITHUB_SHA;run=$env:GITHUB_RUN_ID
                selected_unit=$caseName;nonce=$null;user_sid=$parentIdentity.user_sid
                marker_names=@();marker_hashes=@();attempted=$true
                selected_test_executed=$false;selected_test_passed=$false
                transcript_verified=$false;native_control_verified=$false
                target_reached=$false;partial_verified=$false;primary_probes=0;status='initializing'
                log_path=(Split-Path -Leaf $controlLog)
                records_path=(Split-Path -Leaf $controlRecordsPath)
                metadata_path=(Split-Path -Leaf $controlMetadataPath)
                environment_restore_errors=@()
            }
            $savedEnvironment=[ordered]@{}
            $processEnvironment=[Environment]::GetEnvironmentVariables(
                [EnvironmentVariableTarget]::Process)
            foreach($environmentName in @(
                'ORBIT_REGISTRY_WITNESS_NONCE','ORBIT_REGISTRY_WITNESS_MACHINE_MARKER',
                'ORBIT_REGISTRY_WITNESS_USER_MARKER','ORBIT_REGISTRY_WITNESS_MACHINE_HASH',
                'ORBIT_REGISTRY_WITNESS_USER_HASH'
            )){
                $savedEnvironment[$environmentName]=[ordered]@{
                    present=$processEnvironment.Contains($environmentName)
                    value=[Environment]::GetEnvironmentVariable(
                        $environmentName,[EnvironmentVariableTarget]::Process)
                }
            }
            $caseResult=$null
            $caseFailure=$null
            try {
                New-Item -ItemType Directory -Force $controlDir | Out-Null
                $controlNonce=[guid]::NewGuid().ToString('N')
                $controlMachineName='ORBIT_WITNESS_MACHINE_'+$controlNonce
                $controlUserName='ORBIT_WITNESS_USER_'+$controlNonce
                $controlMachineValue=[guid]::NewGuid().ToString('N')
                $controlUserValue=[guid]::NewGuid().ToString('N')
                $controlMachineHash=[Convert]::ToHexString(
                    [Security.Cryptography.SHA256]::HashData(
                        [Text.Encoding]::UTF8.GetBytes($controlMachineValue)))
                $controlUserHash=[Convert]::ToHexString(
                    [Security.Cryptography.SHA256]::HashData(
                        [Text.Encoding]::UTF8.GetBytes($controlUserValue)))
                $caseContext.nonce=$controlNonce
                $caseContext.marker_names=@($controlMachineName,$controlUserName)
                $caseContext.marker_hashes=@($controlMachineHash,$controlUserHash)
                $caseContext.status='fixture_setup'
                AssertMarkerAbsent $machine $controlMachineName
                AssertMarkerAbsent $user $controlUserName
                foreach($row in @(
                    @{key=$machine;name=$controlMachineName;value=$controlMachineValue;target='machine'},
                    @{key=$user;name=$controlUserName;value=$controlUserValue;target='user'}
                )){
                    AssertMarkerAbsent $row.key $row.name
                    [void]$created.Add($row)
                    $row.key.SetValue($row.name,$row.value,[Microsoft.Win32.RegistryValueKind]::String)
                    if($row.key.GetValueKind($row.name) -ne [Microsoft.Win32.RegistryValueKind]::String -or
                        $row.key.GetValue($row.name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) -cne $row.value){
                        throw "Fresh $controlName fake marker did not verify"
                    }
                }
                [Environment]::SetEnvironmentVariable('ORBIT_REGISTRY_WITNESS_NONCE',$controlNonce,
                    [EnvironmentVariableTarget]::Process)
                [Environment]::SetEnvironmentVariable('ORBIT_REGISTRY_WITNESS_MACHINE_MARKER',$controlMachineName,
                    [EnvironmentVariableTarget]::Process)
                [Environment]::SetEnvironmentVariable('ORBIT_REGISTRY_WITNESS_USER_MARKER',$controlUserName,
                    [EnvironmentVariableTarget]::Process)
                [Environment]::SetEnvironmentVariable('ORBIT_REGISTRY_WITNESS_MACHINE_HASH',$controlMachineHash,
                    [EnvironmentVariableTarget]::Process)
                [Environment]::SetEnvironmentVariable('ORBIT_REGISTRY_WITNESS_USER_HASH',$controlUserHash,
                    [EnvironmentVariableTarget]::Process)
                $caseContext.status='native_test_started'
            cargo +1.99.0 test --locked -p orbit-platform --features registry-witness --lib $caseName -- --exact --test-threads=1 --nocapture 2>&1 |
                Tee-Object -FilePath $controlLog | Out-Host
            $controlCode=$LASTEXITCODE
            $controlReport=Get-Content $controlLog -Raw
            $controlFrames=[Collections.Generic.List[string]]::new()
            $frameRanges=[Collections.Generic.List[object]]::new()
            $controlCursor=0
            while(($frameOffset=$controlReport.IndexOf($frameStart,$controlCursor,[StringComparison]::Ordinal)) -ge 0){
                $lengthStart=$frameOffset+$frameStart.Length
                $colon=$controlReport.IndexOf(':',$lengthStart)
                if($colon -lt 0 -or $colon-$lengthStart -lt 1 -or $colon-$lengthStart -gt 4){throw "$controlName malformed frame length"}
                $lengthText=$controlReport.Substring($lengthStart,$colon-$lengthStart)
                if($lengthText -notmatch '^\d{1,4}$'){throw "$controlName non-numeric frame length"}
                $length=[int]$lengthText
                if($length -gt 8192){throw "$controlName oversized frame"}
                $payloadStart=$colon+1;$payloadEnd=$payloadStart+$length
                if($payloadEnd -ge $controlReport.Length -or [int][char]$controlReport[$payloadEnd] -ne 0x1f){
                    throw "$controlName truncated frame"
                }
                $payload=$controlReport.Substring($payloadStart,$length)
                if($payload -match '[^\x20-\x7e]' -or
                    $payload -notmatch '^(registry_witness_probe|registry_witness_parent_binding|registry_witness_helper_directory_access|registry_witness_helper_directory_descriptor|registry_witness_child_result|registry_witness_diagnostic|registry_witness_child_admission|registry_witness_child_complete|registry_witness_status|registry_witness_finalization|registry_witness_incomplete|registry_witness_setup_cleanup|registry_witness_control|registry_witness_control_detail|registry_witness_control_late_detail)(?: |$)'){
                    throw "$controlName unknown or malformed framed record"
                }
                $controlFrames.Add($payload)
                $frameRanges.Add([pscustomobject]@{start=$frameOffset;length=$payloadEnd+1-$frameOffset})
                $controlCursor=$payloadEnd+1
            }
            $harnessView=$controlReport
            foreach($range in $frameRanges | Sort-Object start -Descending){
                $harnessView=$harnessView.Remove($range.start,$range.length)
            }
            $controlFrames | Out-File $controlRecordsPath -Encoding ascii
            $exactCaseLine='(?m)^test '+[regex]::Escape($caseName)+' (?:\.\.\. ok|\.\.\. FAILED)\r?$'
            $caseLines=[regex]::Matches($harnessView,$exactCaseLine)
            $successLine='(?m)^test '+[regex]::Escape($caseName)+' \.\.\. ok\r?$'
            $failedLine='(?m)^test '+[regex]::Escape($caseName)+' \.\.\. FAILED\r?$'
            $successSummary='(?m)^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s\r?$'
            $failedSummary='(?m)^test result: FAILED\. 0 passed; 1 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s\r?$'
            $runningOne=[regex]::Matches($harnessView,'(?m)^running 1 test\r?$').Count -eq 1
            $summarySuccess=[regex]::Matches($harnessView,$successSummary).Count -eq 1
            $summaryFailure=[regex]::Matches($harnessView,$failedSummary).Count -eq 1
            $caseExecuted=$runningOne -and $caseLines.Count -eq 1 -and ($summarySuccess -or $summaryFailure)
            $casePassed=$caseExecuted -and
                [regex]::IsMatch($harnessView,$successLine) -and $summarySuccess
            $caseContext.selected_test_executed=$caseExecuted
            $caseContext.selected_test_passed=$casePassed
            $caseContext.harness_running_one_test=$runningOne
            $caseContext.harness_summary_success=$summarySuccess
            $caseContext.harness_summary_failure=$summaryFailure
            $caseContext.status=if($casePassed){'selected_test_passed'}elseif($caseExecuted){'selected_test_failed'}else{'selected_test_not_proven'}
            if(-not $caseExecuted){throw "$controlName did not prove execution of exactly one selected Rust unit"}
            if($controlCode -ne 0 -or -not $casePassed){
                throw "$controlName selected Rust unit did not pass (exit $controlCode)"
            }
            $controlActual=[Collections.Generic.List[string]]::new()
            $controlProbes=@{}
            foreach($frame in $controlFrames){
                if($frame.StartsWith('registry_witness_probe ')){
                    if($frame -notmatch '^registry_witness_probe id=([^ ]+) .+$'){throw "$controlName malformed probe"}
                    $id=$Matches[1]
                    if($controlProbes.ContainsKey($id)){throw "$controlName duplicate probe: $id"}
                    if(-not $expected.Contains($id)){throw "$controlName unexpected probe: $id"}
                    $controlActual.Add($id);$controlProbes[$id]=$frame
                }
            }
            $controlMissing=@($expected | Where-Object {-not $controlProbes.ContainsKey($_)})
            if($controlActual.Count -ne 69 -or $controlMissing.Count -ne 1 -or
                $controlMissing[0] -cne 'lifetime/cleanup_absent'){
                throw "$controlName must preserve the exact 69 non-cleanup probes; got $($controlActual.Count), missing $($controlMissing -join ',')"
            }
            if(-not $controlProbes.ContainsKey('lifetime/normal_job_zero') -or
                (WitnessField $controlProbes['lifetime/normal_job_zero'] 'observed') -cne 'true' -or
                (WitnessField $controlProbes['lifetime/normal_job_zero'] 'active_processes') -cne '0' -or
                -not $controlProbes.ContainsKey('lifetime/cancel_ready_mapped') -or
                -not $controlProbes.ContainsKey('lifetime/cancel_job_zero') -or
                (WitnessField $controlProbes['lifetime/cancel_job_zero'] 'active_processes') -cne '0'){
                throw "$controlName did not prove both real helper roles reached Job zero"
            }
            $controlProbes=ValidateWitnessTranscript -InputFrames $controlFrames -RunNonce $controlNonce -ExitCode $controlCode -Mode $controlMode -ControlName $controlName -ExpectedIds $expected -ActualIds $controlActual -ExpectedMachineHash $controlMachineHash -ExpectedUserHash $controlUserHash
            $controlBindings=@($controlFrames | Where-Object {$_ -match '^registry_witness_parent_binding '})
            $normalResults=@($controlFrames | Where-Object {$_ -match '^registry_witness_child_result role=normal '})
            if($controlBindings.Count -ne 1 -or $normalResults.Count -ne 1){
                throw "$controlName strict transcript omitted parent or normal-helper identity binding"
            }
            $binding=$controlBindings[0]
            $normalResult=$normalResults[0]
            $ready=$controlProbes['lifetime/cancel_ready_mapped']
            $cancelJob=$controlProbes['lifetime/cancel_job_zero']
            if($controlMode -ceq 'retained'){
            $controlRecords=@($controlFrames | Where-Object {$_ -match '^registry_witness_control(?: |$)'})
            if($controlRecords.Count -ne 1){throw "$controlName did not emit exactly one targeted control receipt"}
            $controlRecord=$controlRecords[0]
            $controlFields=@('case','nonce','parent_pid','parent_creation','reached','rejection','jobs_zero','known_views_unchanged',
                'view_preimages_unchanged','private_canary_value_sha256','private_canary_descriptor_sha256',
                'private_canary_unchanged','parent_machine_value_sha256','parent_user_value_sha256',
                'parent_machine_descriptor_sha256','parent_user_descriptor_sha256','parent_canary_unchanged',
                'registry_root_retained','image_profile_retained','image_id','image_sha256','fixture_id',
                'disposition_attempted','sdk_called')
            WitnessExactFields $controlRecord $controlFields
            $expectedRejections=@{
                wrong_image_hash='helper_image_hash_differs';unknown_registry_key='private_fixture_inventory_changed'
                wrong_image_id='helper_image_identity_differs';wrong_directory_id='helper_directory_identity_changed'
                wrong_profile_id='profile_entry_identity_changed';changed_image_dacl='helper_image_dacl_changed'
                unknown_registry_value='private_fixture_inventory_changed';unknown_helper_entry='helper_directory_inventory_changed'
                unknown_profile_entry='profile_inventory_changed';profile_enumeration_limit='profile_entry_bound_exceeded'
                image_leaf_swap='helper_image_leaf_swap_refused';directory_swap='helper_directory_swap_refused'
                image_hardlink='helper_image_hardlink_refused';missing_job_fence='cleanup_job_fence_missing'
                live_nonzero_job='cancel_job_live_nonzero_refused';job_query_error='cleanup_job_query_error_injected'
            }
            $expectedRejection=$expectedRejections[$controlName]
            $controlDetailFrames=@($controlFrames | Where-Object {$_ -match '^registry_witness_control_detail(?: |$)'})
            if($controlDetailFrames.Count -ne 1){throw "$controlName did not emit exactly one control detail record"}
            $controlDetail=$controlDetailFrames[0]
            WitnessExactFields $controlDetail @('case','setup_verified','target_reached','final_verified','state',
                'native_status','active_count','object_name','object_id','content_sha256','descriptor_sha256',
                'expected_id','observed_id','inventory_count','inventory_sha256')
            if((WitnessField $controlDetail 'case') -cne $controlName -or
                (WitnessField $controlDetail 'setup_verified') -cne 'true' -or
                (WitnessField $controlDetail 'target_reached') -cne 'true' -or
                (WitnessField $controlDetail 'final_verified') -cne 'true'){
                throw "$controlName did not separate and prove setup, target refusal, and retained postchecks"
            }
            $detailState=WitnessField $controlDetail 'state'
            $detailObjectId=WitnessField $controlDetail 'object_id'
            $detailExpected=WitnessField $controlDetail 'expected_id'
            $detailObserved=WitnessField $controlDetail 'observed_id'
            $detailContent=WitnessField $controlDetail 'content_sha256'
            $detailDescriptor=WitnessField $controlDetail 'descriptor_sha256'
            $detailNativeStatus=WitnessField $controlDetail 'native_status'
            $fullFileId='^[0-9A-Fa-f]{16}:[0-9A-Fa-f]{32}$'
            $sha256='^[0-9A-Fa-f]{64}$'
            switch -CaseSensitive ($controlName) {
                {$_ -in @('wrong_image_hash')} {
                    if($detailState -cne 'expected_hash_corrupted' -or
                        $detailObjectId -notmatch $fullFileId -or
                        $detailObjectId -cne (WitnessField $controlRecord 'image_id') -or
                        $detailContent -cne (WitnessField $controlRecord 'image_sha256') -or
                        $detailExpected -notmatch $sha256 -or $detailObserved -notmatch $sha256 -or
                        $detailExpected -ceq $detailObserved){throw 'Wrong-image-hash control did not bind a distinct expected hash to the held image'}
                }
                {$_ -in @('wrong_image_id','wrong_directory_id','wrong_profile_id')} {
                    if($detailState -cne 'expected_id_corrupted' -or $detailObjectId -notmatch $fullFileId -or
                        $detailExpected -cne $detailObjectId -or $detailObserved -notmatch $fullFileId -or
                        $detailExpected -ceq $detailObserved){throw "$controlName did not prove a distinct corrupted expected full ID"}
                    if($controlName -ceq 'wrong_image_id' -and $detailObjectId -cne (WitnessField $controlRecord 'image_id')){
                        throw 'Wrong-image-ID control did not bind the held image full ID'
                    }
                }
                {$_ -in @('changed_image_dacl')} {
                    if($detailState -cne 'package_ace_removed' -or $detailObjectId -notmatch $fullFileId -or
                        $detailExpected -notmatch $sha256 -or $detailObserved -notmatch $sha256 -or
                        $detailExpected -ceq $detailObserved -or $detailDescriptor -cne $detailObserved){
                        throw 'Changed-DACL control did not prove a real changed descriptor postimage'
                    }
                }
                {$_ -in @('unknown_registry_key','unknown_registry_value')} {
                    $expectedRegistryState=if($controlName -ceq 'unknown_registry_key'){
                        'absent_before_installed_registry_key_canary'
                    }else{'absent_before_installed_reg_sz_canary'}
                    $expectedRegistryStatus=if($controlName -ceq 'unknown_registry_key'){
                        'RegCreateKeyExW_SUCCESS'
                    }else{'RegSetValueExW_SUCCESS_REG_SZ'}
                    if($detailState -cne $expectedRegistryState -or $detailNativeStatus -cne $expectedRegistryStatus -or
                        $detailObjectId -cne 'not_applicable' -or $detailContent -notmatch $sha256 -or
                        $detailDescriptor -notmatch $sha256){throw "$controlName missing actual registry canary value and descriptor preimage"}
                }
                {$_ -in @('unknown_helper_entry','unknown_profile_entry')} {
                    if($detailState -notin @('absent_before_installed_helper_entry','absent_before_installed_profile_entry') -or
                        $detailObjectId -notmatch $fullFileId -or $detailContent -notmatch $sha256 -or
                        $detailDescriptor -notmatch $sha256){throw "$controlName missing actual file identity, content, or descriptor preimage"}
                }
                {$_ -in @('profile_enumeration_limit')} {
                    if($detailState -cne 'installed_513_bounded_empty_files' -or
                        $detailObjectId -notmatch $fullFileId -or $detailDescriptor -notmatch $sha256 -or
                        (WitnessField $controlDetail 'inventory_count') -cne '513' -or
                        (WitnessField $controlDetail 'inventory_sha256') -notmatch $sha256){
                        throw 'Profile enumeration-limit control did not prove the bounded 513-file setup'
                    }
                }
                {$_ -in @('image_leaf_swap','directory_swap')} {
                    if($detailState -ceq 'rename_prevented_by_exact_sharing_violation'){
                        $expectedRejection='namespace_rename_share_violation'
                        if($detailNativeStatus -cne 'NtStatus=0xc0000043_Win32=32' -or
                            $detailExpected -notmatch $fullFileId -or $detailObserved -cne $detailExpected){
                            throw "$controlName sharing prevention was not the exact STATUS_SHARING_VIOLATION branch"
                        }
                    } elseif($detailState -in @('held_image_renamed_and_replacement_installed','held_directory_renamed_and_replacement_installed')){
                        if($detailExpected -notmatch $fullFileId -or $detailObserved -notmatch $fullFileId -or
                            $detailExpected -ceq $detailObserved){throw "$controlName did not distinguish the original and replacement identities"}
                    } else {throw "$controlName setup neither installed the namespace change nor proved exact sharing prevention"}
                }
                {$_ -in @('image_hardlink')} {
                    if($detailState -cne 'same_volume_hardlink_installed' -or
                        $detailObjectId -notmatch $fullFileId -or $detailObjectId -cne $detailExpected -or
                        $detailObjectId -cne $detailObserved -or $detailContent -notmatch $sha256 -or
                        $detailDescriptor -notmatch $sha256 -or
                        $detailNativeStatus -notmatch '^NtSetInformationFile=STATUS_SUCCESS_source_access=0x[0-9A-Fa-f]{8}_parent_access=0x[0-9A-Fa-f]{8}$'){
                        throw 'Hardlink control did not prove successful native installation on the held reader and write-enabled AC parent'
                    }
                }
                {$_ -in @('missing_job_fence')} {
                    if($detailState -cne 'one_fence_removed_for_shared_gate' -or
                        $detailNativeStatus -cne 'STATUS_SUCCESS_both_jobs_zero_before_owner_move' -or
                        (WitnessField $controlDetail 'active_count') -cne '0,0'){
                        throw 'Missing-fence control did not prove both native Jobs were empty before owner transfer'
                    }
                }
                {$_ -in @('live_nonzero_job')} {
                    if($detailState -cne 'actual_cancel_job_singleton_refused_before_stop' -or
                        (WitnessField $controlDetail 'active_count') -cne '1'){
                        throw 'Live-job control did not prove the actual singleton refusal'
                    }
                }
                {$_ -in @('job_query_error')} {
                    if($detailState -cne 'both_native_job_queries_zero_then_shared_gate_error_injected' -or
                        $detailNativeStatus -cne 'native_query_success' -or
                        (WitnessField $controlDetail 'active_count') -cne '0,0'){
                        throw 'Job-query-error control did not distinguish native zero from the injected error'
                    }
                }
            }
            $caseContext.target_reached=(WitnessField $controlRecord 'reached') -ceq 'true'
            $caseContext.primary_probes=69
            if((WitnessField $controlRecord 'case') -cne $controlName -or
                (WitnessField $controlRecord 'nonce') -cne $controlNonce -or
                (WitnessField $controlRecord 'parent_pid') -cne (WitnessField $binding 'pid') -or
                (WitnessField $controlRecord 'parent_creation') -cne (WitnessField $binding 'creation') -or
                (WitnessField $controlRecord 'reached') -cne 'true' -or
                (WitnessField $controlRecord 'rejection') -cne $expectedRejection -or
                (WitnessField $controlRecord 'jobs_zero') -cne 'true' -or
                (WitnessField $controlRecord 'known_views_unchanged') -cne 'true' -or
                (WitnessField $controlRecord 'view_preimages_unchanged') -cne 'true' -or
                (WitnessField $controlRecord 'parent_canary_unchanged') -cne 'true' -or
                (WitnessField $controlRecord 'parent_machine_value_sha256') -cne $controlMachineHash -or
                (WitnessField $controlRecord 'parent_user_value_sha256') -cne $controlUserHash -or
                (WitnessField $controlRecord 'parent_machine_descriptor_sha256') -notmatch '^[0-9A-Fa-f]{64}$' -or
                (WitnessField $controlRecord 'parent_user_descriptor_sha256') -notmatch '^[0-9A-Fa-f]{64}$' -or
                (WitnessField $controlRecord 'registry_root_retained') -cne 'true' -or
                (WitnessField $controlRecord 'image_profile_retained') -cne 'true' -or
                (WitnessField $controlRecord 'image_id') -cne (WitnessField $normalResult 'image_id') -or
                (WitnessField $controlRecord 'image_sha256') -cne (WitnessField $normalResult 'image_sha256') -or
                (WitnessField $controlRecord 'fixture_id') -cne (WitnessField $normalResult 'fixture_id') -or
                (WitnessField $controlRecord 'disposition_attempted') -cne 'false' -or
                (WitnessField $controlRecord 'sdk_called') -cne 'false'){
                throw "$controlName target seam or retained-object receipt failed"
            }
            if($controlName -in @('unknown_registry_key','unknown_registry_value')){
                if((WitnessField $controlRecord 'private_canary_value_sha256') -notmatch '^[0-9A-Fa-f]{64}$' -or
                    (WitnessField $controlRecord 'private_canary_descriptor_sha256') -notmatch '^[0-9A-Fa-f]{64}$' -or
                    (WitnessField $controlRecord 'private_canary_unchanged') -cne 'true'){
                    throw 'Unknown-key control did not preserve its actual foreign-key value and descriptor'
                }
            } elseif((WitnessField $controlRecord 'private_canary_value_sha256') -cne 'not_applicable' -or
                (WitnessField $controlRecord 'private_canary_descriptor_sha256') -cne 'not_applicable' -or
                (WitnessField $controlRecord 'private_canary_unchanged') -cne 'false'){
                throw "$controlName contained an unexpected private-key canary"
            }
            $controlStatus=@($controlFrames | Where-Object {$_ -match '^registry_witness_status(?: |$)'})
            if($controlStatus.Count -ne 1){throw "$controlName status record is not unique"}
            WitnessExactFields $controlStatus[0] @('witness_status','run_status')
            if((WitnessField $controlStatus[0] 'witness_status') -cne 'INCOMPLETE' -or
                (WitnessField $controlStatus[0] 'run_status') -cne 'control_retained'){
                throw "$controlName did not report expected retained incomplete cleanup"
            }
            if(@($controlFrames | Where-Object {$_ -match '^registry_witness_probe id=lifetime/cleanup_absent '}).Count -ne 0){
                throw "$controlName incorrectly reported cleanup absence"
            }
            $controlFinal=@($controlFrames | Where-Object {$_ -match '^registry_witness_finalization(?: |$)'})
            if($controlFinal.Count -ne 1){throw "$controlName retained-residue finalization is not unique"}
            WitnessExactFields $controlFinal[0] @('status','control','profile_absent','sdk_called',
                'registry_fixture_retained','image_retained','helper_directory_retained',
                'normal_job_zero','cancel_job_zero','cleanup_errors')
            if((WitnessField $controlFinal[0] 'status') -cne 'retained' -or
                (WitnessField $controlFinal[0] 'control') -cne $controlName -or
                (WitnessField $controlFinal[0] 'profile_absent') -cne 'false' -or
                (WitnessField $controlFinal[0] 'sdk_called') -cne 'false' -or
                (WitnessField $controlFinal[0] 'registry_fixture_retained') -cne 'true' -or
                (WitnessField $controlFinal[0] 'image_retained') -cne 'true' -or
                (WitnessField $controlFinal[0] 'helper_directory_retained') -cne 'true' -or
                (WitnessField $controlFinal[0] 'normal_job_zero') -cne 'true' -or
                (WitnessField $controlFinal[0] 'cancel_job_zero') -cne 'true' -or
                (WitnessField $controlFinal[0] 'cleanup_errors') -cne '0'){
                throw "$controlName finalization did not prove deliberate retention"
            }
            $caseContext.transcript_verified=$true
            $caseContext.native_control_verified=$true
            $caseContext.target_reached=$true
            $caseContext.primary_probes=69
            $caseContext.status='passed_expected_refusal'
            $caseResult=[pscustomobject][ordered]@{
                case=$controlName;source=$env:GITHUB_SHA;run=$env:GITHUB_RUN_ID
                selected_unit=$caseName;nonce=$controlNonce;user_sid=$parentIdentity.user_sid
                marker_names=@($controlMachineName,$controlUserName)
                marker_hashes=@($controlMachineHash,$controlUserHash)
                attempted=$true;selected_test_executed=$caseContext.selected_test_executed
                selected_test_passed=$caseContext.selected_test_passed
                transcript_verified=$caseContext.transcript_verified
                native_control_verified=$caseContext.native_control_verified
                status='passed_expected_refusal';primary_probes=69
                target_reached=$true;partial_verified=$false;log_path=(Split-Path -Leaf $controlLog)
                records_path=(Split-Path -Leaf $controlRecordsPath)
                metadata_path=(Split-Path -Leaf $controlMetadataPath)
            }
            } else {
            $lateControlRecords=@($controlFrames | Where-Object {$_ -match '^registry_witness_control(?: |$)'})
            $earlyDetailFrames=@($controlFrames | Where-Object {$_ -match '^registry_witness_control_detail(?: |$)'})
            $lateDetailFrames=@($controlFrames | Where-Object {$_ -match '^registry_witness_control_late_detail(?: |$)'})
            if($lateControlRecords.Count -ne 0 -or $earlyDetailFrames.Count -ne 0 -or $lateDetailFrames.Count -ne 1){
                throw "$controlName late mode requires one late detail and no retained-control records"
            }
            $lateDetail=$lateDetailFrames[0]
            $sourceBinding=([string]$env:GITHUB_SHA).ToLowerInvariant()
            $fixtureId=WitnessField $normalResult 'fixture_id'
            Assert-LateControlDetail $lateDetail $controlName $controlNonce $sourceBinding $env:GITHUB_RUN_ID `
                $caseName (WitnessField $binding 'pid') (WitnessField $binding 'creation') $fixtureId `
                $parentIdentity.user_sid $normalResult $cleanupLate[$controlName]
            $controlFinal=@($controlFrames | Where-Object {$_ -match '^registry_witness_finalization(?: |$)'})
            if($controlFinal.Count -ne 1){throw "$controlName partial finalization is not unique"}
            Assert-LateFinalization $controlFinal[0] $controlName $cleanupLate[$controlName]
            $caseContext.transcript_verified=$true
            $caseContext.native_control_verified=$true
            $caseContext.target_reached=$true
            $caseContext.partial_verified=$true
            $caseContext.primary_probes=69
            $caseContext.status='passed_expected_partial'
            $caseResult=[pscustomobject][ordered]@{
                case=$controlName;source=$env:GITHUB_SHA;run=$env:GITHUB_RUN_ID
                selected_unit=$caseName;nonce=$controlNonce;user_sid=$parentIdentity.user_sid
                marker_names=@($controlMachineName,$controlUserName)
                marker_hashes=@($controlMachineHash,$controlUserHash)
                attempted=$true;selected_test_executed=$caseContext.selected_test_executed
                selected_test_passed=$caseContext.selected_test_passed
                transcript_verified=$caseContext.transcript_verified
                native_control_verified=$caseContext.native_control_verified
                status='passed_expected_partial';primary_probes=69
                target_reached=$true;partial_verified=$true
                log_path=(Split-Path -Leaf $controlLog)
                records_path=(Split-Path -Leaf $controlRecordsPath)
                metadata_path=(Split-Path -Leaf $controlMetadataPath)
            }
            }
        } catch {
            $caseFailure=$_.Exception.Message
            $caseContext.failure=$caseFailure
            if($caseContext.status -eq 'initializing'){$caseContext.status='fixture_setup_failed'}
            elseif($caseContext.status -eq 'native_test_started'){$caseContext.status='native_or_transcript_failed'}
            elseif($caseContext.status -eq 'selected_test_passed'){$caseContext.status='transcript_validation_failed'}
        } finally {
            $restoreErrors=[Collections.Generic.List[string]]::new()
            foreach($environmentName in $savedEnvironment.Keys){
                try {
                    $saved=$savedEnvironment[$environmentName]
                    $restoreValue=if($saved.present){[string]$saved.value}else{$null}
                    [Environment]::SetEnvironmentVariable($environmentName,$restoreValue,
                        [EnvironmentVariableTarget]::Process)
                } catch {
                    $restoreErrors.Add("$environmentName restore: $($_.Exception.Message)")
                }
            }
            $caseContext.environment_restore_errors=@($restoreErrors)
            if($restoreErrors.Count -gt 0){
                $restoreFailure=$restoreErrors -join '; '
                if($caseFailure){$caseFailure+="; environment restore: $restoreFailure"}
                else{$caseFailure="environment restore: $restoreFailure"}
                $caseContext.failure=$caseFailure
                $caseContext.status='environment_restore_failed'
                $caseContext.transcript_verified=$false
                $caseContext.native_control_verified=$false
                $caseResult=$null
            }
            try {
                $caseContext | ConvertTo-Json -Depth 8 |
                    Out-File $controlMetadataPath -Encoding utf8
            } catch {
                $metadataFailure="case metadata persistence: $($_.Exception.Message)"
                if($caseFailure){$caseFailure+="; $metadataFailure"}else{$caseFailure=$metadataFailure}
                $caseResult=$null
            }
        }
        if($caseFailure){throw "$controlName failed: $caseFailure"}
        if($null -eq $caseResult){throw "$controlName produced no typed case result"}
        $caseProperties=@($caseResult.PSObject.Properties.Name)
        $requiredCaseProperties=@(
            'case','source','run','selected_unit','nonce','user_sid','marker_names',
            'marker_hashes','attempted','selected_test_executed','selected_test_passed',
            'transcript_verified','native_control_verified','status','primary_probes',
            'target_reached','partial_verified','log_path','records_path','metadata_path'
        )
        if($caseResult -isnot [System.Management.Automation.PSCustomObject] -or
            $caseProperties.Count -ne $requiredCaseProperties.Count -or
            @($requiredCaseProperties | Where-Object {$_ -notin $caseProperties}).Count -ne 0){
            throw "$controlName case result shape was not the exact typed summary"
        }
        return $caseResult
        }
        function ValidateWitnessTranscript {
            param(
                [Collections.Generic.List[string]]$InputFrames,
                [string]$RunNonce,
                [int]$ExitCode,
                [ValidateSet('complete','retained','partial')][string]$Mode,
                [string]$ControlName,
                [Collections.Generic.HashSet[string]]$ExpectedIds,
                [Collections.Generic.List[string]]$ActualIds,
                [string]$ExpectedMachineHash,
                [string]$ExpectedUserHash
            )
            $frames=$InputFrames
            $nonce=$RunNonce
            $code=$ExitCode
            $expected=$ExpectedIds
            $actual=$ActualIds
            $lateDetailCount=@($frames | Where-Object {$_.StartsWith('registry_witness_control_late_detail ')}).Count
            if($Mode -ceq 'partial'){
                if($lateDetailCount -ne 1){throw 'Partial cleanup mode requires exactly one late-detail frame'}
            } elseif($lateDetailCount -ne 0){
                throw 'Late-detail frames are forbidden in complete and retained cleanup modes'
            }
            $probeRecords=@{}
            foreach($frame in $frames){
            if($frame.StartsWith('registry_witness_probe ')){
                if($frame -notmatch '^registry_witness_probe id=([^ ]+) .+$'){throw 'Malformed probe record'}
                $probeRecords[$Matches[1]]=$frame
            }
        }
        $bindingFrames=@($frames|Where-Object{$_.StartsWith('registry_witness_parent_binding ')})
        if($bindingFrames.Count -ne 1){throw 'Expected one parent invocation identity binding'}
        $binding=$bindingFrames[0]
        if((WitnessField $binding 'nonce') -cne $nonce -or
            (WitnessField $binding 'live') -cne 'true' -or
            (WitnessField $binding 'pid') -notmatch '^[1-9][0-9]*$' -or
            (WitnessField $binding 'creation') -notmatch '^[0-9A-Fa-f]{16}$'){
            throw 'Parent invocation identity binding is invalid'
        }
        $boundPid=WitnessField $binding 'pid'
        $boundCreation=WitnessField $binding 'creation'
        $normalExpected=[Collections.Generic.List[string]]::new()
        foreach($operation in @('set_value','delete_value','create_subkey','delete_leaf','set_dacl','set_owner','reopen_write','reopen_delete','reopen_write_dac','reopen_write_owner','duplicate_mutation')){
            foreach($view in @('machine_view','user_view')){$normalExpected.Add("mutation/$operation/$view")}
        }
        foreach($view in @('machine_view','user_view')){$normalExpected.Add("duplicate_read/$view")}
        foreach($right in @('dup_handle','vm_write','vm_operation','create_thread','write_dac','write_owner','vm_read')){$normalExpected.Add("parent_authority/$right")}
        $normalExpected.Add('parent_token/process_query_limited')
        foreach($right in @('token_duplicate','write_dac','write_owner','token_impersonate','token_assign_primary')){$normalExpected.Add("parent_token/$right")}
        if($normalExpected.Count -ne 37){throw 'Internal normal-controls manifest is not 37 IDs'}
        foreach($id in $normalExpected){if(-not $probeRecords.ContainsKey($id)){throw "Normal control missing: $id"}}
        foreach($id in $probeRecords.Keys){
            if($id.StartsWith('parent_authority/') -or $id.StartsWith('parent_token/')){
                $record=$probeRecords[$id]
                if((WitnessField $record 'nonce') -cne $nonce -or
                    (WitnessField $record 'parent_pid') -cne $boundPid -or
                    (WitnessField $record 'parent_creation') -cne $boundCreation){
                    throw "Parent-bound control identity mismatch: $id"
                }
            }
            $record=$probeRecords[$id]
            # Probe-specific schemas below check every normal-tranche branch.
            # Preserve first-equals parsing because attempts embeds key=value pairs.
        }
        $mutationFields=@('id','domain','status','expected','observed','data_and_descriptor_unchanged','mutation_subkey_absent','before','after')
        foreach($operation in @('set_value','delete_value','create_subkey','delete_leaf','set_dacl','set_owner','reopen_write','reopen_delete','reopen_write_dac','reopen_write_owner')){
            foreach($view in @('machine_view','user_view')){WitnessExactFields $probeRecords["mutation/$operation/$view"] $mutationFields}
        }
        $duplicateReadFields=@('id','domain','status','expected','observed','source_access','actual','query_ntstatus','returned_length','label_read')
        foreach($view in @('machine_view','user_view')){WitnessExactFields $probeRecords["duplicate_read/$view"] $duplicateReadFields}
        $authorityFields=@('id','domain','status','expected','observed','requested','nonce','parent_pid','parent_creation')
        foreach($right in @('dup_handle','vm_write','vm_operation','create_thread','write_dac','write_owner','vm_read')){
            WitnessExactFields $probeRecords["parent_authority/$right"] $authorityFields
        }
        $queryBlockedFields=@('id','domain','status','expected','observed','branch','nonce','parent_pid','parent_creation')
        $queryOpenFields=@('id','domain','status','expected','observed','branch','actual','query_ntstatus','returned_length','nonce','parent_pid','parent_creation')
        $queryRecord=$probeRecords['parent_token/process_query_limited']
        $queryRecordBranch=WitnessField $queryRecord 'branch'
        if($queryRecordBranch -ceq 'blocked_by_process_gate'){
            WitnessExactFields $queryRecord $queryBlockedFields
        } elseif($queryRecordBranch -ceq 'query_open'){
            WitnessExactFields $queryRecord $queryOpenFields
        } else {throw 'Unknown query-limited token-gate schema'}
        $blockedTokenFields=@('id','domain','branch','executed','gate_id','gate_status','nonce','parent_pid','parent_creation')
        $executedTokenFields=@('id','domain','status','expected','observed','branch','executed','requested','acquired','nonce','parent_pid','parent_creation')
        foreach($right in @('token_duplicate','write_dac','write_owner','token_impersonate','token_assign_primary')){
            $record=$probeRecords["parent_token/$right"]
            if((WitnessField $record 'branch') -ceq 'blocked_by_process_gate'){
                WitnessExactFields $record $blockedTokenFields
            } else {WitnessExactFields $record $executedTokenFields}
        }
        $duplicateDeniedFields=@('id','domain','status','expected','observed','branch','desired','actual','data_and_descriptor_unchanged','mutation_subkey_absent','before','after')
        $duplicateLimitedFields=@('id','domain','status','expected','observed','branch','desired','actual','query_ntstatus','returned_length','data_and_descriptor_unchanged','mutation_subkey_absent','before','after','attempts')
        foreach($view in @('machine_view','user_view')){
            $record=$probeRecords["mutation/duplicate_mutation/$view"]
            switch(WitnessField $record 'branch'){
                'duplicate_denied' {WitnessExactFields $record $duplicateDeniedFields}
                'limited' {WitnessExactFields $record $duplicateLimitedFields}
                'unexpected_granted_access' {WitnessExactFields $record @('id','domain','status','expected','observed','branch','desired','actual')}
                'mutation_not_denied' {WitnessExactFields $record @('id','domain','status','expected','observed','branch','desired','actual','operation')}
                default {throw 'Unknown duplicate-mutation schema'}
            }
        }
        foreach($operation in @('set_value','delete_value','create_subkey','delete_leaf','set_dacl','set_owner','reopen_write','reopen_delete','reopen_write_dac','reopen_write_owner')){
            foreach($view in @('machine_view','user_view')){
                $id="mutation/$operation/$view";$record=$probeRecords[$id]
                if((WitnessField $record 'domain') -cne 'lstatus' -or
                    (WitnessHex (WitnessField $record 'status')) -ne 5 -or
                    (WitnessHex (WitnessField $record 'expected')) -ne 5 -or
                    (WitnessField $record 'observed') -cne 'true' -or
                    (WitnessField $record 'data_and_descriptor_unchanged') -cne 'true' -or
                    (WitnessField $record 'mutation_subkey_absent') -cne 'true'){
                    throw "Private mutation control failed schema/status/preimage validation: $id"
                }
                $before=WitnessField $record 'before';$after=WitnessField $record 'after'
                if($before -notmatch '^[0-9A-Fa-f]{64}$' -or $before -cne $after){throw "Private mutation preimage changed: $id"}
            }
        }
        foreach($view in @('machine_view','user_view')){
            $id="duplicate_read/$view";$record=$probeRecords[$id]
            if((WitnessField $record 'domain') -cne 'win32' -or
                (WitnessHex (WitnessField $record 'status')) -ne 0 -or
                (WitnessHex (WitnessField $record 'expected')) -ne 0 -or
                (WitnessField $record 'observed') -cne 'true' -or
                (WitnessField $record 'label_read') -cne 'true' -or
                (WitnessHex (WitnessField $record 'query_ntstatus')) -ne 0 -or
                [int](WitnessField $record 'returned_length') -ne 56){throw "Same-access duplicate read failed: $id"}
            $source=WitnessHex (WitnessField $record 'source_access');$granted=WitnessHex (WitnessField $record 'actual')
            if($source -ne $granted -or ($granted -band ([uint32]::MaxValue -bxor [uint32]0x20019)) -ne 0){throw "Duplicate read handle exceeded source KEY_READ: $id"}
        }
        foreach($operation in @('dup_handle','vm_write','vm_operation','create_thread','write_dac','write_owner','vm_read')){
            $id="parent_authority/$operation";$record=$probeRecords[$id]
            $rights=@{dup_handle='0x40';vm_write='0x20';vm_operation='0x8';create_thread='0x2';write_dac='0x40000';write_owner='0x80000';vm_read='0x10'}
            if((WitnessField $record 'domain') -cne 'win32' -or
                (WitnessHex (WitnessField $record 'status')) -ne 5 -or
                (WitnessHex (WitnessField $record 'expected')) -ne 5 -or
                (WitnessField $record 'observed') -cne 'true' -or
                (WitnessField $record 'requested') -cne $rights[$operation]){throw "Parent authority gate failed: $id"}
        }
        $query=$probeRecords['parent_token/process_query_limited']
        $queryBranch=WitnessField $query 'branch'
        if($queryBranch -ceq 'blocked_by_process_gate'){
            if((WitnessField $query 'domain') -cne 'win32' -or
                (WitnessHex (WitnessField $query 'status')) -ne 5 -or
                (WitnessHex (WitnessField $query 'expected')) -ne 5 -or
                (WitnessField $query 'observed') -cne 'true'){throw 'Query-limited denial branch was not exact'}
            foreach($right in @('token_duplicate','write_dac','write_owner','token_impersonate','token_assign_primary')){
                $record=$probeRecords["parent_token/$right"]
                if((WitnessField $record 'domain') -cne 'gate' -or
                    (WitnessField $record 'branch') -cne 'blocked_by_process_gate' -or
                    (WitnessField $record 'executed') -cne 'false' -or
                    (WitnessField $record 'gate_id') -cne 'parent_token/process_query_limited' -or
                    (WitnessHex (WitnessField $record 'gate_status')) -ne 5 -or
                    $record -match '(?:^|\s)status=') {throw "Invalid blocked token-gate record: parent_token/$right"}
            }
        } elseif($queryBranch -ceq 'query_open'){
            if((WitnessField $query 'domain') -cne 'win32' -or
                (WitnessHex (WitnessField $query 'status')) -ne 0 -or
                (WitnessHex (WitnessField $query 'expected')) -ne 0 -or
                (WitnessField $query 'observed') -cne 'true' -or
                (WitnessHex (WitnessField $query 'actual')) -ne 0x1000 -or
                (WitnessHex (WitnessField $query 'query_ntstatus')) -ne 0 -or
                [int](WitnessField $query 'returned_length') -ne 56 -or
                (WitnessField $query 'parent_pid') -cne $boundPid -or
                (WitnessField $query 'parent_creation') -cne $boundCreation){throw 'Query-limited success binding was invalid'}
            $tokenRights=@{token_duplicate='0x2';write_dac='0x40000';write_owner='0x80000';token_impersonate='0x4';token_assign_primary='0x1'}
            foreach($right in $tokenRights.Keys){
                $record=$probeRecords["parent_token/$right"]
                if((WitnessField $record 'domain') -cne 'win32' -or
                    (WitnessField $record 'branch') -cne 'query_open' -or
                    (WitnessField $record 'executed') -cne 'true' -or
                    (WitnessField $record 'observed') -cne 'true' -or
                    (WitnessHex (WitnessField $record 'status')) -ne 5 -or
                    (WitnessHex (WitnessField $record 'expected')) -ne 5 -or
                    (WitnessField $record 'acquired') -cne 'false' -or
                    (WitnessField $record 'requested') -cne $tokenRights[$right]){throw "Token right gate failed: parent_token/$right"}
            }
        } else {throw 'Unknown query-limited token-gate branch'}
        foreach($view in @('machine_view','user_view')){
            $id="mutation/duplicate_mutation/$view";$record=$probeRecords[$id]
            $branch=WitnessField $record 'branch';$status=WitnessHex (WitnessField $record 'status')
            if((WitnessField $record 'domain') -cne 'win32'){throw "Mutation duplicate domain invalid: $id"}
            # KEY_WRITE (0x20006, including KEY_CREATE_SUB_KEY) | DELETE | WRITE_DAC | WRITE_OWNER.
            $expectedDuplicateDesired=[uint32]0xf0006
            if($branch -ceq 'duplicate_denied'){
                if($status -ne 5 -or (WitnessHex (WitnessField $record 'expected')) -ne 5 -or
                    (WitnessField $record 'observed') -cne 'true' -or
                    (WitnessHex (WitnessField $record 'desired')) -ne $expectedDuplicateDesired -or
                    (WitnessField $record 'actual') -cne 'unknown' -or
                    (WitnessField $record 'data_and_descriptor_unchanged') -cne 'true' -or
                    (WitnessField $record 'mutation_subkey_absent') -cne 'true') {throw "Mutation duplicate denial invalid: $id"}
                $before=WitnessField $record 'before';$after=WitnessField $record 'after'
                if($before -notmatch '^[0-9A-Fa-f]{64}$' -or $before -cne $after){throw "Mutation duplicate denial changed preimage: $id"}
            } elseif($branch -ceq 'limited'){
                $granted=WitnessHex (WitnessField $record 'actual')
                if($status -ne 0 -or (WitnessHex (WitnessField $record 'expected')) -ne 0 -or
                    (WitnessField $record 'observed') -cne 'true' -or
                    (WitnessHex (WitnessField $record 'desired')) -ne $expectedDuplicateDesired -or
                    (WitnessHex (WitnessField $record 'query_ntstatus')) -ne 0 -or
                    [int](WitnessField $record 'returned_length') -ne 56 -or
                    ($granted -band ([uint32]::MaxValue -bxor [uint32]0x20019)) -ne 0 -or
                    (WitnessField $record 'data_and_descriptor_unchanged') -cne 'true' -or
                    (WitnessField $record 'mutation_subkey_absent') -cne 'true'){throw "Mutation duplicate exceeded safe read-only branch: $id"}
                $attempts=@{}
                foreach($pair in (WitnessField $record 'attempts').Split(',')){
                    if($pair -notmatch '^([a-z_]+)=(0x[0-9a-fA-F]+)$'){throw "Malformed duplicate mutation subprobe: $id"}
                    $operationName=$Matches[1];$operationStatus=$Matches[2]
                    if($attempts.ContainsKey($operationName)){throw "Malformed duplicate mutation subprobe: $id"}
                    $attempts[$operationName]=$operationStatus
                }
                foreach($operation in @('set_value','delete_value','create_subkey','delete_leaf','set_dacl','set_owner')){
                    if(-not $attempts.ContainsKey($operation) -or (WitnessHex $attempts[$operation]) -ne 5){throw "Duplicate mutation was not denied: $id/$operation"}
                }
                if($attempts.Count -ne 6){throw "Unexpected duplicate mutation subprobe: $id"}
                $before=WitnessField $record 'before';$after=WitnessField $record 'after'
                if($before -notmatch '^[0-9A-Fa-f]{64}$' -or $before -cne $after){throw "Duplicate mutation changed preimage: $id"}
            } else {throw "Unknown mutation-duplicate branch: $id"}
        }
        foreach($id in $probeRecords.Keys){
            $record=$probeRecords[$id]
            if($id -match '^(baseline|reset)/host_denied/(win32|nt)/(machine|user)$' -or
                $id -match '^mapped/host_denied/(win32|nt)/(machine|user)$'){
                $api=$id.Split('/')[2]
                $expectedStatus=if($api -ceq 'win32'){'0x5'}else{'0xc0000022'}
                $expectedDomain=if($api -ceq 'win32'){'lstatus'}else{'ntstatus'}
                if((WitnessField $record 'domain') -cne $expectedDomain -or
                    (WitnessField $record 'status') -cne $expectedStatus){throw "Host-denial status mismatch: $id"}
            } elseif($id -match '^mapped/private_absent/(machine_view|user_view)$'){
                if((WitnessField $record 'domain') -cne 'lstatus' -or
                    (WitnessField $record 'status') -cne '2'){throw "Private absence status mismatch: $id"}
            } elseif($id -match '^parent_present/(before|after)/(win32|nt)/(machine|user)$'){
                $expectedMarkerHash=if($Matches[3] -ceq 'machine'){$ExpectedMachineHash}else{$ExpectedUserHash}
                if((WitnessField $record 'status') -cne '0' -or
                    (WitnessField $record 'observed') -cne 'true' -or
                    (WitnessField $record 'sha256') -notmatch '^[0-9A-Fa-f]{64}$' -or
                    (WitnessField $record 'sha256') -ine $expectedMarkerHash){
                    throw "Parent marker control failed its fresh expected value hash: $id"
                }
            } elseif($id -match '^(inherited|mapped|remapped)/public_read/(machine_view|user_view)$'){
                if((WitnessField $record 'observed') -cne 'true'){throw "Private view read failed: $id"}
            } elseif($id -match '^parent_recovery/(machine_view|user_view)$'){
                if((WitnessField $record 'observed') -cne 'true' -or
                    (WitnessHex (WitnessField $record 'granted_access')) -ne 0xf003f){throw "Parent fixture recovery failed: $id"}
            } elseif($id -ceq 'lifetime/normal_job_zero'){
                if((WitnessField $record 'observed') -cne 'true' -or
                    (WitnessField $record 'active_processes') -cne '0'){throw 'Normal helper Job did not reach zero'}
            }
        }
        $normalResults=@($frames | Where-Object { $_.StartsWith('registry_witness_child_result ') })
        if($normalResults.Count -ne 1){throw 'Expected exactly one completed normal helper identity record'}
        $normalResult=$normalResults[0]
        $normalResultFields=@('role','completion','exit','pid','creation','image_id','image_sha256','fixture_id','fixture_digest')
        WitnessExactFields $normalResult $normalResultFields
        if((WitnessField $normalResult 'role') -cne 'normal' -or
            (WitnessField $normalResult 'completion') -cne 'Exited' -or
            (WitnessField $normalResult 'exit') -cne '0' -or
            (WitnessField $normalResult 'pid') -notmatch '^[1-9][0-9]*$' -or
            (WitnessField $normalResult 'creation') -notmatch '^[0-9A-Fa-f]{16}$' -or
            (WitnessField $normalResult 'image_id') -notmatch '^[0-9A-Fa-f]{16}:[0-9A-Fa-f]{32}$' -or
            (WitnessField $normalResult 'image_sha256') -notmatch '^[0-9A-Fa-f]{64}$' -or
            (WitnessField $normalResult 'fixture_id') -notmatch '^[0-9A-Fa-f]{64}$' -or
            (WitnessField $normalResult 'fixture_digest') -notmatch '^[0-9A-Fa-f]{64}$'){
            throw 'Normal helper identity binding is incomplete'
        }
        $admissionRecords=@($frames | Where-Object { $_.StartsWith('registry_witness_child_admission ') })
        if($admissionRecords.Count -ne 2){throw 'Expected exactly one admission record per helper role'}
        $admissionFields=@('nonce','role','pid','creation','appcontainer','lpac','capability_count','network_capabilities','job','thread_token')
        foreach($admission in $admissionRecords){WitnessExactFields $admission $admissionFields}
        $normalAdmission=@($admissionRecords | Where-Object {(WitnessField $_ 'role') -ceq 'normal'})
        $cancelAdmission=@($admissionRecords | Where-Object {(WitnessField $_ 'role') -ceq 'cancel'})
        if($normalAdmission.Count -ne 1 -or $cancelAdmission.Count -ne 1){throw 'Admission records were not uniquely bound to normal and cancel roles'}
        $normalAdmissionRecord=$normalAdmission[0]
        $cancelAdmissionRecord=$cancelAdmission[0]
        foreach($admission in @($normalAdmissionRecord,$cancelAdmissionRecord)){
            if((WitnessField $admission 'nonce') -cne $nonce -or
                (WitnessField $admission 'pid') -notmatch '^[1-9][0-9]*$' -or
                (WitnessField $admission 'creation') -notmatch '^[0-9A-Fa-f]{16}$' -or
                (WitnessField $admission 'appcontainer') -cne 'true' -or
                (WitnessField $admission 'lpac') -cne 'true' -or
                (WitnessField $admission 'capability_count') -cne '1' -or
                (WitnessField $admission 'network_capabilities') -cne '0' -or
                (WitnessField $admission 'job') -cne 'true' -or
                (WitnessField $admission 'thread_token') -cne 'false'){
                throw 'Helper admission token, Job, or invocation binding failed'
            }
        }
        if((WitnessField $normalAdmissionRecord 'pid') -cne (WitnessField $normalResult 'pid') -or
            (WitnessField $normalAdmissionRecord 'creation') -cne (WitnessField $normalResult 'creation')){
            throw 'Normal admission did not match the parent-observed child identity'
        }
        $cancelReady=$probeRecords['lifetime/cancel_ready_mapped']
        $cancelReadyFields=@('id','nonce','role','pid','creation','parent_pid','parent_creation',
            'image_id','image_sha256','fixture_id','fixture_digest','machine_descriptor_sha256',
            'user_descriptor_sha256','inherited_machine_label_sha256','inherited_user_label_sha256',
            'mapped_machine_label_sha256','mapped_user_label_sha256','appcontainer','lpac',
            'capability_count','network_capabilities','thread_token','job','inherited_reads',
            'mapped_machine','mapped_user','maps_live','parent_received_while_alive','job_active_processes')
        WitnessExactFields $cancelReady $cancelReadyFields
        if((WitnessField $cancelReady 'id') -cne 'lifetime/cancel_ready_mapped' -or
            (WitnessField $cancelReady 'nonce') -cne $nonce -or
            (WitnessField $cancelReady 'role') -cne 'cancel' -or
            (WitnessField $cancelReady 'pid') -notmatch '^[1-9][0-9]*$' -or
            (WitnessField $cancelReady 'creation') -notmatch '^[0-9A-Fa-f]{16}$' -or
            (WitnessField $cancelReady 'parent_pid') -cne $boundPid -or
            (WitnessField $cancelReady 'parent_creation') -cne $boundCreation -or
            (WitnessField $cancelReady 'image_id') -cne (WitnessField $normalResult 'image_id') -or
            (WitnessField $cancelReady 'image_id') -notmatch '^[0-9A-Fa-f]{16}:[0-9A-Fa-f]{32}$' -or
            (WitnessField $cancelReady 'image_sha256') -cne (WitnessField $normalResult 'image_sha256') -or
            (WitnessField $cancelReady 'fixture_id') -cne (WitnessField $normalResult 'fixture_id') -or
            (WitnessField $cancelReady 'fixture_digest') -cne (WitnessField $normalResult 'fixture_digest') -or
            (WitnessField $cancelReady 'machine_descriptor_sha256') -notmatch '^[0-9A-Fa-f]{64}$' -or
            (WitnessField $cancelReady 'user_descriptor_sha256') -notmatch '^[0-9A-Fa-f]{64}$' -or
            (WitnessField $cancelReady 'inherited_machine_label_sha256') -notmatch '^[0-9A-Fa-f]{64}$' -or
            (WitnessField $cancelReady 'inherited_user_label_sha256') -notmatch '^[0-9A-Fa-f]{64}$' -or
            (WitnessField $cancelReady 'mapped_machine_label_sha256') -cne (WitnessField $cancelReady 'inherited_machine_label_sha256') -or
            (WitnessField $cancelReady 'mapped_user_label_sha256') -cne (WitnessField $cancelReady 'inherited_user_label_sha256') -or
            (WitnessField $cancelReady 'appcontainer') -cne 'true' -or
            (WitnessField $cancelReady 'lpac') -cne 'true' -or
            (WitnessField $cancelReady 'capability_count') -cne '1' -or
            (WitnessField $cancelReady 'network_capabilities') -cne '0' -or
            (WitnessField $cancelReady 'thread_token') -cne 'false' -or
            (WitnessField $cancelReady 'job') -cne 'true' -or
            (WitnessField $cancelReady 'inherited_reads') -cne '2' -or
            (WitnessField $cancelReady 'mapped_machine') -cne 'true' -or
            (WitnessField $cancelReady 'mapped_user') -cne 'true' -or
            (WitnessField $cancelReady 'maps_live') -cne '2' -or
            (WitnessField $cancelReady 'parent_received_while_alive') -cne 'true' -or
            (WitnessField $cancelReady 'job_active_processes') -cne '1'){
            throw 'Cancellation readiness bindings or live observations failed'
        }
        if((WitnessField $cancelAdmissionRecord 'pid') -cne (WitnessField $cancelReady 'pid') -or
            (WitnessField $cancelAdmissionRecord 'creation') -cne (WitnessField $cancelReady 'creation')){
            throw 'Cancellation admission did not match the live readiness child identity'
        }
        $cancelJob=$probeRecords['lifetime/cancel_job_zero']
        $cancelJobFields=@('id','nonce','role','pid','creation','parent_pid','parent_creation',
            'image_id','image_sha256','fixture_id','fixture_digest','terminate_job_object',
            'process_waited','active_processes','exit_code','observed')
        WitnessExactFields $cancelJob $cancelJobFields
        if((WitnessField $cancelJob 'id') -cne 'lifetime/cancel_job_zero' -or
            (WitnessField $cancelJob 'nonce') -cne $nonce -or
            (WitnessField $cancelJob 'role') -cne 'cancel' -or
            (WitnessField $cancelJob 'pid') -cne (WitnessField $cancelReady 'pid') -or
            (WitnessField $cancelJob 'creation') -cne (WitnessField $cancelReady 'creation') -or
            (WitnessField $cancelJob 'parent_pid') -cne $boundPid -or
            (WitnessField $cancelJob 'parent_creation') -cne $boundCreation -or
            (WitnessField $cancelJob 'image_id') -cne (WitnessField $cancelReady 'image_id') -or
            (WitnessField $cancelJob 'image_id') -notmatch '^[0-9A-Fa-f]{16}:[0-9A-Fa-f]{32}$' -or
            (WitnessField $cancelJob 'image_sha256') -cne (WitnessField $cancelReady 'image_sha256') -or
            (WitnessField $cancelJob 'fixture_id') -cne (WitnessField $cancelReady 'fixture_id') -or
            (WitnessField $cancelJob 'fixture_digest') -cne (WitnessField $cancelReady 'fixture_digest') -or
            (WitnessField $cancelJob 'terminate_job_object') -cne 'true' -or
            (WitnessField $cancelJob 'process_waited') -cne 'true' -or
            (WitnessField $cancelJob 'active_processes') -cne '0' -or
            (WitnessField $cancelJob 'exit_code') -cne '1' -or
            (WitnessField $cancelJob 'observed') -cne 'true'){
            throw 'Cancellation termination, process wait or zero-active Job proof failed'
        }
        $peDiagnostics=@($frames | Where-Object {$_ -match '^registry_witness_diagnostic stream=helper_image_pe(?: |$)'})
        if($peDiagnostics.Count -ne 1){throw 'Expected exactly one held-image PE diagnostic'}
        $peDiagnostic=$peDiagnostics[0]
        WitnessExactFields $peDiagnostic @('stream','image_id','image_sha256','image_bytes','machine','subsystem')
        if((WitnessField $peDiagnostic 'image_id') -cne (WitnessField $normalResult 'image_id') -or
            (WitnessField $peDiagnostic 'image_sha256') -cne (WitnessField $normalResult 'image_sha256') -or
            (WitnessField $peDiagnostic 'image_bytes') -notmatch '^[1-9][0-9]*$' -or
            [int64](WitnessField $peDiagnostic 'image_bytes') -gt 16777216 -or
            (WitnessField $peDiagnostic 'machine') -cne '0x8664' -or
            (WitnessField $peDiagnostic 'subsystem') -cne '0x0002'){
            throw 'Held-image PE diagnostic did not bind the bounded AMD64 GUI image'
        }
        $liveMemberDiagnostics=@($frames | Where-Object {$_ -match '^registry_witness_diagnostic stream=cancel_job_live_member(?: |$)'})
        if($liveMemberDiagnostics.Count -ne 1){throw 'Expected exactly one live cancellation Job-member diagnostic'}
        $liveMember=$liveMemberDiagnostics[0]
        WitnessExactFields $liveMember @('stream','child_pid','child_creation','assigned','listed',
            'returned_bytes','pid','actual_pid','actual_creation','membership','active_processes','observed')
        if((WitnessField $liveMember 'child_pid') -cne (WitnessField $cancelReady 'pid') -or
            (WitnessField $liveMember 'child_creation') -cne (WitnessField $cancelReady 'creation') -or
            (WitnessField $liveMember 'assigned') -cne '1' -or
            (WitnessField $liveMember 'listed') -cne '1' -or
            (WitnessField $liveMember 'returned_bytes') -notmatch '^[1-9][0-9]*$' -or
            [int](WitnessField $liveMember 'returned_bytes') -lt 8 -or
            (WitnessField $liveMember 'pid') -cne (WitnessField $cancelReady 'pid') -or
            (WitnessField $liveMember 'actual_pid') -cne (WitnessField $cancelReady 'pid') -or
            (WitnessField $liveMember 'actual_creation') -cne (WitnessField $cancelReady 'creation') -or
            (WitnessField $liveMember 'membership') -cne 'owned_job' -or
            (WitnessField $liveMember 'active_processes') -cne '1' -or
            (WitnessField $liveMember 'observed') -cne 'true'){
            throw 'Live cancellation Job membership did not prove its exact singleton process'
        }
        if($code -ne 0){throw "Registry witness test did not exit successfully (exit $code)"}
        $statusRecords=@($frames | Where-Object { $_ -match '^registry_witness_status(?: |$)' })
        if($statusRecords.Count -ne 1){throw "Expected exactly one registry witness status record (found $($statusRecords.Count))"}
        $statusRecord=$statusRecords[0]
        WitnessExactFields $statusRecord @('witness_status','run_status')
        if(@($frames | Where-Object { $_ -match '^registry_witness_incomplete(?: |$)' }).Count -ne 0){
            throw 'A witness transcript included a separate incomplete record'
        }
        $finalizations=@($frames | Where-Object { $_ -match '^registry_witness_finalization(?: |$)' })
        if($finalizations.Count -ne 1){throw "Expected exactly one finalization receipt (found $($finalizations.Count))"}
        $finalization=$finalizations[0]
        if($Mode -ceq 'complete'){
            if((WitnessField $statusRecord 'witness_status') -cne 'COMPLETE' -or
                (WitnessField $statusRecord 'run_status') -cne 'completed'){
                throw 'Primary registry witness did not report completed cleanup'
            }
            $cleanup=$probeRecords['lifetime/cleanup_absent']
            $cleanupFields=@('id','observed','normal_job_zero','cancel_job_zero','registry_absent',
                'image_absent','directory_absent','profile_absent')
            WitnessExactFields $cleanup $cleanupFields
            foreach($field in @('observed','normal_job_zero','cancel_job_zero','registry_absent',
                'image_absent','directory_absent','profile_absent')){
                if((WitnessField $cleanup $field) -cne 'true'){throw "Cleanup absence receipt failed: $field"}
            }
            $finalFields=@('cleanup_errors','registry_absent','image_absent','directory_absent',
                'profile_absent','normal_job_zero','cancel_job_zero','host_marker_postcontrol')
            WitnessExactFields $finalization $finalFields
            if((WitnessField $finalization 'cleanup_errors') -cne '0' -or
                (WitnessField $finalization 'registry_absent') -cne 'true' -or
                (WitnessField $finalization 'image_absent') -cne 'true' -or
                (WitnessField $finalization 'directory_absent') -cne 'true' -or
                (WitnessField $finalization 'profile_absent') -cne 'true' -or
                (WitnessField $finalization 'normal_job_zero') -cne 'true' -or
                (WitnessField $finalization 'cancel_job_zero') -cne 'true' -or
                (WitnessField $finalization 'host_marker_postcontrol') -cne 'observed'){
                throw 'Final cleanup receipt did not bind all required absence and Job proofs'
            }
            $missing=@($expected | Where-Object { -not $actual.Contains($_) })
            if($missing.Count -ne 0 -or $actual.Count -ne 70){
                throw "Registry control set incomplete (observed $($actual.Count)/70; missing $($missing -join ', '))"
            }
        } elseif($Mode -ceq 'retained') {
            if((WitnessField $statusRecord 'witness_status') -cne 'INCOMPLETE' -or
                (WitnessField $statusRecord 'run_status') -cne 'control_retained'){
                throw 'Retained control did not report exact INCOMPLETE/control_retained status'
            }
            if($probeRecords.ContainsKey('lifetime/cleanup_absent')){
                throw 'Retained control reported cleanup absence'
            }
            $retainedFields=@('status','control','profile_absent','sdk_called',
                'registry_fixture_retained','image_retained','helper_directory_retained',
                'normal_job_zero','cancel_job_zero','cleanup_errors')
            WitnessExactFields $finalization $retainedFields
            if((WitnessField $finalization 'status') -cne 'retained' -or
                (WitnessField $finalization 'control') -cne $ControlName -or
                (WitnessField $finalization 'profile_absent') -cne 'false' -or
                (WitnessField $finalization 'sdk_called') -cne 'false' -or
                (WitnessField $finalization 'registry_fixture_retained') -cne 'true' -or
                (WitnessField $finalization 'image_retained') -cne 'true' -or
                (WitnessField $finalization 'helper_directory_retained') -cne 'true' -or
                (WitnessField $finalization 'normal_job_zero') -cne 'true' -or
                (WitnessField $finalization 'cancel_job_zero') -cne 'true' -or
                (WitnessField $finalization 'cleanup_errors') -cne '0'){
                throw 'Retained control finalization did not bind unchanged retained state'
            }
            $missing=@($expected | Where-Object { -not $actual.Contains($_) })
            if($actual.Count -ne 69 -or $missing.Count -ne 1 -or
                $missing[0] -cne 'lifetime/cleanup_absent'){
                throw "Retained transcript is not exactly the existing 69-control subset; missing $($missing -join ', ')"
            }
        } else {
            if((WitnessField $statusRecord 'witness_status') -cne 'INCOMPLETE' -or
                (WitnessField $statusRecord 'run_status') -cne 'control_partial'){
                throw 'Late control did not report exact INCOMPLETE/control_partial status'
            }
            if($probeRecords.ContainsKey('lifetime/cleanup_absent')){
                throw 'Late control reported a cleanup_absent probe'
            }
            $missing=@($expected | Where-Object { -not $actual.Contains($_) })
            if($actual.Count -ne 69 -or $missing.Count -ne 1 -or
                $missing[0] -cne 'lifetime/cleanup_absent'){
                throw "Late transcript is not exactly the 69-probe partial subset; missing $($missing -join ', ')"
            }
            $partialFields=@('status','control','registry_absent','image_absent','directory_absent',
                'profile_absent','image_disposition_executed','directory_disposition_executed',
                'sdk_executed','normal_job_zero','cancel_job_zero','cleanup_errors')
            WitnessExactFields $finalization $partialFields
            if((WitnessField $finalization 'status') -cne 'partial' -or
                (WitnessField $finalization 'control') -cne $ControlName -or
                (WitnessField $finalization 'registry_absent') -cne 'true' -or
                (WitnessField $finalization 'normal_job_zero') -cne 'true' -or
                (WitnessField $finalization 'cancel_job_zero') -cne 'true' -or
                (WitnessField $finalization 'cleanup_errors') -cne '1'){
                throw 'Late transcript finalization did not prove the fixed partial cleanup state'
            }
        }
            if($Mode -ceq 'complete'){
                $parentIdentity.primary_witness_status='COMPLETE'
                $parentIdentity.missing_probe_count=0
                $parentIdentity.ordinary_user_support_proven=$false
            }
            return ,$probeRecords
        }
        $probeRecords=ValidateWitnessTranscript -InputFrames $frames -RunNonce $nonce -ExitCode $code -Mode complete -ControlName '' -ExpectedIds $expected -ActualIds $actual -ExpectedMachineHash $parentIdentity.marker_sha256[0] -ExpectedUserHash $parentIdentity.marker_sha256[1]
        $lateParserRegression=Test-LateErrorGrammarParser -CaseTable $cleanupLate -CaseOrder $cleanupLateOrder
        $lateParserRegression | ConvertTo-Json -Depth 4 |
            Out-File -LiteralPath (Join-Path $EvidenceDir 'cleanup-late-parser-regression.json') -Encoding utf8
        $lateAdmissionUnit='process::windows::registry_witness_tests::registry_witness_late_error_admission_rejects_coalesced_unexpected_close'
        $lateAdmissionLog=Join-Path $EvidenceDir 'cleanup-late-error-admission.log'
        cargo +1.99.0 test --locked -p orbit-platform --features registry-witness --lib $lateAdmissionUnit -- --exact --test-threads=1 --nocapture 2>&1 |
            Tee-Object -FilePath $lateAdmissionLog | Out-Host
        $lateAdmissionCode=$LASTEXITCODE
        $lateAdmissionOutput=Get-Content $lateAdmissionLog -Raw
        $lateAdmissionHarness=[regex]::Replace($lateAdmissionOutput,'\x1b\[[0-9;]*m','')
        $lateAdmissionLine='(?m)^test '+[regex]::Escape($lateAdmissionUnit)+' \.\.\. ok\r?$'
        $lateAdmissionSummary='(?m)^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s\r?$'
        if($lateAdmissionCode -ne 0 -or
            [regex]::Matches($lateAdmissionHarness,'(?m)^running 1 test\r?$').Count -ne 1 -or
            [regex]::Matches($lateAdmissionHarness,$lateAdmissionLine).Count -ne 1 -or
            [regex]::Matches($lateAdmissionHarness,$lateAdmissionSummary).Count -ne 1){
            throw 'Validator-only late error admission regression did not execute and pass exactly once'
        }
        $controlRuns=[Collections.Generic.List[object]]::new()
        # Every fixed case gets a fresh nonce, fake marker names, and an exact Rust unit selection.
        $controlFailures=[Collections.Generic.List[object]]::new()
        foreach($controlName in (@($cleanupImplemented)+@($cleanupLateOrder))){
            try {
                $caseSummary=InvokeCleanupControl $controlName
                if($caseSummary -isnot [System.Management.Automation.PSCustomObject] -or
                    $caseSummary.case -cne $controlName -or
                    $caseSummary.attempted -ne $true){
                    throw "$controlName did not return one validated case summary"
                }
                [void]$controlRuns.Add($caseSummary)
            } catch {
                $controlError=$_.Exception.Message
                $caseMetadataPath=Join-Path $EvidenceDir ('registry-cleanup-controls/'+$controlName+'.json')
                $caseFailureRecord=$null
                if(Test-Path -LiteralPath $caseMetadataPath -PathType Leaf){
                    try {$caseFailureRecord=Get-Content $caseMetadataPath -Raw | ConvertFrom-Json -AsHashtable}
                    catch {$controlError+="; case metadata parse: $($_.Exception.Message)"}
                }
                if($null -eq $caseFailureRecord){
                    $caseUnit='process::windows::registry_witness_tests::registry_witness_cleanup_control_'+$controlName
                    $caseFailureRecord=[ordered]@{
                        case=$controlName;source=$env:GITHUB_SHA;run=$env:GITHUB_RUN_ID
                        selected_unit=$caseUnit;nonce=$null;user_sid=$parentIdentity.user_sid
                        marker_names=@();marker_hashes=@();attempted=$true
                        selected_test_executed=$false;selected_test_passed=$false
                        transcript_verified=$false;native_control_verified=$false
                        status='metadata_missing';primary_probes=0;target_reached=$false
                        partial_verified=$false;failure=$controlError
                        log_path=('registry-cleanup-controls/'+$controlName+'.log')
                        records_path=('registry-cleanup-controls/'+$controlName+'.records.txt')
                        metadata_path=('registry-cleanup-controls/'+$controlName+'.json')
                    }
                }else{
                    $caseFailureRecord.failure=$controlError
                }
                [void]$controlFailures.Add($caseFailureRecord)
            }
        }
        $allControlCases=@($controlRuns.ToArray())+@($controlFailures.ToArray())
        $controlAttempted=@($allControlCases | Where-Object {$_.attempted -eq $true}).Count
        $controlExecuted=@($allControlCases | Where-Object {$_.selected_test_executed -eq $true}).Count
        $controlTestPassed=@($allControlCases | Where-Object {
            $_.selected_test_executed -eq $true -and $_.selected_test_passed -eq $true
        }).Count
        $controlPassed=@($allControlCases | Where-Object {
            $_.transcript_verified -eq $true -and $_.native_control_verified -eq $true
        }).Count
        $suiteVerified=$controlAttempted -eq 25 -and $controlExecuted -eq 25 -and
            $controlTestPassed -eq 25 -and $controlPassed -eq 25 -and
            $controlFailures.Count -eq 0 -and $cleanupPending.Count -eq 0
        $cleanupControlSummary=[ordered]@{
            status=$(if($suiteVerified){'ALL_25_VERIFIED'}else{'INCOMPLETE_FAIL_CLOSED'});required=25;attempted=$controlAttempted
            selected_test_executed=$controlExecuted;selected_test_passed=$controlTestPassed
            native_controls_verified=$controlPassed;missing=$cleanupPending
            failed=@($controlFailures.ToArray());manifest=$cleanupCaseManifest
            cases=$allControlCases
        }
        $cleanupControlSummary | ConvertTo-Json -Depth 6 |
            Out-File (Join-Path $EvidenceDir 'registry-cleanup-controls.json')
        $parentIdentity.witness_status='INCOMPLETE'
        $parentIdentity.cleanup_negative_controls=$cleanupControlSummary.status
        $parentIdentity.cleanup_controls_attempted=$cleanupControlSummary.attempted
        $parentIdentity.cleanup_controls_executed=$cleanupControlSummary.selected_test_executed
        $parentIdentity.cleanup_controls_selected_tests_passed=$cleanupControlSummary.selected_test_passed
        $parentIdentity.cleanup_controls_verified=$cleanupControlSummary.native_controls_verified
        $parentIdentity.cleanup_controls_required=25
        $parentIdentity.cleanup_controls_missing=$cleanupPending
        $parentIdentity | ConvertTo-Json -Depth 8 |
            Out-File (Join-Path $EvidenceDir 'registry-witness-parent.json')
        if(-not $suiteVerified){
            throw "Cleanup negative-control suite remains fail-closed: $($cleanupControlSummary.native_controls_verified)/25 verified; failed $(@($controlFailures | ForEach-Object {$_.case}) -join ', '); missing $($cleanupPending -join ', ')"
        }
    } catch { $failure=$_ }
    finally {
        $cleanupComplete=$true
        foreach ($row in $created) {
            try {
                $kind=$row.key.GetValueKind($row.name)
                $value=$row.key.GetValue($row.name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                if ($kind -eq [Microsoft.Win32.RegistryValueKind]::String -and $value -ceq $row.value) {
                    $row.key.DeleteValue($row.name,$true)
                    [uint32]$kind=0; [uint32]$size=0
                    $status=[OrbitRegistryWitnessFixture]::RegQueryValueExW($row.key.Handle,$row.name,
                        [IntPtr]::Zero,[ref]$kind,[IntPtr]::Zero,[ref]$size)
                    if ($status -ne 2) { $cleanupComplete=$false }
                } else { $cleanupComplete=$false }
            } catch { $cleanupComplete=$false }
        }
        for ($index=$keys.Count-1; $index -ge 0; $index--) { $keys[$index].Dispose() }
        if ($null -ne $nonce) {
            $parentIdentity.cleanup_complete=$cleanupComplete
            $parentIdentity | ConvertTo-Json -Depth 5 | Out-File (Join-Path $EvidenceDir 'registry-witness-parent.json')
        }
    }
    if (-not $cleanupComplete) { throw 'Registry witness marker cleanup did not prove exact-name absence' }
    if ($null -ne $failure) { throw $failure }
    return
}
$hostExecutable = (Get-Process -Id $PID).Path
$env:ORBIT_TEST_POWERSHELL = $hostExecutable
$env:ORBIT_TEST_POWERSHELL_ID = "$($PSVersionTable.PSEdition):$($PSVersionTable.PSVersion)"
$env:ORBIT_FAKE_SECRET = 'parent-only-fake-secret'
$env:ORBIT_NATIVE_EVIDENCE_DIR = (Resolve-Path $EvidenceDir).Path
@{ executable = $hostExecutable; family = $PSVersionTable.PSEdition
   version = $PSVersionTable.PSVersion.ToString()
   sha256 = (Get-FileHash -Algorithm SHA256 $hostExecutable).Hash
   source = $env:GITHUB_SHA; scope = $(if($Group -eq 'RegistryDiagnostic'){'private fake-data diagnostic'}else{'initial LPAC production tracer'})
   runtime_capability_policy = $(if($Group -eq 'RegistryDiagnostic'){'test-only instrumentation plus registryRead, SE_GROUP_ENABLED'}else{'lpacInstrumentation only, SE_GROUP_ENABLED'})
   expected_total_capabilities = $(if($Group -eq 'RegistryDiagnostic'){2}else{1}); expected_network_capabilities = 0 } |
    ConvertTo-Json | Out-File (Join-Path $EvidenceDir 'powershell-identity.json')
Get-ComputerInfo -Property WindowsProductName, WindowsVersion, OsBuildNumber |
    Format-List | Out-File (Join-Path $EvidenceDir 'windows.txt')
whoami /all | Out-File (Join-Path $EvidenceDir 'identity.txt')
if ($Group -eq 'RegistryDiagnostic') {
    # No fake registry value may be created on a local/operator machine.
    $conditions = @{
        GITHUB_ACTIONS = 'true'; RUNNER_ENVIRONMENT = 'github-hosted'; RUNNER_OS = 'Windows'
        GITHUB_REF = 'refs/heads/codex/platform-first-run-windows-proof-20261105'
        ORBIT_REGISTRY_DIAGNOSTIC_FIXTURE = 'github-hosted-fake-data-only-v1'
    }
    foreach ($entry in $conditions.GetEnumerator()) {
        if ([Environment]::GetEnvironmentVariable($entry.Key) -cne $entry.Value) {
            throw 'Registry diagnostic requires its declared disposable Windows CI fixture'
        }
    }
    if ($env:GITHUB_RUN_ID -notmatch '^[0-9]+$' -or $env:GITHUB_SHA -notmatch '^[0-9a-f]{40}$') {
        throw 'Registry fixture run identity missing'
    }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class OrbitRegistryFixture {
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
 public static extern int RegQueryValueExW(SafeRegistryHandle key,string name,IntPtr reserved,
     out uint type,IntPtr data,ref uint size);
}
'@
    function FixtureHash([string]$value) {
        [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($value)))
    }
    $nonce = [guid]::NewGuid().ToString('N')
    $originalSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $env:ORBIT_PROBE_NONCE = $nonce
    $env:ORBIT_PROBE_ORIGINAL_SID = $originalSid
    $env:ORBIT_FAKE_SECRET = [guid]::NewGuid().ToString('N')
    $machineValue = [guid]::NewGuid().ToString('N')
    $userValue = [guid]::NewGuid().ToString('N')
    $env:ORBIT_PROBE_MACHINE_HASH = FixtureHash $machineValue
    $env:ORBIT_PROBE_USER_HASH = FixtureHash $userValue
    $ledger = [Collections.Generic.List[object]]::new()
    $keys = [Collections.Generic.List[Microsoft.Win32.RegistryKey]]::new()
    $fixture = [ordered]@{source=$env:GITHUB_SHA;run=$env:GITHUB_RUN_ID;nonce=$nonce
        original_user_sid=$originalSid;registry_view=64;scope='disposable fake-data measurement only'
        machine_key='HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
        original_user_key=('HKU\'+$originalSid+'\Environment')
        ordinary_user_support_proven=$false;production_policy_unchanged=$true;production_support_pass=$false
        protected_classes=@('process_credential','orbit_credential_file','persisted_machine_credential','persisted_original_user_credential')
        nonsensitive_class='public_configuration';cleanup_status='pending';measurement_status='incomplete'}
    $failure = $null
    try {
        $machineRoot = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
        $keys.Add($machineRoot)
        $usersRoot = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users,[Microsoft.Win32.RegistryView]::Registry64)
        $keys.Add($usersRoot)
        $machine = $machineRoot.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment',$true)
        $user = $usersRoot.OpenSubKey(($originalSid+'\Environment'),$true)
        if ($null -eq $machine -or $null -eq $user) { throw 'Required existing fixture keys missing' }
        $keys.Add($machine); $keys.Add($user)
        # Retain these exact key handles until identity-bound value cleanup.
        $definitions = @(
            @{key=$machine;name=('ORBIT_FAKE_MACHINE_'+$nonce);value=$machineValue;class='protected_machine_credential'},
            @{key=$user;name=('ORBIT_FAKE_USER_'+$nonce);value=$userValue;class='protected_original_user_credential'},
            @{key=$machine;name=('ORBIT_PUBLIC_CONFIG_'+$nonce);value='public-fixture-config';class='nonsensitive_configuration'},
            @{key=$user;name=('ORBIT_FAKE_WRITE_'+$nonce);value=('unchanged:'+$nonce);class='must_deny_write'}
        )
        foreach ($definition in $definitions) {
            [uint32]$kind = 0; [uint32]$bytes = 0
            $status = [OrbitRegistryFixture]::RegQueryValueExW($definition.key.Handle,
                $definition.name,[IntPtr]::Zero,[ref]$kind,[IntPtr]::Zero,[ref]$bytes)
            if ($status -ne 2) { throw "Nonce fixture value is not absent: Win32 status $status" }
            $ledger.Add($definition)
            $definition.key.SetValue($definition.name,$definition.value,[Microsoft.Win32.RegistryValueKind]::String)
            if ($definition.key.GetValueKind($definition.name) -ne [Microsoft.Win32.RegistryValueKind]::String -or
                $definition.key.GetValue($definition.name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) -cne $definition.value) {
                throw 'Fake value parent positive control failed'
            }
        }
        $fixture.parent_positive_controls = @($definitions | ForEach-Object {
            @{name=$_.name;class=$_.class;type='REG_SZ';sha256=(FixtureHash $_.value);read_write_control='passed'}
        })
        $fixture | ConvertTo-Json -Depth 8 | Out-File (Join-Path $EvidenceDir 'registry-fixture.json')
        # This feature/unit is absent from all default and non-test release builds.
        $case = 'process::windows::registry_probe_tests::registry_read_fake_data_measurement'
        $log = Join-Path $EvidenceDir 'registry-diagnostic.log'
        cargo +1.99.0 test --locked -p orbit-platform --features registry-diagnostic --lib $case -- --exact --test-threads=1 --nocapture 2>&1 |
            Tee-Object -FilePath $log
        $code = $LASTEXITCODE
        $report = Get-Content $log -Raw
        if ($code -ne 0) { throw "Registry measurement unit exited $code; retained evidence is not a production pass" }
        if ($report -notmatch ('(?m)^test '+[regex]::Escape($case)+' \.\.\. ok\r?$') -or
            $report -notmatch 'test result: ok\. 1 passed; 0 failed; 0 ignored;') {
            throw 'Exactly one real registry measurement case must execute'
        }
        $payload = Get-Content (Join-Path $EvidenceDir 'registry-probe-payload.json') -Raw | ConvertFrom-Json
        if ($payload.measurement_status -ne 'complete' -or $payload.production_support_pass -ne $false -or
            $payload.production_policy_unchanged -ne $true -or $payload.nonce -cne $nonce -or
            $payload.original_user_sid -cne $originalSid -or $payload.identity -cne $env:ORBIT_TEST_POWERSHELL_ID -or -not $payload.runtime -or -not $payload.module) {
            throw 'Registry measurement payload incomplete or incorrectly classified'
        }
        $required = @('private_credential_file','outside_write','process_credential','loopback','nonlocal',
            'dotnet_machine','dotnet_mapped_user','dotnet_original_user','provider_machine','provider_original_user',
            'public_configuration','original_user_registry_write','win32_machine','win32_mapped_user','win32_original_user')
        foreach ($id in $required) {
            $rows = @($payload.observations | Where-Object { $_.id -eq $id })
            if ($rows.Count -ne 1 -or $rows[0].status -in @('api_error','unavailable','failed')) {
                throw "Required registry measurement missing/unavailable: $id"
            }
            if ($rows[0].status -eq 'not_found' -and $id -notin @('dotnet_mapped_user','win32_mapped_user')) {
                throw "Known-present fake value was missing, not denied: $id"
            }
            if ($rows[0].status -eq 'readable' -and $rows[0].matches_fixture -ne $true) {
                throw 'Fake value identity/digest mismatch'
            }
        }
        $readable = @($payload.observations | Where-Object { $_.protected_credential -eq $true -and $_.status -eq 'readable' })
        $expectedBoundary = if ($readable.Count) { 'unresolved_exposed_persisted_credential' } else { 'no_exposure_observed' }
        if ($payload.credential_boundary_status -ne $expectedBoundary) { throw 'Protected credential exposure misclassified' }
        if ($user.GetValue(('ORBIT_FAKE_WRITE_'+$nonce)) -cne ('unchanged:'+$nonce)) { throw 'Confined registry write was not denied' }
        $fixture.measurement_status = 'complete'
        $fixture.credential_boundary_status = $expectedBoundary
        $fixture.executed_diagnostic_cases = 1
    } catch { $failure = $_; $fixture.failure = $_.Exception.ToString() }
    finally {
        $cleanup = $true
        foreach ($entry in $ledger) {
            try {
                $kind = $entry.key.GetValueKind($entry.name)
                $current = $entry.key.GetValue($entry.name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $allowed = @($entry.value)
                if ($entry.class -eq 'must_deny_write') { $allowed += ('child-change:'+$nonce) }
                if ($kind -eq [Microsoft.Win32.RegistryValueKind]::String -and $current -cin $allowed) {
                    $entry.key.DeleteValue($entry.name,$true)
                    [uint32]$remainingKind=0; [uint32]$remainingBytes=0
                    $deletedStatus=[OrbitRegistryFixture]::RegQueryValueExW($entry.key.Handle,
                        $entry.name,[IntPtr]::Zero,[ref]$remainingKind,[IntPtr]::Zero,[ref]$remainingBytes)
                    if($deletedStatus -ne 2){$cleanup=$false}
                } else { $cleanup=$false }
            } catch { $cleanup=$false }
        }
        foreach ($key in $keys) { $key.Dispose() }
        $fixture.cleanup_status = if ($cleanup) { 'verified_nonce_values_deleted_through_held_keys' } else { 'failed_preserved_unexpected_value' }
        if (-not $cleanup) { $fixture.measurement_status='incomplete' }
        $fixture | ConvertTo-Json -Depth 8 | Out-File (Join-Path $EvidenceDir 'registry-fixture.json')
        Remove-Item Env:ORBIT_PROBE_NONCE,Env:ORBIT_PROBE_ORIGINAL_SID,Env:ORBIT_PROBE_MACHINE_HASH,Env:ORBIT_PROBE_USER_HASH -ErrorAction SilentlyContinue
    }
    if ($null -ne $failure) { throw $failure }
    if (-not $cleanup) { throw 'Fake registry fixture cleanup incomplete' }
    return
}
# Read-only parent-side measurements precede every test child. Failure of this
# auxiliary diagnostic is recorded and does not skip the required native cases.
$etw = [ordered]@{
    provider = 'F90714A8-5509-434A-BF6D-B1624C8A19A2'; registration_mask = '0x00000800'
    query_status = 'not_run'; conversion_status = 'not_run'; derivation_status = 'not_run'
    comparison_status = 'unavailable'; comparison_kind = 'raw_ace_only_not_effective_access'
    source = $env:GITHUB_SHA; candidate = 'lpacInstrumentation'; diagnostic_grants_capability = $false
}
try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class OrbitEtwReadOnly {
    [DllImport("advapi32.dll", ExactSpelling=true)]
    public static extern uint EventAccessQuery(ref Guid guid, IntPtr buffer, ref uint size);
    [DllImport("kernelbase.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeriveCapabilitySidsFromName(string name, out IntPtr groups,
        out uint groupCount, out IntPtr capabilities, out uint capabilityCount);
    [DllImport("kernel32.dll", ExactSpelling=true)]
    public static extern IntPtr LocalFree(IntPtr pointer);
}
'@
    $guid = [guid]$etw.provider
    [uint32]$size = 0
    $codes = [System.Collections.Generic.List[uint32]]::new()
    $result = [OrbitEtwReadOnly]::EventAccessQuery([ref]$guid, [IntPtr]::Zero, [ref]$size)
    $codes.Add($result)
    $etw.query_codes = @($codes.ToArray())
    if (($result -ne 0 -and $result -ne 234) -or $size -eq 0 -or $size -gt 65536) {
        throw "EventAccessQuery sizing status=$result size=$size"
    }
    $descriptor = $null
    for ($attempt = 0; $attempt -lt 3; $attempt++) {
        $allocated = $size
        $buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal([int]$allocated)
        try {
            $result = [OrbitEtwReadOnly]::EventAccessQuery([ref]$guid, $buffer, [ref]$size)
            $codes.Add($result)
            $etw.query_codes = @($codes.ToArray())
            if ($result -eq 0) {
                if ($size -eq 0 -or $size -gt $allocated) { throw 'Invalid descriptor size' }
                $descriptor = [byte[]]::new($size)
                [Runtime.InteropServices.Marshal]::Copy($buffer, $descriptor, 0, [int]$size)
                break
            }
            if ($result -ne 234 -or $size -le $allocated -or $size -gt 65536) {
                throw "EventAccessQuery status=$result size=$size"
            }
        } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer) }
    }
    if ($null -eq $descriptor) { throw 'EventAccessQuery descriptor changed repeatedly' }
    $etw.query_status = 'success'
    [IO.File]::WriteAllBytes((Join-Path $EvidenceDir 'powershell-etw-provider.sd'), $descriptor)
    $etw.descriptor_sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($descriptor))
    try {
        $sd = [Security.AccessControl.RawSecurityDescriptor]::new($descriptor, 0)
        $etw.sddl = $sd.GetSddlForm([Security.AccessControl.AccessControlSections]::All)
        $etw.descriptor_control_flags = $sd.ControlFlags.ToString()
        $etw.null_dacl = $null -eq $sd.DiscretionaryAcl
        $etw.aces = @(
            foreach ($ace in $sd.DiscretionaryAcl) {
                $row = [ordered]@{ type = $ace.AceType.ToString(); flags = $ace.AceFlags.ToString() }
                if ($ace -is [Security.AccessControl.KnownAce]) {
                    $row.sid = $ace.SecurityIdentifier.Value
                    $row.mask = ('0x{0:X8}' -f $ace.AccessMask)
                    $row.registration_bit = ($ace.AccessMask -band 0x800) -eq 0x800
                }
                if ($ace -is [Security.AccessControl.QualifiedAce]) {
                    $row.qualifier = $ace.AceQualifier.ToString()
                }
                [pscustomobject]$row
            }
        )
        $etw.conversion_status = 'success'
    } catch { $etw.conversion_status = 'error'; $etw.conversion_error = $_.Exception.ToString() }
} catch { $etw.query_status = 'error'; $etw.query_error = $_.Exception.ToString() }
try {
    $groups = [IntPtr]::Zero; $capabilities = [IntPtr]::Zero
    [uint32]$groupCount = 0; [uint32]$capabilityCount = 0
    try {
        $derived = [OrbitEtwReadOnly]::DeriveCapabilitySidsFromName($etw.candidate,
            [ref]$groups, [ref]$groupCount, [ref]$capabilities, [ref]$capabilityCount)
        $deriveError = [Runtime.InteropServices.Marshal]::GetLastPInvokeError()
        $etw.derivation_return = $derived
        if (-not $derived) { throw "DeriveCapabilitySidsFromName error=$deriveError" }
        if ($groupCount -gt 32 -or $capabilityCount -gt 32) { throw 'Unexpected derived SID count' }
        $etw.candidate_groups = @(
            for ($i = 0; $i -lt $groupCount; $i++) {
                $pointer = [Runtime.InteropServices.Marshal]::ReadIntPtr($groups, $i * [IntPtr]::Size)
                [Security.Principal.SecurityIdentifier]::new($pointer).Value
            }
        )
        $etw.candidate_sids = @(
            for ($i = 0; $i -lt $capabilityCount; $i++) {
                $pointer = [Runtime.InteropServices.Marshal]::ReadIntPtr($capabilities, $i * [IntPtr]::Size)
                [Security.Principal.SecurityIdentifier]::new($pointer).Value
            }
        )
        if ($etw.conversion_status -eq 'success') {
            $etw.candidate_ace_comparison = @(
                foreach ($sid in $etw.candidate_sids) {
                    $matching = @($etw.aces | Where-Object { $_.sid -eq $sid })
                    [ordered]@{ sid = $sid; present = $matching.Count -gt 0
                        registration_allow_aces = @($matching | Where-Object {
                            $_.qualifier -eq 'AccessAllowed' -and $_.registration_bit
                        }); matching_aces = $matching }
                }
            )
            $etw.comparison_status = 'success'
        }
        $etw.derivation_status = 'success'
    } finally {
        foreach ($entry in @(@($groups, $groupCount), @($capabilities, $capabilityCount))) {
            $array = [IntPtr]$entry[0]; $count = [uint32]$entry[1]
            if ($array -ne [IntPtr]::Zero) {
                for ($i = 0; $i -lt $count; $i++) {
                    $pointer = [Runtime.InteropServices.Marshal]::ReadIntPtr($array, $i * [IntPtr]::Size)
                    [void][OrbitEtwReadOnly]::LocalFree($pointer)
                }
                [void][OrbitEtwReadOnly]::LocalFree($array)
            }
        }
    }
} catch { $etw.derivation_status = 'error'; $etw.derivation_error = $_.Exception.ToString() }
$etw | ConvertTo-Json -Depth 12 | Out-File (Join-Path $EvidenceDir 'powershell-etw-provider.json')
$log = Join-Path $EvidenceDir 'powershell-tracer.log'
cargo +1.99.0 test --locked -p orbit-platform --test windows_process -- --test-threads=1 --nocapture 2>&1 |
    Tee-Object -FilePath $log
$code = $LASTEXITCODE
if ($code -ne 0) { exit $code }
$required = @(
    'windows::ordinary_appcontainer_does_not_pass_lpac_access_probe',
    'windows::runtime_policy_rejects_missing_capability',
    'windows::runtime_policy_rejects_extra_capability',
    'windows::runtime_policy_rejects_internet_capability',
    'windows::runtime_policy_rejects_changed_attributes',
    'windows::powershell_lpac_reads_owned_resources_and_denies_ambient_authority',
    'windows::silent_powershell_deadline_observes_owned_completion',
    'windows::powershell_output_limit_observes_owned_completion'
)
$report = Get-Content $log -Raw
foreach ($case in $required) {
    if ($report -notmatch ('(?m)^test ' + [regex]::Escape($case) + ' \.\.\. ok\r?$')) {
        throw "Required native tracer did not pass: $case"
    }
}
if ($report -match '\b[1-9][0-9]* (ignored|filtered out)\b') { throw 'Native tracer cases were skipped' }
@{ required_cases = $required.Count; status = 'passed'; source = $env:GITHUB_SHA
   scope = 'initial tracer; full lifecycle still required' } |
    ConvertTo-Json | Out-File (Join-Path $EvidenceDir 'powershell-tracer.json')
