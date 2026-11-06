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
        optional_feature_timeout_seconds=20; collection_deadline_seconds=60
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
        $serviceQuery=ReadHostCim 'Win32_Service' @('Name','State','StartMode') (($serviceNames | ForEach-Object {"Name='$_'"}) -join ' OR ')
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
    cargo +1.99.0 test --locked --no-fail-fast -p orbit-platform --lib --test windows_foundation -- --test-threads=1 2>&1 |
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
        'windows::simultaneous_publication_preserves_the_only_successful_name'
    )
    if ($required.Count -ne 47 -or @($required | Select-Object -Unique).Count -ne 47) {
        throw "Foundation's exact required-name manifest must contain 47 unique cases; found $($required.Count)"
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
            if ($payload -notmatch '^(registry_witness_probe|registry_witness_parent_binding|registry_witness_helper_directory_access|registry_witness_helper_directory_descriptor|registry_witness_child_result|registry_witness_diagnostic|registry_witness_child_admission|registry_witness_child_complete|registry_witness_status|registry_witness_finalization|registry_witness_incomplete|registry_witness_setup_cleanup)(?: |$)') {
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
                if((WitnessField $record 'status') -cne '0' -or
                    (WitnessField $record 'observed') -cne 'true' -or
                    (WitnessField $record 'sha256') -notmatch '^[0-9A-Fa-f]{64}$'){throw "Parent marker control failed: $id"}
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
        $statusRecords=@($frames | Where-Object { $_ -match '^registry_witness_status(?: |$)' })
        if($statusRecords.Count -ne 1){throw "Expected exactly one registry witness status record (found $($statusRecords.Count))"}
        $statusRecord=$statusRecords[0]
        if((WitnessField $statusRecord 'witness_status') -cne 'INCOMPLETE'){
            throw 'Registry witness status was not explicitly INCOMPLETE'
        }
        $runStatus=WitnessField $statusRecord 'run_status'
        if($runStatus -ceq 'completed_partial'){
            WitnessExactFields $statusRecord @('witness_status','run_status')
        } elseif($runStatus -ceq 'FAILED'){
            WitnessExactFields $statusRecord @('witness_status','run_status','primary')
            throw "Registry witness failed before the intentional partial checkpoint: $(WitnessField $statusRecord 'primary')"
        } else {throw "Unknown registry witness run status: $runStatus"}
        if($code -eq 0) {
            throw "Partial registry witness did not fail closed with explicit INCOMPLETE evidence (exit $code)"
        }
        $missing=@($expected | Where-Object { -not $actual.Contains($_) })
        $openIds=@('lifetime/cleanup_absent')
        $missingKey=@($missing|Sort-Object) -join '|'
        $openKey=@($openIds|Sort-Object) -join '|'
        if($missingKey -cne $openKey){
            throw "Registry control set incomplete; only cleanup_absent may remain open (missing $($missing -join ', '))"
        }
        $parentIdentity.witness_status='INCOMPLETE_FAILED_partial_checkpoint'
        $parentIdentity.missing_probe_count=$missing.Count
        $parentIdentity.ordinary_user_support_proven=$false
        $parentIdentity | ConvertTo-Json -Depth 5 | Out-File (Join-Path $EvidenceDir 'registry-witness-parent.json')
        throw "Registry witness intentionally remains INCOMPLETE: exit=$code observed=$($actual.Count)/70 missing=$($missing.Count)"
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
