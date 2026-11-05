param(
    [ValidateSet('Foundation', 'Confinement', 'RegistryDiagnostic')]
    [string] $Group = 'Confinement',
    [string] $EvidenceDir = 'platform-results'
)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'Native Windows is required' }
New-Item -ItemType Directory -Force $EvidenceDir | Out-Null
$env:CARGO_BUILD_JOBS = '1'
$env:CARGO_TERM_COLOR = 'never'
$env:NO_COLOR = '1'
if ($Group -eq 'Foundation') {
    $log = Join-Path $EvidenceDir 'foundation.log'
    cargo +1.99.0 test --locked -p orbit-platform --lib --test windows_foundation -- --test-threads=1 2>&1 |
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
        'windows::shared_readers_coexist_but_exclude_writer',
        'fs::windows::tests::private_storage_works_without_admin_group_or_privileges',
        'fs::windows::tests::flush_failure_preserves_original_and_unpublished_candidate',
        'fs::windows::tests::prepublication_failure_restores_expected_original',
        'fs::windows::tests::postpublication_flush_failure_retains_original_backup',
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
