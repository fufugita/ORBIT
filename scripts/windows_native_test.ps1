param(
    [ValidateSet('Foundation', 'Confinement')]
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
   source = $env:GITHUB_SHA; scope = 'initial LPAC production tracer'
   runtime_capability_policy = 'lpacInstrumentation only, SE_GROUP_ENABLED'
   expected_total_capabilities = 1; expected_network_capabilities = 0 } |
    ConvertTo-Json | Out-File (Join-Path $EvidenceDir 'powershell-identity.json')
Get-ComputerInfo -Property WindowsProductName, WindowsVersion, OsBuildNumber |
    Format-List | Out-File (Join-Path $EvidenceDir 'windows.txt')
whoami /all | Out-File (Join-Path $EvidenceDir 'identity.txt')
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
