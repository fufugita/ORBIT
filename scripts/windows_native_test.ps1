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
   source = $env:GITHUB_SHA; scope = 'initial LPAC production tracer' } |
    ConvertTo-Json | Out-File (Join-Path $EvidenceDir 'powershell-identity.json')
Get-ComputerInfo -Property WindowsProductName, WindowsVersion, OsBuildNumber |
    Format-List | Out-File (Join-Path $EvidenceDir 'windows.txt')
whoami /all | Out-File (Join-Path $EvidenceDir 'identity.txt')
$log = Join-Path $EvidenceDir 'powershell-tracer.log'
cargo +1.99.0 test --locked -p orbit-platform --test windows_process -- --test-threads=1 --nocapture 2>&1 |
    Tee-Object -FilePath $log
$code = $LASTEXITCODE
if ($code -ne 0) { exit $code }
$required = @(
    'windows::ordinary_appcontainer_does_not_pass_lpac_access_probe',
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
