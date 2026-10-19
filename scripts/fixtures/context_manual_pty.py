#!/usr/bin/env python3
"""Exercise the real terminal after the Rust namespace guard has succeeded."""

import argparse
import codecs
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import selectors
import signal
import stat
import struct
import subprocess
import sys
import termios
import time

SCHEMA = 'orbit.context-manual-pty/v1'
MAX_OUTPUT = 2 * 1024 * 1024
MAX_BINARY = 1024 * 1024 * 1024
ROWS, COLUMNS = 50, 180


class Failed(Exception):
    pass


class NotRun(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise Failed(reason)


def metadata(value):
    return [value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns]


def checked_file(path, limit, mode, owner):
    before = os.lstat(path)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
            'file_type_or_link_count')
    require(before.st_uid == owner and stat.S_IMODE(before.st_mode) == mode,
            'file_owner_or_mode')
    require(0 <= before.st_size <= limit, 'file_size_bound')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        require(metadata(os.fstat(stream.fileno())) == metadata(before), 'file_identity_before_read')
        data = stream.read(limit + 1)
        require(len(data) == before.st_size, 'file_read_bound')
        require(metadata(os.fstat(stream.fileno())) == metadata(before), 'file_changed_during_read')
    require(metadata(os.lstat(path)) == metadata(before), 'file_path_changed')
    return data


def clear_source(home, session, owner):
    require(0 < len(session) <= 128 and all(character.isascii()
            and (character.isalnum() or character in '-_') for character in session),
            'clear_source_session_identity')
    directories = [home, home / 'sessions', home / 'context-history',
                   home / 'context-history' / session]
    identities = []
    for directory in directories:
        value = os.lstat(directory)
        require(directory.resolve(strict=True) == directory and stat.S_ISDIR(value.st_mode)
                and value.st_uid == owner and stat.S_IMODE(value.st_mode) == 0o700,
                'clear_source_directory_identity')
        identities.append(metadata(value))
    source = {
        'snapshot': checked_file(home / 'sessions' / (session + '.json'),
                                 64 * 1024 * 1024, 0o600, owner),
        'accounting': checked_file(home / 'context-history' / session / 'accounting.json',
                                   128 * 1024, 0o600, owner),
    }
    require([metadata(os.lstat(directory)) for directory in directories] == identities,
            'clear_source_directory_changed_during_read')
    return source


def clear_source_digests(source):
    return {name: {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
            for name, data in source.items()}


def clear_changed_fields(before, after):
    before, after = json.loads(before), json.loads(after)
    require(isinstance(before, dict) and isinstance(after, dict)
            and len(before) <= 32 and len(after) <= 32, 'clear_source_snapshot_object_bound')
    fields = sorted(before.keys() | after.keys())
    require(len(fields) <= 32 and all(0 < len(name) <= 64 and all(character.isascii()
            and (character.isalnum() or character == '_') for character in name)
            for name in fields), 'clear_source_field_name_bound')
    return [name for name in fields if (name in before) != (name in after)
            or before.get(name) != after.get(name)]


def private_guard():
    require(sys.flags.isolated == 1 and sys.flags.no_site == 1, 'python_isolation_flags')
    require(os.environ.get('ORBIT_ACTIVATION_ISOLATED') == '1'
            and os.environ.get('ORBIT_ACTIVATION_RUNNER_DEPTH') == '1', 'private_runner_controls')
    for name, namespace in [('ORBIT_ACTIVATION_PARENT_MOUNT_FD', 'mnt'),
                            ('ORBIT_ACTIVATION_PARENT_USER_FD', 'user')]:
        value = int(os.environ[name])
        require(0 <= value < 4096, 'namespace_descriptor_bound')
        parent = os.fstat(value)
        current = os.stat('/proc/self/ns/' + namespace)
        require((parent.st_dev, parent.st_ino) != (current.st_dev, current.st_ino),
                'private_namespace_identity')
    mounts = Path('/proc/self/mountinfo').read_text().splitlines()
    require(any(line.split()[4] == '/etc' and ' - tmpfs ' in line for line in mounts),
            'private_etc_tmpfs')
    root = Path(os.environ['ORBIT_ACTIVATION_ROOT'])
    require(root.is_absolute() and root.resolve(strict=True) == root
            and root.name.startswith('oc-'), 'private_root_identity')
    root_metadata = os.lstat(root)
    require(stat.S_ISDIR(root_metadata.st_mode) and stat.S_IMODE(root_metadata.st_mode) == 0o700,
            'private_root_mode')
    owner = root_metadata.st_uid
    marker = os.environ['ORBIT_ACTIVATION_MANAGED_MARKER']
    require(marker.startswith('ORBIT_ACTIVATION_MANAGED_') and len(marker) <= 128
            and all(character.isascii() and (character.isalnum() or character == '_')
                    for character in marker), 'private_managed_marker_shape')
    require(checked_file(Path('/etc/orbit/ORBIT.md'), 128, 0o600, owner) == marker.encode(),
            'private_managed_marker')
    require(len(list(Path('/etc/orbit').iterdir())) == 1, 'private_managed_directory')
    for name in ['HOME', 'TMPDIR', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME',
                 'XDG_STATE_HOME', 'XDG_RUNTIME_DIR']:
        path = Path(os.environ[name])
        require(path.is_absolute() and path != root and root in path.parents
                and path.resolve(strict=True) == path, 'private_user_path')
        value = os.lstat(path)
        require(stat.S_ISDIR(value.st_mode) and value.st_uid == owner
                and stat.S_IMODE(value.st_mode) == 0o700, 'private_user_path_mode')
    require(root in Path.cwd().parents, 'private_working_directory')
    for name in ['ORBIT_HOME', 'ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'ANTHROPIC_BASE_URL',
                 'OPENAI_BASE_URL', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
                 'http_proxy', 'https_proxy', 'all_proxy']:
        require(name not in os.environ, 'inherited_provider_setting')
    return root, owner


def dependencies(path, expected, owner, load=True):
    try:
        value = os.lstat(path)
    except FileNotFoundError:
        raise NotRun('private_pyte_dependency_root_missing') from None
    require(path.is_absolute() and path.resolve(strict=True) == path
            and stat.S_ISDIR(value.st_mode) and value.st_uid == owner
            and stat.S_IMODE(value.st_mode) == 0o700, 'dependency_root_identity')
    raw = checked_file(path / 'manifest.json', 32 * 1024, 0o400, owner)
    require(hashlib.sha256(raw).hexdigest() == expected, 'dependency_manifest_hash')
    manifest = json.loads(raw)
    require(manifest['schema'] == 'orbit.manual-pty-test-dependencies/v1'
            and manifest['packages'] == {'pyte': '0.8.2', 'wcwidth': '0.8.2'},
            'dependency_manifest_schema')
    entries = manifest['files']
    require(isinstance(entries, list) and len(entries) == 56, 'dependency_file_count')
    wanted, total = set(), 0
    for entry in entries:
        relative = entry['path']
        parts = Path(relative).parts
        require(not Path(relative).is_absolute() and len(parts) >= 2
                and parts[0] in ['pyte', 'wcwidth'] and all(part not in ['', '.', '..'] for part in parts)
                and relative not in wanted and relative.endswith('.py'), 'dependency_relative_path')
        wanted.add(relative)
        parent = path
        for part in parts[:-1]:
            parent = parent / part
            value = os.lstat(parent)
            require(stat.S_ISDIR(value.st_mode) and value.st_uid == owner
                    and stat.S_IMODE(value.st_mode) == 0o700, 'dependency_parent_identity')
        data = checked_file(path / relative, 512 * 1024, 0o400, owner)
        require(len(data) == entry['bytes'] and hashlib.sha256(data).hexdigest() == entry['sha256'],
                'dependency_file_hash')
        total += len(data)
    require(total == 1844069, 'dependency_total_bytes')
    actual, pending, directories = set(), [path], 0
    while pending:
        directory = pending.pop()
        directories += 1
        require(directories <= 8, 'dependency_directory_bound')
        with os.scandir(directory) as scanned:
            for item in scanned:
                value = item.stat(follow_symlinks=False)
                require(value.st_uid == owner, 'dependency_tree_owner')
                if stat.S_ISDIR(value.st_mode):
                    require(stat.S_IMODE(value.st_mode) == 0o700, 'dependency_directory_mode')
                    pending.append(Path(item.path))
                else:
                    require(stat.S_ISREG(value.st_mode), 'dependency_tree_file_type')
                    actual.add(str(Path(item.path).relative_to(path)))
                    require(len(actual) <= 57, 'dependency_tree_count_bound')
    require(actual == wanted | {'manifest.json'}, 'dependency_tree_exact_files')
    if not load:
        return None
    # -I -S prevents user-site and .pth processing. Only this verified tree is
    # added, after both the Rust guard and this independent guard have run.
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(path))
    try:
        import pyte
        import wcwidth
    except Exception:
        raise Failed('verified_dependency_import_failed') from None
    for module in [pyte, wcwidth]:
        require(path in Path(module.__file__).resolve(strict=True).parents,
                'dependency_import_origin')
    return pyte


def binary_fingerprint(path, owner):
    require(path.is_absolute() and path.resolve(strict=True) == path, 'binary_path_identity')
    before = os.lstat(path)
    require(stat.S_ISREG(before.st_mode) and before.st_uid == owner
            and before.st_mode & 0o111 and 0 < before.st_size <= MAX_BINARY,
            'binary_type_owner_or_size')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb', buffering=0) as stream:
        require(metadata(os.fstat(stream.fileno())) == metadata(before), 'binary_identity_before_read')
        hashed, count = hashlib.sha256(), 0
        while True:
            part = stream.read(1024 * 1024)
            if not part:
                break
            hashed.update(part)
            count += len(part)
            require(count <= before.st_size, 'binary_read_bound')
        require(count == before.st_size and metadata(os.fstat(stream.fileno())) == metadata(before),
                'binary_changed_during_read')
    require(metadata(os.lstat(path)) == metadata(before), 'binary_path_changed')
    return {'metadata': metadata(before), 'sha256': hashed.hexdigest()}


def run(args, report):
    root, owner = private_guard()
    report['private_guard'] = True
    for path in [args.home, args.workspace, args.post_marker.parent]:
        require(path.is_absolute() and root in path.parents and path.resolve(strict=True) == path,
                'fixture_path_outside_private_root')
    require(args.workspace == Path.cwd(), 'fixture_workspace_mismatch')
    require(not os.path.lexists(args.post_marker), 'provider_marker_already_exists')
    pyte = dependencies(args.dependency_root, args.manifest_sha256, owner)
    report['dependency_manifest_sha256'] = args.manifest_sha256
    before = binary_fingerprint(args.binary, owner)
    report['binary_sha256'] = before['sha256']
    clear_prelaunch = clear_source(args.home, args.session, owner) if args.mode == 'clear' else None
    screen = pyte.Screen(COLUMNS, ROWS)
    stream = pyte.Stream(screen)
    decoder = codecs.getincrementaldecoder('utf-8')('replace')
    master, slave = pty.openpty()
    process, selector = None, selectors.DefaultSelector()
    output, checks = bytearray(), []
    end = time.monotonic() + 18
    status = None
    try:
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', ROWS, COLUMNS, 0, 0))
        env = {name: os.environ[name] for name in ['HOME', 'TMPDIR', 'XDG_CONFIG_HOME',
               'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'XDG_RUNTIME_DIR']}
        env.update({'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                    'TERM': 'xterm-256color', 'COLORTERM': 'truecolor'})

        def child_setup():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        process = subprocess.Popen([str(args.binary), 'chat', '--tui', '--resume', args.session,
                                    '--bare', '--home', str(args.home)], cwd=args.workspace, env=env,
                                   stdin=slave, stdout=slave, stderr=slave, close_fds=True,
                                   preexec_fn=child_setup)
        os.close(slave)
        slave = -1
        require(os.getpgid(process.pid) == process.pid, 'owned_terminal_process_group')
        report['pty_started'] = True
        os.set_blocking(master, False)
        selector.register(master, selectors.EVENT_READ)

        def cells():
            return '\n'.join(screen.display)

        def pump():
            require(time.monotonic() < end, 'terminal_workflow_deadline')
            for _, _ in selector.select(min(0.05, max(0, end - time.monotonic()))):
                try:
                    part = os.read(master, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        part = b''
                    else:
                        raise
                if part:
                    output.extend(part)
                    require(len(output) <= MAX_OUTPUT, 'terminal_output_bound')
                    stream.feed(decoder.decode(part))
                else:
                    selector.unregister(master)
            require(selector.get_map() or process.poll() is None, 'terminal_closed_before_expected_cells')

        def wait_cells(name, predicate):
            while not predicate(cells()):
                require(process.poll() is None, 'terminal_exited_before_' + name)
                pump()
            require(bool(output), 'terminal_cells_without_output')
            checks.append(name)
            return cells()

        def send(data):
            require(process.poll() is None and os.getpgid(process.pid) == process.pid,
                    'terminal_input_owner_lost')
            require(os.write(master, data) == len(data), 'terminal_input_short_write')

        initial = wait_cells('initial_qualified_cells', lambda text:
                             'earlier cost unknown' in text and 'ctx unknown' in text)
        report['initial_cells_sha256'] = hashlib.sha256(initial.encode()).hexdigest()
        clear_barrier = None
        if args.mode == 'clear':
            # The actual Initial view is the causal barrier. This capture must
            # finish before the first /clear key is sent; prelaunch differences
            # remain diagnostic evidence, never an automatic allowed mutation.
            clear_barrier = clear_source(args.home, args.session, owner)
            report['clear_source_barrier'] = {
                'phase': 'after_initial_before_clear',
                'prelaunch': clear_source_digests(clear_prelaunch),
                'before_clear': clear_source_digests(clear_barrier),
                'startup_changed_fields': clear_changed_fields(clear_prelaunch['snapshot'],
                                                               clear_barrier['snapshot']),
            }
            checks.append('old_source_captured_after_initial_before_clear')
        send(b'/clear\r' if args.mode == 'clear' else b'/compact\r')
        if args.mode == 'clear':
            terminal = wait_cells('fresh_identity_known_zero_cells', lambda text:
                                  '$0.0000' in text and 'ctx unknown' in text
                                  and 'earlier cost unknown' not in text and 'bill unavailable' not in text
                                  and 'New session' in text and 'Ask ORBIT, or type / for commands' in text
                                  and 'ready' in text and all(marker not in text for marker in
                                      ['old user', 'old answer', 'exact recent question', 'exact recent answer',
                                       'a' * 32, 'u' * 32]))
            checks.append('fresh_clear_view_without_old_source_cells')
            require(not os.path.lexists(args.post_marker), 'clear_made_provider_request')
            checks.append('clear_no_provider_post')
            cleared_source = clear_source(args.home, args.session, owner)
            report['clear_source_after_clear'] = clear_source_digests(cleared_source)
            report['clear_source_after_clear_changed_fields'] = clear_changed_fields(
                clear_barrier['snapshot'], cleared_source['snapshot'])
            report['clear_source_preserved_after_clear'] = cleared_source == clear_barrier
            require(report['clear_source_preserved_after_clear'],
                    'clear_changed_old_source_after_initial_barrier')
            checks.append('old_source_barrier_bytes_preserved_after_clear')
        else:
            while not os.path.lexists(args.post_marker):
                require(process.poll() is None, 'terminal_exited_before_provider_post')
                pump()
            require(checked_file(args.post_marker, 64, 0o600, owner) == b'observed-provider-post\n',
                    'provider_post_marker')
            checks.append('actual_provider_post_observed')
            if args.mode == 'escape':
                wait_cells('admitted_bill_unavailable_cells', lambda text: 'bill unavailable' in text)
                send(b'\x1b')
                terminal = wait_cells('cancelled_uncertain_terminal_cells', lambda text:
                                      'compaction accounting is uncertain' in text
                                      and 'accounting uncertain' in text)
            else:
                terminal = wait_cells('completed_manual_terminal_cells', lambda text:
                                      'context compacted' in text and 'earlier cost unknown' in text
                                      and 'ctx unknown' in text)
        report['terminal_cells'] = terminal
        send(b'\x03')
        wait_cells('operator_quit_card_cells', lambda text: 'QUIT ORBIT?' in text)
        send(b'y')
        while process.poll() is None:
            require(time.monotonic() < end, 'terminal_exit_deadline')
            if selector.get_map():
                for _, _ in selector.select(0.05):
                    try:
                        part = os.read(master, 65536)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                        part = b''
                    if part:
                        output.extend(part)
                        require(len(output) <= MAX_OUTPUT, 'terminal_output_bound')
                    else:
                        selector.unregister(master)
            else:
                process.wait(timeout=max(0.01, end - time.monotonic()))
        status = process.wait(timeout=1)
        require(status == 0, 'terminal_exit_status')
        # Include all final terminal bytes in the same cap/hash, rather than
        # ending capture when the leader exits with data still in the PTY.
        while selector.get_map():
            require(time.monotonic() < end, 'terminal_final_drain_deadline')
            for _, _ in selector.select(0.05):
                try:
                    part = os.read(master, 65536)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    part = b''
                if part:
                    output.extend(part)
                    require(len(output) <= MAX_OUTPUT, 'terminal_output_bound')
                else:
                    selector.unregister(master)
        report.update({'process_exit': status, 'process_reaped': True,
                       'output_bytes': len(output), 'output_sha256': hashlib.sha256(output).hexdigest(),
                       'cell_checks': checks, 'cells_observed': True})
        if args.mode == 'clear':
            quit_source = clear_source(args.home, args.session, owner)
            report['clear_source_after_quit'] = clear_source_digests(quit_source)
            report['clear_source_after_quit_changed_fields'] = clear_changed_fields(
                clear_barrier['snapshot'], quit_source['snapshot'])
            report['clear_source_preserved_after_quit'] = quit_source == clear_barrier
            require(report['clear_source_preserved_after_quit'],
                    'quit_changed_old_source_after_initial_barrier')
            checks.append('old_source_barrier_bytes_preserved_after_quit')
    finally:
        selector.close()
        if process is not None:
            # Signal only the still-live leader's own group, before reaping.
            if process.poll() is None:
                require(os.getpgid(process.pid) == process.pid, 'cleanup_process_group_identity')
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait(timeout=3)
            report['owned_process_cleanup'] = True
        os.close(master)
        if slave >= 0:
            os.close(slave)
        report['binary_unchanged'] = binary_fingerprint(args.binary, owner) == before
        require(report['binary_unchanged'], 'binary_changed_after_terminal')
        try:
            dependencies(args.dependency_root, args.manifest_sha256, owner, load=False)
        except NotRun:
            raise Failed('dependency_tree_disappeared_after_terminal') from None
        report['dependency_tree_reverified'] = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--home', type=Path, required=True)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--session', required=True)
    parser.add_argument('--post-marker', type=Path, required=True)
    parser.add_argument('--dependency-root', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--mode', choices=['success', 'escape', 'clear'], required=True)
    args = parser.parse_args()
    report = {'schema': SCHEMA, 'mode': args.mode, 'status': 'INFRA_FAILURE',
              'pty_started': False, 'cells_observed': False}
    result = 1
    try:
        run(args, report)
        report['status'] = 'TEST_PASSED'
        result = 0
    except NotRun as error:
        report.update({'status': 'NOTRUN', 'reason': str(error)})
        result = 77
    except (Failed, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        # Never dump arbitrary exception text or a raw terminal stream.
        report['reason'] = str(error) if isinstance(error, Failed) else type(error).__name__
    print(json.dumps(report, sort_keys=True), flush=True)
    return result


if __name__ == '__main__':
    raise SystemExit(main())
