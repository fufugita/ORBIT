#!/usr/bin/env python3
"""Observe one real plain approval, then signal its owned terminal process."""

import argparse
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

SCHEMA = 'orbit.context-plain-approval-pty/v1'
MAX_OUTPUT = 2 * 1024 * 1024
MAX_BINARY = 1024 * 1024 * 1024
PROMPT = b'approval needed: Bash'
STARTUP = b'type /help for commands, exit to quit'
INTENT = b'request the one approval fixture command\n'


class Failed(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise Failed(reason)


def metadata(value):
    return [value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns]


def checked_file(path, limit, owner, mode=0o600):
    before = os.lstat(path)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_uid == owner and stat.S_IMODE(before.st_mode) == mode
            and 0 <= before.st_size <= limit, 'private_file_identity_or_bound')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        require(metadata(os.fstat(stream.fileno())) == metadata(before), 'file_open_identity')
        data = stream.read(limit + 1)
        require(len(data) == before.st_size
                and metadata(os.fstat(stream.fileno())) == metadata(before), 'file_read_identity')
    require(metadata(os.lstat(path)) == metadata(before), 'file_path_identity')
    return data


def private_guard():
    # Only standard-library imports precede this independent inherited-FD guard.
    # No terminal, dependency, provider, config or snapshot is opened before it.
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
    value = os.lstat(root)
    require(stat.S_ISDIR(value.st_mode) and stat.S_IMODE(value.st_mode) == 0o700,
            'private_root_mode')
    owner = value.st_uid
    marker = os.environ['ORBIT_ACTIVATION_MANAGED_MARKER']
    require(marker.startswith('ORBIT_ACTIVATION_MANAGED_') and len(marker) <= 128
            and all(character.isascii() and (character.isalnum() or character == '_')
                    for character in marker), 'private_managed_marker_shape')
    require(checked_file(Path('/etc/orbit/ORBIT.md'), 128, owner) == marker.encode(),
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


def binary_fingerprint(path, owner):
    require(path.is_absolute() and path.resolve(strict=True) == path, 'binary_path_identity')
    before = os.lstat(path)
    require(stat.S_ISREG(before.st_mode) and before.st_uid == owner
            and before.st_mode & 0o111 and 0 < before.st_size <= MAX_BINARY,
            'binary_type_owner_or_size')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb', buffering=0) as stream:
        require(metadata(os.fstat(stream.fileno())) == metadata(before), 'binary_open_identity')
        hashed, count = hashlib.sha256(), 0
        while True:
            part = stream.read(1024 * 1024)
            if not part:
                break
            hashed.update(part)
            count += len(part)
            require(count <= before.st_size, 'binary_read_bound')
        require(count == before.st_size and metadata(os.fstat(stream.fileno())) == metadata(before),
                'binary_read_identity')
    require(metadata(os.lstat(path)) == metadata(before), 'binary_path_changed')
    return {'metadata': metadata(before), 'sha256': hashed.hexdigest()}


def publish_control(directory, name, data):
    staged = directory / ('.' + name + '.pending')
    descriptor = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        require(stream.write(data) == len(data), 'control_short_write')
        stream.flush()
    require(not os.path.lexists(directory / name), 'control_target_already_exists')
    # Each name has one fixture-owned producer; publish only complete bytes to
    # the other process. This is a private test barrier, not a product writer.
    os.rename(staged, directory / name)


def group_members(group):
    # Read only this private PID namespace. The exact unreaped leader retains
    # the group identity until cleanup/reap, so its numeric PID cannot be reused.
    found, count = [], 0
    for entry in os.scandir('/proc'):
        if not entry.name.isdigit():
            continue
        count += 1
        require(count <= 4096, 'private_process_count_bound')
        try:
            with open('/proc/' + entry.name + '/stat', 'rb') as stream:
                raw = stream.read(4097)
            require(len(raw) <= 4096, 'private_process_stat_bound')
            fields = raw[raw.rindex(b')') + 2:].split()
            if int(fields[2]) == group:
                found.append(int(entry.name))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return sorted(found)


def direct_children(pid):
    found = set()
    tasks = list(Path('/proc/' + str(pid) + '/task').iterdir())
    require(0 < len(tasks) <= 128, 'owned_thread_count_bound')
    for task in tasks:
        try:
            with open(task / 'children', 'rb') as stream:
                raw = stream.read(4097)
        except FileNotFoundError:
            continue
        require(len(raw) <= 4096, 'owned_children_read_bound')
        found.update(int(value) for value in raw.split())
        require(len(found) <= 128, 'owned_child_count_bound')
    return sorted(found)


def run(args, report):
    root, owner = private_guard()
    report['private_guard'] = True
    for path in [args.home, args.workspace, args.control_dir]:
        require(path.is_absolute() and root in path.parents and path.resolve(strict=True) == path,
                'fixture_path_outside_private_root')
        value = os.lstat(path)
        require(stat.S_ISDIR(value.st_mode) and value.st_uid == owner
                and stat.S_IMODE(value.st_mode) == 0o700, 'fixture_path_mode')
    require(args.workspace == Path.cwd(), 'fixture_workspace_mismatch')
    require(not list(args.control_dir.iterdir()), 'control_directory_not_empty')
    require(0 < len(args.session) <= 128 and all(character.isascii()
            and (character.isalnum() or character in '-_') for character in args.session),
            'session_identity')
    before = binary_fingerprint(args.binary, owner)
    test_before = binary_fingerprint(args.test_binary, owner)
    report.update({'binary_sha256': before['sha256'], 'test_binary_sha256': test_before['sha256']})
    master, slave = pty.openpty()
    process, selector = None, selectors.DefaultSelector()
    output, status = bytearray(), None
    deadline = time.monotonic() + 25
    original_flags = termios.tcgetattr(slave)
    original_window = fcntl.ioctl(slave, termios.TIOCGWINSZ, b'\0' * 8)
    signalled, reaped = False, False
    try:
        # Retain BOTH ends through actual process exit. No artificial stdin EOF
        # or terminal HUP can rescue a broken approval cancellation boundary.
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 50, 180, 0, 0))
        require(os.isatty(slave), 'slave_not_tty')
        env = {name: os.environ[name] for name in ['HOME', 'TMPDIR', 'XDG_CONFIG_HOME',
               'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'XDG_RUNTIME_DIR']}
        env.update({'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                    'TERM': 'dumb', 'NO_COLOR': '1'})

        def child_setup():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        process = subprocess.Popen([str(args.binary), 'chat', '--no-tui', '--resume', args.session,
                                    '--bare', '--home', str(args.home)], cwd=args.workspace, env=env,
                                   stdin=slave, stdout=slave, stderr=slave, close_fds=True,
                                   preexec_fn=child_setup)
        require(os.getpgid(process.pid) == process.pid, 'owned_terminal_process_group')
        require(os.stat('/proc/' + str(process.pid) + '/fd/0').st_rdev == os.fstat(slave).st_rdev,
                'actual_child_stdin_tty_identity')
        report['pty_started'] = True
        os.set_blocking(master, False)
        selector.register(master, selectors.EVENT_READ)

        def peek_exit():
            require(process.returncode is None, 'child_reaped_before_boundary')
            return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)

        def live():
            require(peek_exit() is None and os.getpgid(process.pid) == process.pid,
                    'owned_unreaped_terminal_not_live')

        def control():
            path = args.control_dir / 'signal'
            if not os.path.lexists(path):
                return None
            value = checked_file(path, 64, owner)
            require(value in [b'send-owned-sigterm\n', b'abort-owned-fixture\n'], 'invalid_control')
            require(value != b'abort-owned-fixture\n', 'parent_aborted_fixture')
            return value

        def pump():
            require(time.monotonic() < deadline, 'terminal_workflow_deadline')
            control()
            for _, _ in selector.select(min(0.02, max(0, deadline - time.monotonic()))):
                try:
                    data = os.read(master, 65536)
                except OSError as error:
                    if error.errno not in [errno.EAGAIN, errno.EWOULDBLOCK]:
                        raise
                    data = b''
                if data:
                    output.extend(data)
                    require(len(output) <= MAX_OUTPUT, 'terminal_output_bound')
            if peek_exit() is None:
                require(group_members(process.pid) == [process.pid], 'unexpected_tool_child_process')
                require(not direct_children(process.pid), 'unexpected_child_in_another_process_group')

        def wait_output(predicate, reason):
            while not predicate(bytes(output)):
                live()
                pump()
            live()
            require(bool(output), reason)

        wait_output(lambda data: STARTUP in data, 'missing_actual_plain_startup')
        require(os.write(master, INTENT) == len(INTENT), 'intent_short_write')
        report['intent_written'] = True
        wait_output(lambda data: PROMPT in data and b'y allow once,' in data and data.endswith(b'n deny: '),
                    'missing_actual_approval_prompt')

        def waiting_in_input():
            live()
            raw = checked_proc_syscall(process.pid)
            # Linux syscall numbers are architecture-specific; root passes the
            # actual libc constants compiled for this fixture's target.
            return raw.split(maxsplit=1)[0] in args.poll_syscall

        while not waiting_in_input():
            pump()
        require(termios.tcgetattr(slave) == original_flags, 'plain_approval_changed_terminal_flags')
        require(group_members(process.pid) == [process.pid], 'approval_spawned_tool_child')
        require(not direct_children(process.pid), 'approval_spawned_separate_tool_child')
        report.update({'actual_approval_prompt': True, 'actual_input_poll': True,
                       'actual_stdin_tty': True, 'no_tool_child_at_approval': True})
        publish_control(args.control_dir, 'ready.json', json.dumps({
            'schema': SCHEMA, 'boundary': 'actual_plain_approval_input_poll',
            'binary_sha256': before['sha256'], 'test_binary_sha256': test_before['sha256'],
            'cli_pid': process.pid, 'output_bytes': len(output),
            'output_sha256': hashlib.sha256(output).hexdigest(),
        }, sort_keys=True).encode())
        # Rust now checks the actual SessionLease Busy, settled known accounting
        # and durable ToolIntent before permitting this one signal.
        while control() is None:
            live()
            pump()
        live()
        while not waiting_in_input():
            pump()
        require(group_members(process.pid) == [process.pid], 'tool_child_before_signal')
        require(not direct_children(process.pid), 'separate_tool_child_before_signal')
        os.kill(process.pid, signal.SIGTERM)
        signalled = True
        report['sigterm_delivered_to_owned_unreaped_cli'] = True
        while peek_exit() is None:
            pump()
        # The unreaped leader still reserves PID/group identity during this
        # positive no-descendant check; no kill targets a recycled PID.
        require(group_members(process.pid) == [process.pid], 'owned_group_descendant_after_exit')
        status = process.wait(timeout=1)
        reaped = True
        report.update({'process_reaped': True, 'process_exit': status,
                       'pty_held_through_exit': os.isatty(slave) and os.isatty(master),
                       'terminal_flags_unchanged': termios.tcgetattr(slave) == original_flags,
                       'no_tool_child_after_exit': True})
        # A held slave prevents EOF, so drain until nonblocking EAGAIN rather
        # than closing a terminal endpoint to make the command terminate.
        while True:
            require(time.monotonic() < deadline, 'terminal_final_drain_deadline')
            try:
                data = os.read(master, 65536)
            except OSError as error:
                if error.errno in [errno.EAGAIN, errno.EWOULDBLOCK]:
                    break
                raise
            require(bool(data), 'terminal_eof_with_held_slave')
            output.extend(data)
            require(len(output) <= MAX_OUTPUT, 'terminal_output_bound')
        publish_control(args.control_dir, 'pty.bin', bytes(output))
        report.update({'output_bytes': len(output), 'output_sha256': hashlib.sha256(output).hexdigest(),
                       'approval_answers_written': 0, 'input_bytes_written': len(INTENT)})
        require(report['pty_held_through_exit'] and report['terminal_flags_unchanged'],
                'terminal_lifetime_or_flags')
        require(status == 143, 'approval_did_not_exit_normally143')
    finally:
        selector.close()
        if process is not None:
            if not reaped:
                # The exact unreaped leader reserves the group even if it has
                # just become a zombie. Kill only this positively owned group.
                require(process.returncode is None and os.getpgid(process.pid) == process.pid,
                        'cleanup_unreaped_group_identity')
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=3)
            report['owned_process_cleanup'] = True
            require(not group_members(process.pid), 'owned_process_group_leak')
        # Restore the fixture's window and compare every termios field; the CLI
        # must already have left flags exact before this fixture cleanup.
        fcntl.ioctl(slave, termios.TIOCSWINSZ, original_window)
        require(termios.tcgetattr(slave) == original_flags, 'terminal_flags_not_restored')
        os.close(master)
        os.close(slave)
        report['terminal_fds_closed'] = True
        report['binary_unchanged'] = binary_fingerprint(args.binary, owner) == before
        report['test_binary_unchanged'] = binary_fingerprint(args.test_binary, owner) == test_before
        require(report['binary_unchanged'] and report['test_binary_unchanged'], 'binary_changed')
        report['signal_count'] = int(signalled)


def checked_proc_syscall(pid):
    with open('/proc/' + str(pid) + '/syscall', 'rb') as stream:
        raw = stream.read(1025)
    require(0 < len(raw) <= 1024, 'owned_syscall_read_bound')
    return raw.decode('ascii')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--test-binary', type=Path, required=True)
    parser.add_argument('--home', type=Path, required=True)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--control-dir', type=Path, required=True)
    parser.add_argument('--session', required=True)
    parser.add_argument('--poll-syscall', action='append', required=True)
    args = parser.parse_args()
    require(1 <= len(args.poll_syscall) <= 2 and all(value.isdecimal() for value in args.poll_syscall),
            'poll_syscall_argument')
    report = {'schema': SCHEMA, 'status': 'INFRA_FAILURE', 'pty_started': False,
              'actual_approval_prompt': False}
    result = 1
    try:
        run(args, report)
        report['status'] = 'TEST_PASSED'
        result = 0
    except (Failed, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        # No arbitrary exception body, terminal stream or source data on stdout.
        report['reason'] = str(error) if isinstance(error, Failed) else type(error).__name__
    print(json.dumps(report, sort_keys=True), flush=True)
    return result


if __name__ == '__main__':
    raise SystemExit(main())
