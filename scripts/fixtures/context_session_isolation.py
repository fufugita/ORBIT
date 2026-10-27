#!/usr/bin/env python3
"""Run session integration tests with private system instructions and user state."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

SCHEMA = 'orbit.context-session-isolation/v1'
STAGE = 'orbit.context-session-isolation-stage/v1'
MAX_BINARY = 1024 * 1024 * 1024
MAX_OUTPUT = 2 * 1024 * 1024
MAX_CLEANUP_ENTRIES = 5000
EXCERPT = 16 * 1024


class NotRun(Exception):
    pass


class Failed(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Failed(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def metadata(value):
    return [value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns]


def managed_fingerprint():
    try:
        return metadata(os.lstat('/etc/orbit/ORBIT.md'))
    except FileNotFoundError:
        return None
    except OSError:
        raise Failed('host_managed_metadata_unavailable') from None


def verify_binary(path, expected=None):
    before = os.lstat(path)
    require(stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode), 'binary_regular_file')
    require(before.st_uid == os.getuid() and before.st_mode & 0o111, 'binary_owner_or_executable')
    require(0 < before.st_size <= MAX_BINARY, 'binary_size_bound')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb', buffering=0) as stream:
        require(metadata(os.fstat(stream.fileno())) == metadata(before), 'binary_changed_before_read')
        hashed = hashlib.sha256()
        count = 0
        while True:
            part = stream.read(1024 * 1024)
            if not part:
                break
            count += len(part)
            require(count <= MAX_BINARY, 'binary_read_bound')
            hashed.update(part)
        require(count == before.st_size and metadata(os.fstat(stream.fileno())) == metadata(before), 'binary_changed_during_read')
    require(metadata(os.lstat(path)) == metadata(before), 'binary_path_changed')
    actual = hashed.hexdigest()
    require(expected is None or actual == expected, 'binary_hash_mismatch')
    return {'metadata': metadata(before), 'sha256': actual}


def private_write(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def environment(root):
    user = root / 'user'
    return {
        'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
        'HOME': str(user), 'USER': 'orbit-fixture', 'LOGNAME': 'orbit-fixture',
        'TMPDIR': str(root / 'tmp'), 'XDG_CONFIG_HOME': str(user / 'config'),
        'XDG_CACHE_HOME': str(user / 'cache'), 'XDG_DATA_HOME': str(user / 'data'),
        'XDG_STATE_HOME': str(user / 'state'), 'XDG_RUNTIME_DIR': str(user / 'runtime'),
        'TERM': 'dumb', 'NO_COLOR': '1',
    }


def command(arguments, env, cwd, timeout, pass_fds=(), lifecycle=None):
    if lifecycle is not None:
        require(lifecycle == {'spawn_attempted': False, 'reaped': False}, 'namespace_lifecycle_initial_state')
        lifecycle['spawn_attempted'] = True
    process = subprocess.Popen(arguments, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True, pass_fds=pass_fds)
    selector = selectors.DefaultSelector()
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    end = time.monotonic() + timeout
    try:
        for name, pipe in [('stdout', process.stdout), ('stderr', process.stderr)]:
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        while selector.get_map():
            require(time.monotonic() < end, 'subprocess_deadline')
            for key, _ in selector.select(min(0.1, max(0.0, end-time.monotonic()))):
                part = os.read(key.fileobj.fileno(), 65536)
                if not part:
                    selector.unregister(key.fileobj)
                else:
                    output[key.data].extend(part)
                    require(sum(map(len, output.values())) <= MAX_OUTPUT, 'subprocess_output_bound')
        code = process.wait(timeout=max(0.1, end-time.monotonic()))
        return code, bytes(output['stdout']), bytes(output['stderr'])
    finally:
        selector.close()
        # Kill only our still-live leader's exact owned process group. A
        # completed leader is not signalled after reaping/PID reuse. The PID1
        # namespace process exiting also terminates any leaked inner fixtures.
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait(timeout=5)
        if lifecycle is not None:
            lifecycle['reaped'] = True
        process.stdout.close()
        process.stderr.close()


def fixture_root_identity(info):
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700, 'owned_fixture_root_type_owner_mode')
    return (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode))


def cleanup_owned_fixture(root, expected, lifecycle):
    require(expected is not None, 'owned_fixture_original_identity_missing')
    require(lifecycle['spawn_attempted'] is False or lifecycle['reaped'] is True,
            'owned_namespace_reaping_unproven')
    require(fixture_root_identity(root.lstat()) == expected, 'owned_fixture_root_changed')
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    walker = None
    count = 0
    try:
        require(fixture_root_identity(os.fstat(descriptor)) == expected, 'owned_fixture_root_fd_changed')
        def reject_walk_error(error):
            raise error
        walker = os.fwalk('.', topdown=True, onerror=reject_walk_error,
                          follow_symlinks=False, dir_fd=descriptor)
        for _base, directories, files, current in walker:
            require(os.fstat(current).st_uid == expected[2], 'owned_fixture_directory_owner')
            for name in directories + files:
                count += 1
                require(count <= MAX_CLEANUP_ENTRIES, 'owned_fixture_entry_bound')
                require(os.stat(name, dir_fd=current, follow_symlinks=False).st_uid == expected[2],
                        'owned_fixture_entry_owner')
        require(fixture_root_identity(os.fstat(descriptor)) == expected, 'owned_fixture_root_fd_changed')
    finally:
        try:
            if walker is not None:
                walker.close()
        finally:
            os.close(descriptor)
    # The walk is a bounded preflight, not an atomic proof of an immutable tree.
    require(fixture_root_identity(root.lstat()) == expected, 'owned_fixture_root_changed')
    require(getattr(shutil.rmtree, 'avoids_symlink_attacks', False) is True,
            'owned_fixture_safe_rmtree_unavailable')
    shutil.rmtree(root)
    require(not root.exists() and not root.is_symlink(), 'owned_fixture_cleanup_incomplete')
    return count


def isolate(args, root, env):
    parent_mount = os.fstat(args.parent_mount_fd)
    parent_user = os.fstat(args.parent_user_fd)
    own_mount = os.stat('/proc/self/ns/mnt')
    own_user = os.stat('/proc/self/ns/user')
    require('mnt:[' + str(parent_mount.st_ino) + ']' == args.parent_mount, 'original_mount_descriptor_changed')
    if (own_mount.st_dev, own_mount.st_ino) == (parent_mount.st_dev, parent_mount.st_ino):
        raise Failed('private_mount_namespace_not_proven')
    if (own_user.st_dev, own_user.st_ino) == (parent_user.st_dev, parent_user.st_ino):
        raise Failed('private_user_namespace_not_proven')
    if os.getpid() != 1 or os.getppid() != 0 or os.getuid() != 0:
        raise Failed('private_pid_user_namespace_not_proven')
    proof = {'distinct_mount_before_mounts': True, 'distinct_user_before_mounts': True,
             'pid1_uid0_before_mounts': True, 'original_namespaces_pinned_by_fds': True}
    for arguments in [
        ['/usr/bin/mount', '--make-rprivate', '/'],
        ['/usr/bin/mount', '-t', 'proc', 'proc', '/proc'],
        ['/usr/bin/mount', '-t', 'tmpfs', '-o', 'mode=755,size=65536', 'orbit-test-etc', '/etc'],
    ]:
        try:
            code, _, stderr = command(arguments, env, root, 5)
        except FileNotFoundError:
            raise NotRun('mount_tool_unavailable') from None
        if code:
            if any(term in stderr.lower() for term in [b'operation not permitted', b'permission denied', b'not supported', b'must be superuser']):
                raise NotRun('private_mount_capability_unavailable')
            raise Failed('private_mount_setup_failed')
    require(os.stat('/proc/self/ns/mnt').st_ino == own_mount.st_ino, 'mount_namespace_changed')
    marker = 'ORBIT_ACTIVATION_MANAGED_' + args.nonce
    Path('/etc/orbit').mkdir(mode=0o700)
    private_write(Path('/etc/orbit/ORBIT.md'), marker.encode())
    require(Path('/etc/orbit/ORBIT.md').read_text() == marker, 'private_marker_mismatch')
    mounts = Path('/proc/self/mountinfo').read_text().splitlines()
    require(any(line.split()[4] == '/etc' and ' - tmpfs ' in line for line in mounts), 'private_etc_tmpfs_missing')
    proof.update({'private_proc': True, 'private_etc_tmpfs': True, 'synthetic_managed_marker': True})
    # Do not close original descriptors here: the real test checks those same
    # pinned identities. Explicit pass_fds retains them across its exec.
    env.update({
        'ORBIT_ACTIVATION_ROOT': str(root),
        'ORBIT_ACTIVATION_PARENT_MOUNT_FD': str(args.parent_mount_fd),
        'ORBIT_ACTIVATION_PARENT_USER_FD': str(args.parent_user_fd),
        'ORBIT_ACTIVATION_MANAGED_MARKER': marker,
        'ORBIT_ACTIVATION_ISOLATED': '1',
        'ORBIT_ACTIVATION_RUNNER_DEPTH': '1',
    })
    return proof


def harness_summary(stdout):
    text = stdout.decode('utf-8', 'replace')
    matches = re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', text, re.MULTILINE)
    require(len(matches) == 1, 'test_harness_terminal_summary')
    status, passed, failed, ignored = matches[0]
    return {'status': status, 'passed': int(passed), 'failed': int(failed), 'ignored': int(ignored)}


def inside(args):
    root = Path(args.fixture_root)
    env = environment(root)
    report = {'schema': SCHEMA, 'status': 'NOTRUN', 'phase': 'isolation',
              'test_filter': args.exact, 'binary_sha256': args.binary_sha256,
              'test_started': False}
    result = 77
    try:
        report['isolation'] = isolate(args, root, env)
        report['observed_namespace'] = {
            'pid': os.getpid(),
            'ppid': os.getppid(),
            'uid': os.getuid(), 'gid': os.getgid(),
            'uid_map': Path('/proc/self/uid_map').read_text().strip(),
            'gid_map': Path('/proc/self/gid_map').read_text().strip(),
            'mount_namespace': os.readlink('/proc/self/ns/mnt'),
            'user_namespace': os.readlink('/proc/self/ns/user'),
            'pid_namespace': os.readlink('/proc/self/ns/pid'),
        }
        print(json.dumps({'schema': STAGE, 'phase': 'isolated_before_test', 'test_started': False}), flush=True)
        verify_binary(args.binary, args.binary_sha256)
        code, listing, _ = command([args.binary, '--list', '--format', 'terse'], env, root / 'work', 10,
                                  pass_fds=(args.parent_mount_fd, args.parent_user_fd))
        require(code == 0, 'test_listing_failed')
        names = [line[:-6] for line in listing.decode().splitlines() if line.endswith(': test')]
        require(names and len(names) == len(set(names)), 'test_listing_shape')
        require(args.exact is None or names.count(args.exact) == 1, 'exact_test_filter_missing')
        arguments = [args.binary, '--nocapture', '--test-threads=1']
        if args.exact is not None:
            arguments.extend(['--exact', args.exact])
        report.update({'phase': 'test_execution', 'test_started': True})
        code, stdout, stderr = command(arguments, env, root / 'work', args.timeout,
                                       pass_fds=(args.parent_mount_fd, args.parent_user_fd))
        report.update({'test_exit': code, 'stdout_sha256': digest(stdout), 'stderr_sha256': digest(stderr),
                       'stdout_bytes': len(stdout), 'stderr_bytes': len(stderr),
                       'stdout_excerpt': stdout[-EXCERPT:].decode('utf-8', 'replace'),
                       'stderr_excerpt': stderr[-EXCERPT:].decode('utf-8', 'replace')})
        report['harness'] = harness_summary(stdout)
        if code == 0:
            require(report['harness']['status'] == 'ok' and report['harness']['failed'] == 0, 'successful_test_summary_mismatch')
            require(report['harness']['passed'] == 1 and report['harness']['ignored'] == 0 if args.exact is not None else report['harness']['passed'] > 0, 'successful_test_count')
            report['status'] = 'TEST_PASSED'
            result = 0
        else:
            require(report['harness']['status'] == 'FAILED' and report['harness']['failed'] > 0, 'failed_test_summary_mismatch')
            report['status'] = 'TEST_FAILED'
            result = 1
        verify_binary(args.binary, args.binary_sha256)
        report['binary_postcheck_inside'] = True
    except NotRun as error:
        report.update({'status': 'NOTRUN', 'reason': str(error)})
    except Exception as error:
        report.update({'status': 'INFRA_FAILURE', 'reason': str(error)[:120] if isinstance(error, Failed) else type(error).__name__})
        result = 2
    print(json.dumps(report, sort_keys=True, separators=(',', ':')), flush=True)
    return result


def outer(args):
    root = None
    root_identity = None
    namespace_lifecycle = {'spawn_attempted': False, 'reaped': False}
    before_binary = None
    host_before = None
    host_checked = False
    report = {'schema': SCHEMA, 'status': 'NOTRUN', 'phase': 'preconditions',
              'test_filter': args.exact, 'test_started': False}
    result = 77
    try:
        binary = Path(args.binary)
        require(binary.is_absolute(), 'absolute_test_binary_required')
        before_binary = verify_binary(binary, args.binary_sha256)
        report['binary_sha256'] = before_binary['sha256']
        host_before = managed_fingerprint()
        host_checked = True
        if not Path('/usr/bin/unshare').is_file() or not Path('/usr/bin/mount').is_file():
            raise NotRun('namespace_tools_unavailable')
        root = Path(tempfile.mkdtemp(prefix='oc-'))
        root.chmod(0o700)
        root_identity = fixture_root_identity(root.lstat())
        for name in ['user', 'tmp', 'work', 'user/config', 'user/cache', 'user/data', 'user/state', 'user/runtime']:
            (root / name).mkdir(mode=0o700)
        nonce = os.urandom(12).hex()
        with open('/proc/self/ns/mnt', 'rb', buffering=0) as mount_ns, open('/proc/self/ns/user', 'rb', buffering=0) as user_ns:
            parent_mount = os.readlink('/proc/self/ns/mnt')
            require(parent_mount == 'mnt:[' + str(os.fstat(mount_ns.fileno()).st_ino) + ']', 'original_mount_descriptor_identity')
            arguments = ['/usr/bin/unshare', '--user', '--map-root-user', '--mount', '--pid', '--fork', '--kill-child=KILL',
                         sys.executable, str(Path(__file__).resolve()), '--inside', '--binary', str(binary),
                         '--binary-sha256', before_binary['sha256'], '--fixture-root', str(root),
                         '--parent-mount-fd', str(mount_ns.fileno()), '--parent-user-fd', str(user_ns.fileno()),
                         '--parent-mount', parent_mount, '--nonce', nonce, '--timeout', str(args.timeout)]
            if args.exact is not None:
                arguments.extend(['--exact', args.exact])
            else:
                arguments.append('--all')
            report.update({'phase': 'namespace_reexec', 'test_started': None})
            code, stdout, stderr = command(arguments, environment(root), root, args.timeout + 25,
                                          pass_fds=(mount_ns.fileno(), user_ns.fileno()),
                                          lifecycle=namespace_lifecycle)
        records = [json.loads(line) for line in stdout.decode().splitlines() if line.strip()]
        stages = [record for record in records if record.get('schema') == STAGE]
        finals = [record for record in records if record.get('schema') == SCHEMA]
        require(len(records) == len(stages) + len(finals) and len(stages) <= 1 and len(finals) <= 1, 'inner_receipt_protocol')
        if finals:
            report = finals[0]
            require(report.get('binary_sha256') == before_binary['sha256'] and report.get('test_filter') == args.exact, 'inner_receipt_identity')
            require((code == 0 and report.get('status') == 'TEST_PASSED')
                    or (code == 1 and report.get('status') == 'TEST_FAILED')
                    or (code == 2 and report.get('status') == 'INFRA_FAILURE')
                    or (code == 77 and report.get('status') == 'NOTRUN' and report.get('test_started') is False), 'inner_exit_status_mismatch')
            result = code
        elif not stages and code != 0 and b'unshare:' in stderr and any(term in stderr.lower() for term in [b'operation not permitted', b'not supported']):
            report.update({'status': 'NOTRUN', 'reason': 'namespace_reexec_unavailable', 'test_started': False,
                           'reexec_exit': code, 'stderr_sha256': digest(stderr)})
        else:
            report.update({'status': 'INFRA_FAILURE', 'reason': 'inner_receipt_missing', 'test_started': None})
            result = 2
    except NotRun as error:
        report.update({'status': 'NOTRUN', 'reason': str(error)})
    except Exception as error:
        report.update({'status': 'INFRA_FAILURE', 'reason': str(error)[:120] if isinstance(error, Failed) else type(error).__name__})
        result = 2
    finally:
        if before_binary is not None:
            try:
                unchanged = verify_binary(args.binary, before_binary['sha256']) == before_binary
                report['binary_metadata_and_hash_unchanged'] = unchanged
                require(unchanged, 'binary_changed')
            except Exception:
                report.update({'status': 'INFRA_FAILURE', 'reason': 'binary_postcheck_failed'})
                result = 2
        if host_checked:
            try:
                unchanged = managed_fingerprint() == host_before
                report['host_managed_path_metadata_unchanged'] = unchanged
                require(unchanged, 'host_managed_metadata_changed')
            except Exception:
                report.update({'status': 'INFRA_FAILURE', 'reason': 'host_managed_metadata_recheck_failed'})
                result = 2
        if root is not None:
            report['owned_fixture_root_identity'] = root_identity
            report['owned_namespace_lifecycle'] = dict(namespace_lifecycle)
            try:
                report['owned_fixture_cleanup_entries'] = cleanup_owned_fixture(root, root_identity, namespace_lifecycle)
                report['owned_fixture_removed'] = True
            except Exception as error:
                report.update({'status': 'INFRA_FAILURE', 'reason': 'owned_fixture_cleanup_failed',
                               'owned_fixture_removed': False,
                               'cleanup_detail': str(error)[:120] if isinstance(error, Failed) else type(error).__name__})
                result = 2
    encoded = json.dumps(report, sort_keys=True, separators=(',', ':')).encode() + b'\n'
    if args.receipt is not None:
        receipt = Path(args.receipt)
        require(receipt.is_absolute() and receipt.parent.is_dir(), 'receipt_absolute_parent_required')
        private_write(receipt, encoded)
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--binary-sha256')
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--exact')
    choice.add_argument('--all', action='store_true')
    parser.add_argument('--timeout', type=int, default=45)
    parser.add_argument('--receipt')
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--fixture-root')
    parser.add_argument('--parent-mount-fd', type=int)
    parser.add_argument('--parent-user-fd', type=int)
    parser.add_argument('--parent-mount')
    parser.add_argument('--nonce')
    args = parser.parse_args()
    require(5 <= args.timeout <= 300, 'timeout_bound')
    require(args.exact is None or re.fullmatch(r'[A-Za-z0-9_:]{1,512}', args.exact) is not None, 'exact_filter_shape')
    require(args.binary_sha256 is None or re.fullmatch(r'[a-f0-9]{64}', args.binary_sha256) is not None, 'binary_hash_shape')
    if args.inside:
        require(args.fixture_root is not None and args.parent_mount_fd is not None and args.parent_user_fd is not None
                and args.parent_mount is not None and args.nonce is not None
                and re.fullmatch(r'[a-f0-9]{24}', args.nonce) is not None
                and args.binary_sha256 is not None, 'inner_arguments')
    def timeout_signal(_signum, _frame):
        raise Failed('runner_deadline')
    signal.signal(signal.SIGALRM, timeout_signal)
    signal.signal(signal.SIGTERM, timeout_signal)
    signal.alarm(args.timeout + 45)
    return inside(args) if args.inside else outer(args)


if __name__ == '__main__':
    raise SystemExit(main())
