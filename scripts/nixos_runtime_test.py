#!/usr/bin/env python3
"""Installed-package user journey; execute as a normal user in a NixOS VM."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import time
import unittest


class Mock:
    def __init__(self):
        self.command = None
        self.results = []
        self.background = False
        self.ready = None
        self.started = threading.Event()
        self.release = threading.Event()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                self.connection.settimeout(5)
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size < 1024 * 1024:
                    self.send_error(400)
                    return
                body = json.loads(self.rfile.read(size))
                tools = [m for m in body.get("messages", []) if m.get("role") == "tool"]
                for message in tools:
                    content = message.get("content", "")
                    if isinstance(content, str):
                        try:
                            owner.results.append(json.loads(content))
                        except ValueError:
                            pass
                if owner.command is not None and not tools:
                    delta = {"tool_calls": [{"index": 0, "id": "nix-shell",
                        "type": "function", "function": {"name": "Bash",
                        "arguments": json.dumps({"command": owner.command,
                                                  "run_in_background": owner.background})}}]}
                    reason = "tool_calls"
                elif owner.background and len(tools) == 1:
                    task = next((r.get('task_id') for r in owner.results if r.get('backgrounded')), None)
                    if task is None:
                        self.send_error(500, 'missing background task identity')
                        return
                    deadline = time.monotonic() + 10
                    while not owner.ready.exists() and time.monotonic() < deadline:
                        time.sleep(0.02)
                    owner.started.set()
                    if not owner.release.wait(timeout=10):
                        self.send_error(500, 'background control was not inspected')
                        return
                    delta = {'tool_calls': [{'index': 0, 'id': 'nix-stop', 'type': 'function',
                        'function': {'name': 'TaskStop', 'arguments': json.dumps({'task_id': task})}}]}
                    reason = 'tool_calls'
                else:
                    delta, reason = {"content": "NIXOS_JOURNEY_OK"}, "stop"
                events = [{"choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
                          {"choices": [{"index": 0, "delta": {}, "finish_reason": reason}],
                           "usage": {"prompt_tokens": 2, "completion_tokens": 3}}]
                payload = "".join("data: " + json.dumps(e) + "\n\n" for e in events) + "data: [DONE]\n\n"
                encoded = payload.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.url = f"http://127.0.0.1:{self.server.server_port}/v1/"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        assert not self.thread.is_alive()


class Journey(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() == 0 or 'ID=nixos' not in Path('/etc/os-release').read_text():
            raise RuntimeError("this acceptance requires a normal user in a real NixOS guest")
        for binary in (OPTIONS.binary, OPTIONS.web_binary):
            if not str(Path(binary).resolve()).startswith('/nix/store/'):
                raise RuntimeError("acceptance requires the actual installed store package")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='orbit-nixos-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home, self.work = self.root / 'state', self.root / 'work'
        self.work.mkdir(mode=0o700)
        self.env = {k: v for k, v in os.environ.items()
                    if k in ('PATH', 'TERM', 'LANG', 'ORBIT_RUNTIME_PATH')}
        self.env.update(HOME=str(self.work), NO_COLOR='1', ORBIT_TEST_SECRET='nix-private-env')
        self.mock = self.enterContext(Mock())
        result = self.run_orbit('setup', '--provider', 'fixture', '--gate', self.mock.url,
                                '--model', 'runtime', '--json')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def run_orbit(self, *args, **kwargs):
        return subprocess.run([OPTIONS.binary, '--home', str(self.home), *args],
            cwd=self.work, env=self.env, text=True, capture_output=True, timeout=35, **kwargs)

    def turn(self, command=None, resume=None):
        self.mock.command = command
        self.mock.results.clear()
        args = ['-p', 'Nix runtime acceptance', '--model', 'fixture/runtime',
                '--bare', '--output-format', 'json', '--allowedTools', 'Bash']
        if resume:
            args += ['--resume', resume]
        return self.run_orbit(*args)

    def shell_result(self, command):
        result = self.turn(command)
        self.assertTrue(self.mock.results, result.stdout + result.stderr)
        payload = self.mock.results[-1]
        self.assertIs(payload.get('sandboxed'), True, payload)
        return payload

    def test_setup_conversation_and_resume(self):
        result = self.turn()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        receipt = json.loads(result.stdout)
        self.assertIn('NIXOS_JOURNEY_OK', result.stdout)
        paths = list((self.home / 'sessions').glob('*.json'))
        self.assertEqual(len(paths), 1, paths)
        state = json.loads(paths[0].read_text())
        self.assertEqual(state['schema'], 'orbit.session/v1')
        session = state['session_id']
        before_turns = state['turns']
        keys = [self.home / 'trust/operator.key', self.home / 'trust/manifest.json']
        before = [p.read_bytes() for p in keys]
        result = self.turn(resume=session)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        updated = json.loads(paths[0].read_text())
        self.assertEqual(updated['session_id'], session)
        self.assertEqual(updated['turns'], before_turns + 1)
        self.assertEqual(list((self.home / 'sessions').glob('*.json')), paths)
        self.assertEqual([p.read_bytes() for p in keys], before)
        doctor = self.run_orbit('doctor', '--json')
        self.assertIn(doctor.returncode, (0, 1), doctor.stderr)
        report = json.loads(doctor.stdout)['report']
        self.assertTrue(any(c['id'] == 'identity' and c['status'] == 'ready' for c in report['checks']))

    def test_paired_web_startup(self):
        fresh = self.root / 'uninitialized'
        for binary, prefix in [(OPTIONS.binary, ['web']), (OPTIONS.web_binary, [])]:
            result = subprocess.run([binary, '--home', str(fresh), *prefix, '--no-browser'],
                cwd=self.work, env=self.env, text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn('ORBIT-E0400', result.stderr + result.stdout)
            self.assertIn('not initialized', result.stderr + result.stdout)

    def test_confined_store_tools_and_denials(self):
        result = self.shell_result("printf 'nix-runtime-ok\\n' > allowed.txt && rg nix-runtime-ok allowed.txt && git --version && command -v bash")
        self.assertIs(result['ok'], True, result)
        self.assertEqual((self.work / 'allowed.txt').read_text(), 'nix-runtime-ok\n')
        self.assertIn('/nix/store/', result['output'])
        self.assertIs(self.shell_result('printf forbidden > /etc/orbit-forbidden')['ok'], False)
        self.assertFalse(Path('/etc/orbit-forbidden').exists())
        result = self.shell_result("test -z \"$ORBIT_TEST_SECRET\" && printf env-clean")
        self.assertIs(result['ok'], True, result)
        self.assertIn('env-clean', result['output'])
        result = self.shell_result("bash -c 'exec 3<>/dev/tcp/127.0.0.1/%d'" % self.mock.server.server_port)
        self.assertIs(result['ok'], False, result)
        secret = self.work / '.ssh'
        secret.mkdir(mode=0o700)
        (secret / 'id_rsa').write_text('private-nix-secret')
        encoded = ''.join('\\%03o' % b for b in str(secret / 'id_rsa').encode())
        result = self.shell_result("p=$(printf '%s'); cat \"$p\"" % encoded)
        self.assertNotIn('private-nix-secret', result['output'])

    def process_tree(self, parent):
        found = {}
        pending = [parent]
        while pending:
            pid = pending.pop()
            try:
                children = Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
                for child in map(int, children):
                    stat = Path(f'/proc/{child}/stat').read_text().rsplit(')', 1)[1].split()
                    found[child] = stat[19]
                    pending.append(child)
            except FileNotFoundError:
                pass
        return found

    def assert_reaped(self, processes):
        self.assertTrue(processes, 'no owned descendants were observed')
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            alive = {}
            for pid, started in processes.items():
                try:
                    stat = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
                    if stat[19] == started:
                        # The namespace test runner is PID1. Its normal-init
                        # duty is limited to these recorded adopted children;
                        # never wait for an unrelated Popen or arbitrary PID.
                        if os.getpid() == 1 and stat[0] == 'Z' and stat[1] == '1':
                            try:
                                reaped, _ = os.waitpid(pid, os.WNOHANG)
                                if reaped == pid:
                                    continue
                            except ChildProcessError:
                                pass
                        alive[pid] = started
                except FileNotFoundError:
                    pass
            if not alive:
                return
            time.sleep(0.05)
        self.fail(f'owned descendants remain after cancellation: {list(alive)}')

    def test_detached_tool_task_stop(self):
        marker = self.work / 'detached.pid'
        self.mock.command = f'sleep 120 & child=$!; echo "$child" > {marker.name}; wait'
        self.mock.background = True
        self.mock.ready = marker
        unrelated = subprocess.Popen(['sleep', '121'])
        process = subprocess.Popen([OPTIONS.binary, '--home', str(self.home), '-p', 'detached stop',
            '--model', 'fixture/runtime', '--bare', '--allowedTools', 'Bash,TaskStop'],
            cwd=self.work, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertTrue(self.mock.started.wait(timeout=15), 'detached tool did not reach its stop control')
            self.assertTrue(marker.exists(), 'detached tool did not start')
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                descendants = self.process_tree(process.pid)
                witnessed = False
                for pid in descendants:
                    try:
                        argv = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
                        if argv[0].rsplit(b'/', 1)[-1] == b'sleep' and argv[1:2] == [b'120']:
                            witnessed = True
                    except FileNotFoundError:
                        pass
                if witnessed:
                    break
                time.sleep(0.02)
            self.assertTrue(witnessed, 'detached sleep descendant identity was not observed')
            self.mock.release.set()
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, stdout + stderr)
            self.assertTrue(any(r.get('backgrounded') and r.get('sandboxed') is True for r in self.mock.results))
            self.assertTrue(any(r.get('stopped') for r in self.mock.results), self.mock.results)
            self.assert_reaped(descendants)
            self.assertIsNone(unrelated.poll(), 'stopping a task killed an unrelated process')
        finally:
            self.mock.release.set()
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:
                    process.communicate(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=3)
            unrelated.terminate()
            unrelated.wait(timeout=3)

    def test_cancel_reaps_owned_foreground_and_background(self):
        for background in (False, True):
            marker = self.work / ('background.pid' if background else 'foreground.pid')
            command = f"sleep 120 & echo $! > {marker.name}; wait" if background else f"echo $$ > {marker.name}; exec sleep 120"
            self.mock.command = command
            process = subprocess.Popen([OPTIONS.binary, '--home', str(self.home), '-p', 'cancel test',
                '--model', 'fixture/runtime', '--bare', '--allowedTools', 'Bash'], cwd=self.work,
                env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 15
                while not marker.exists() and time.monotonic() < deadline and process.poll() is None:
                    time.sleep(0.05)
                self.assertTrue(marker.exists(), 'confined child did not start')
                descendants = self.process_tree(process.pid)
                process.send_signal(signal.SIGINT)
                stdout, stderr = process.communicate(timeout=8)
                self.assertEqual(process.returncode, 130, stdout + stderr)
                self.assert_reaped(descendants)
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGINT)
                    try:
                        process.communicate(timeout=8)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate(timeout=3)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--web-binary', required=True)
    OPTIONS, remaining = parser.parse_known_args()
    unittest.main(argv=[__file__, *remaining], verbosity=2)
