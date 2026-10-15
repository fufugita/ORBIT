#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn, spawnSync} from 'node:child_process';
import {gzipSync, gunzipSync} from 'node:zlib';
import {once} from 'node:events';
import {nativePackage, platforms} from '../packaging/npm/lib/platform.mjs';
import {readTar, sha256, verifyArchive, verifyMembers} from '../packaging/npm/lib/archive.mjs';
import {stage} from '../packaging/npm/stage.mjs';

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit npm distribution '));
const scenarios = {};
let checks = 0;
function check(value, message) { assert(value, message); checks++; }
async function scenario(name, run) {
  const before = checks;
  await run();
  scenarios[name] = {passed: true, assertions: checks - before};
  console.log(`PASS ${name}: ${checks - before} assertions`);
}
const version = '0.2.0';
const target = 'x86_64-unknown-linux-gnu';
const armTarget = 'aarch64-unknown-linux-gnu';
const wrapperMetadata = JSON.parse(fs.readFileSync(path.join(repository, 'packaging/npm/package.json'), 'utf8'));
const license = fs.readFileSync(path.join(repository, 'LICENSE'));
const npmDirectory = path.join(root, 'npm');
fs.mkdirSync(npmDirectory);
const npmConfig = path.join(npmDirectory, 'empty.npmrc');
fs.writeFileSync(npmConfig, '');
const npmEnvironment = {
  ...process.env,
  npm_config_cache: path.join(npmDirectory, 'cache'),
  npm_config_userconfig: npmConfig,
  npm_config_globalconfig: path.join(npmDirectory, 'absent.npmrc'),
  npm_config_registry: 'http://127.0.0.1:9',
  npm_config_fetch_retries: '0',
  npm_config_update_notifier: 'false',
};
function command(file, args, options = {}) {
  const result = spawnSync(file, args, {encoding: 'utf8', timeout: 60000, ...options});
  assert.ifError(result.error);
  assert.equal(result.status, 0, `${file} failed: ${result.stderr}`);
  return result;
}
function npm(args, options = {}) {
  return command('npm', [...args, '--ignore-scripts', '--offline', '--no-audit', '--no-fund'], {env: npmEnvironment, ...options});
}
function header(name, size, type = '0', mode = 0o755) {
  const result = Buffer.alloc(512);
  result.write(name, 0, 100, 'ascii');
  const number = (value, start, width) => result.write(`${value.toString(8).padStart(width - 1, '0')}\0`, start, width, 'ascii');
  number(mode, 100, 8); number(0, 108, 8); number(0, 116, 8); number(size, 124, 12); number(0, 136, 12);
  result.fill(32, 148, 156); result.write(type, 156, 1, 'ascii');
  result.write('ustar\0', 257, 6, 'ascii'); result.write('00', 263, 2, 'ascii');
  const sum = result.reduce((total, byte) => total + byte, 0);
  result.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
  return result;
}
function tar(members) {
  const chunks = [];
  for (const {name, bytes, type = '0', size = bytes.length, mode = 0o755} of members) {
    chunks.push(header(name, size, type, mode), bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
  }
  return Buffer.concat([...chunks, Buffer.alloc(1024)]);
}
function releaseMembers(binary, releaseTarget = target, changes = {}) {
  const manifest = {
    schema_version: 1, version, target: releaseTarget, signature: 'absent',
    components: Object.fromEntries(['orbit', 'orbit-web'].map(name => [name, {size: binary.length, sha256: sha256(binary)}])),
    ...changes,
  };
  return [{name: 'manifest.json', bytes: Buffer.from(`${JSON.stringify(manifest)}\n`), mode: 0o600}, ...['orbit', 'orbit-web'].map(name => ({name, bytes: binary}))];
}
let archiveNumber = 0;
function archive(members, transform = bytes => bytes) {
  const file = path.join(root, `release-${++archiveNumber}.tar.gz`);
  const bytes = transform(gzipSync(tar(members)));
  fs.writeFileSync(file, bytes);
  fs.writeFileSync(`${file}.sha256`, `${sha256(bytes)}  ${path.basename(file)}\n`);
  return file;
}
function rejects(run, pattern) { assert.throws(run, pattern); checks++; }
function packedFile(file, wanted) {
  const bytes = gunzipSync(fs.readFileSync(file), {maxOutputLength: 16 * 1024 * 1024});
  for (let offset = 0; offset + 512 <= bytes.length; ) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every(byte => byte === 0)) break;
    const name = header.subarray(0, 100).toString('utf8').split('\0')[0];
    const size = Number.parseInt(header.subarray(124, 136).toString('ascii').replace(/[\0 ]+$/g, ''), 8);
    assert(Number.isSafeInteger(size) && size >= 0 && offset + 512 + size <= bytes.length);
    if (name === wanted) return bytes.subarray(offset + 512, offset + 512 + size);
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  throw new Error(`Missing packed file ${wanted}`);
}

try {
  await scenario('platform_and_package_contract', () => {
    check(wrapperMetadata.name === '@fufugita/orbit' && wrapperMetadata.version === version);
    check(wrapperMetadata.engines.node === '^22.15.0 || >=23.11.0');
    check(wrapperMetadata.license === 'Apache-2.0' && wrapperMetadata.files.includes('LICENSE'));
    check(!wrapperMetadata.scripts && !wrapperMetadata.dependencies);
    check(JSON.stringify(wrapperMetadata.os) === '["linux"]' && JSON.stringify(wrapperMetadata.libc) === '["glibc"]');
    check(Object.values(wrapperMetadata.optionalDependencies).every(value => value === version));
    for (const platform of Object.values(platforms)) {
      check(nativePackage('linux', platform.arch, '2.35') === platform.name);
      check(nativePackage('linux', platform.arch, '2.39') === platform.name);
      rejects(() => nativePackage('linux', platform.arch, '2.34'), /glibc 2\.35.*detected glibc 2\.34.*Homebrew.*source/);
      rejects(() => nativePackage('linux', platform.arch, 'not-a-version'), /glibc 2\.35.*could not be determined.*Homebrew.*source/);
      rejects(() => nativePackage('linux', platform.arch, undefined), /glibc 2\.35.*could not be determined.*Homebrew.*source/);
    }
    for (const args of [['darwin', 'x64', '2.39'], ['win32', 'arm64', '2.39'], ['linux', 'riscv64', '2.39']]) rejects(() => nativePackage(...args), /Linux glibc/);
  });

  const nativeScript = path.join(root, 'native behavior.mjs');
  fs.writeFileSync(nativeScript, `import fs from 'node:fs';
const args=process.argv.slice(2);
if(args[0]==='wait'){console.log('READY '+process.pid);setInterval(()=>{},1000);}
else if(args[0]==='signal'){process.kill(process.pid,'SIGTERM');}
else {console.log(JSON.stringify({args,stdin:fs.readFileSync(0,'utf8'),native:process.env.ORBIT_TEST_NATIVE_EXEC,cwd:process.cwd()}));if(args[0]==='exit'){console.error('native failure');process.exit(37);}}
`);
  const cString = value => JSON.stringify(value);
  const fixtureSource = path.join(root, 'native.c');
  fs.writeFileSync(fixtureSource, `#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(int argc,char **argv){
if(argc>1 && strcmp(argv[1],"web")==0){char *s=calloc(strlen(argv[0])+10,1);if(!s)return 110;strcpy(s,argv[0]);char *p=strrchr(s,'/');if(!p)return 111;strcpy(p+1,"orbit-web");argv[1]=s;execv(s,argv+1);return 112;}
setenv("ORBIT_TEST_NATIVE_EXEC",argv[0],1);
char **args=calloc(argc+2,sizeof(char*));if(!args)return 114;args[0]=${cString(process.execPath)};args[1]=${cString(nativeScript)};
for(int i=1;i<argc;i++){args[i+1]=argv[i];}
execv(args[0],args);perror("fixture exec");return 113;}
`);
  const nativeExecutable = path.join(root, 'native fixture');
  command('cc', ['-O0', '-Wall', '-Wextra', '-Werror', '-o', nativeExecutable, fixtureSource]);
  const binary = fs.readFileSync(nativeExecutable);
  const armBinary = Buffer.from(binary); armBinary.writeUInt16LE(183, 18);
  const x64Archive = archive(releaseMembers(binary));
  const armArchive = archive(releaseMembers(armBinary, armTarget));

  await scenario('release_archive_validation', () => {
    check(verifyArchive(x64Archive, version).manifest.target === target);
    check(verifyArchive(armArchive, version).manifest.target === armTarget);
    rejects(() => verifyArchive(x64Archive, '0.2.1'), /manifest version/);
    for (const change of [{signature: 'claimed'}, {target: 'unknown-linux-gnu'}, {schema_version: 2}, {extra: true}]) rejects(() => verifyArchive(archive(releaseMembers(binary, target, change)), version), /manifest/);
    rejects(() => verifyArchive(archive(releaseMembers(binary, armTarget)), version), /ELF architecture/);
    const brokenHash = releaseMembers(binary); const doc = JSON.parse(brokenHash[0].bytes); doc.components.orbit.sha256 = '0'.repeat(64); brokenHash[0].bytes = Buffer.from(JSON.stringify(doc));
    rejects(() => verifyArchive(archive(brokenHash), version), /checksum or size mismatch/);
    const brokenSize = releaseMembers(binary); const sizeDoc = JSON.parse(brokenSize[0].bytes); sizeDoc.components['orbit-web'].size++; brokenSize[0].bytes = Buffer.from(JSON.stringify(sizeDoc));
    rejects(() => verifyArchive(archive(brokenSize), version), /checksum or size mismatch/);
    const extraComponent = releaseMembers(binary); const extraDoc = JSON.parse(extraComponent[0].bytes); extraDoc.components.extra = extraDoc.components.orbit; extraComponent[0].bytes = Buffer.from(JSON.stringify(extraDoc));
    rejects(() => verifyArchive(archive(extraComponent), version), /both native/);
    for (const name of ['../orbit', '/orbit', './orbit', 'extra']) rejects(() => readTar(tar([...releaseMembers(binary), {name, bytes: Buffer.from('x')}])), /Unexpected or duplicate/);
    for (const type of ['1', '2', '5', 'x', 'g']) {const entries = releaseMembers(binary); entries[1].type = type; rejects(() => readTar(tar(entries)), /plain regular/);}
    rejects(() => readTar(tar([...releaseMembers(binary), releaseMembers(binary)[1]])), /duplicate/);
    const noExec = releaseMembers(binary); noExec[1].mode = 0o644; rejects(() => readTar(tar(noExec)), /executable permissions/);
    const setuid = releaseMembers(binary); setuid[1].mode = 0o4755; rejects(() => readTar(tar(setuid)), /executable permissions/);
    rejects(() => readTar(tar(releaseMembers(binary)).subarray(0, -1024)), /complete tar terminator/);
    rejects(() => readTar(Buffer.alloc(511)), /Truncated/);
    const badHeader = tar(releaseMembers(binary)); badHeader[1] ^= 1; rejects(() => readTar(badHeader), /header checksum/);
    const badPadding = tar(releaseMembers(binary)); badPadding[512 + releaseMembers(binary)[0].bytes.length] = 1; rejects(() => readTar(badPadding), /nonzero tar padding/);
    const badSidecar = archive(releaseMembers(binary)); fs.writeFileSync(`${badSidecar}.sha256`, `${'0'.repeat(64)}  ${path.basename(badSidecar)}\n`); rejects(() => verifyArchive(badSidecar, version), /sidecar mismatch/);
    const badFilename = archive(releaseMembers(binary)); fs.writeFileSync(`${badFilename}.sha256`, `${sha256(fs.readFileSync(badFilename))}  other.tar.gz\n`); rejects(() => verifyArchive(badFilename, version), /sidecar mismatch/);
    const missing = archive(releaseMembers(binary)); fs.unlinkSync(`${missing}.sha256`); rejects(() => verifyArchive(missing, version), /ENOENT/);
    const truncated = archive(releaseMembers(binary), bytes => bytes.subarray(0, -8)); rejects(() => verifyArchive(truncated, version), /unexpected end/i);
    const oversized = path.join(root, 'oversized.tar.gz'); const fd = fs.openSync(oversized, 'w'); fs.ftruncateSync(fd, 512 * 1024 * 1024 + 1); fs.closeSync(fd); rejects(() => verifyArchive(oversized, version), /oversized/);
    const link = path.join(root, 'linked.tar.gz'); fs.symlinkSync(x64Archive, link); rejects(() => verifyArchive(link, version), /ELOOP/);
    check(verifyMembers(readTar(tar(releaseMembers(binary))), version).version === version);
  });

  const staged = path.join(root, 'staged packages');
  await scenario('staging_is_complete_and_fresh', () => {
    const names = stage([x64Archive, armArchive], staged);
    check(names.length === 2);
    check(fs.readFileSync(path.join(staged, 'orbit/LICENSE')).equals(license));
    rejects(() => stage([x64Archive], staged), /EEXIST/);
    const duplicate = path.join(root, 'duplicate'); rejects(() => stage([x64Archive, x64Archive], duplicate), /Duplicate/); check(!fs.existsSync(duplicate));
    const bad = path.join(root, 'invalid'); rejects(() => stage([x64Archive], bad + '/missing-parent'), /ENOENT/); check(!fs.existsSync(bad));
    for (const platform of Object.values(platforms)) {
      const directory = path.join(staged, platform.name.split('/')[1]);
      const doc = JSON.parse(fs.readFileSync(path.join(directory, 'package.json')));
      check(doc.name === platform.name && doc.version === version && doc.cpu[0] === platform.arch && doc.libc[0] === 'glibc');
      check(!doc.scripts && !doc.dependencies && !doc.bin);
      check(doc.license === 'Apache-2.0' && doc.files.includes('LICENSE') && fs.readFileSync(path.join(directory, 'LICENSE')).equals(license));
      for (const name of ['orbit', 'orbit-web']) check((fs.statSync(path.join(directory, 'bin', name)).mode & 0o111) !== 0);
    }
    check(fs.readFileSync(path.join(staged, 'orbit-linux-x64-gnu/bin/orbit')).equals(binary));
    check(fs.readFileSync(path.join(staged, 'orbit-linux-arm64-gnu/bin/orbit-web')).equals(armBinary));
  });

  const packs = path.join(root, 'packs'); fs.mkdirSync(packs);
  const packed = new Map();
  await scenario('npm_pack_contains_only_runtime_files', () => {
    for (const directory of ['orbit', 'orbit-linux-x64-gnu', 'orbit-linux-arm64-gnu']) {
      const result = JSON.parse(npm(['pack', '--json', '--pack-destination', packs], {cwd: path.join(staged, directory)}).stdout)[0];
      const expected = directory === 'orbit' ? ['LICENSE', 'bin/orbit-web.mjs', 'bin/orbit.mjs', 'lib/launcher.mjs', 'lib/platform.mjs', 'package.json'] : ['LICENSE', 'bin/orbit', 'bin/orbit-web', 'manifest.json', 'package.json'];
      check(JSON.stringify(result.files.map(file => file.path).sort()) === JSON.stringify(expected.sort()), `${directory}: unexpected packed files`);
      check(result.bundled.length === 0);
      packed.set(directory, path.join(packs, result.filename));
      check(packedFile(packed.get(directory), 'package/LICENSE').equals(license));
    }
  });

  const prefix = path.join(root, 'private prefix');
  const cli = path.join(prefix, 'bin/orbit');
  const web = path.join(prefix, 'bin/orbit-web');
  const installedNative = path.join(prefix, 'lib/node_modules/@fufugita/orbit-linux-x64-gnu');
  await scenario('npm_install_and_native_execution', () => {
    npm(['install', '--global', '--prefix', prefix, packed.get('orbit'), packed.get('orbit-linux-x64-gnu')]);
    check(fs.lstatSync(cli).isSymbolicLink() && fs.lstatSync(web).isSymbolicLink());
    check(fs.readFileSync(path.join(prefix, 'lib/node_modules/@fufugita/orbit/LICENSE')).equals(license));
    check(fs.readFileSync(path.join(installedNative, 'LICENSE')).equals(license));
    const result = command(cli, ['spaces in one arg', '--literal=$HOME', 'a"b', '', 'line\nbreak', 'unicode-λ'], {cwd: root, input: 'stdin survives\n'});
    const data = JSON.parse(result.stdout);
    check(JSON.stringify(data.args) === JSON.stringify(['spaces in one arg', '--literal=$HOME', 'a"b', '', 'line\nbreak', 'unicode-λ']));
    check(data.stdin === 'stdin survives\n' && data.cwd === root);
    check(data.native === path.join(installedNative, 'bin/orbit'));
    check(result.stderr === '', 'launcher must not add diagnostics or experimental warnings');
    const directWeb = JSON.parse(command(web, ['--port', '1234'], {input: ''}).stdout);
    check(directWeb.native === path.join(installedNative, 'bin/orbit-web') && directWeb.args[0] === '--port');
    const sibling = JSON.parse(command(cli, ['web', '--port', '1234'], {input: ''}).stdout);
    check(sibling.native === path.join(installedNative, 'bin/orbit-web') && sibling.args[1] === '1234');
    const nonzero = spawnSync(cli, ['exit'], {encoding: 'utf8', input: ''});
    check(nonzero.status === 37 && nonzero.stderr === 'native failure\n');
    const signal = spawnSync(cli, ['signal'], {encoding: 'utf8', input: ''});
    check(signal.status === null && signal.signal === 'SIGTERM');
  });

  await scenario('native_keeps_pid_and_external_signal', async () => {
    const child = spawn(cli, ['wait'], {stdio: ['ignore', 'pipe', 'pipe']});
    const ready = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {child.kill('SIGKILL'); reject(new Error('native signal fixture readiness timeout'));}, 10000);
      child.once('error', error => {clearTimeout(timer); reject(error);});
      child.stdout.once('data', bytes => {clearTimeout(timer); resolve(bytes.toString());});
      child.once('exit', code => {clearTimeout(timer); reject(new Error(`native fixture exited before readiness: ${code}`));});
    });
    check(ready.trim() === `READY ${child.pid}`, 'execve must keep the launcher PID');
    const exited = once(child, 'exit');
    check(child.kill('SIGTERM'));
    const [code, signal] = await exited;
    check(code === null && signal === 'SIGTERM');
  });

  await scenario('broken_optional_install_is_actionable', () => {
    const metadataPath = path.join(installedNative, 'package.json');
    const metadata = fs.readFileSync(metadataPath); const changed = JSON.parse(metadata); changed.version = '9.9.9'; fs.writeFileSync(metadataPath, JSON.stringify(changed));
    const mismatch = spawnSync(cli, [], {encoding: 'utf8'}); check(mismatch.status === 1 && mismatch.stderr.includes('version mismatch') && mismatch.stderr.includes(version));
    fs.writeFileSync(metadataPath, metadata);
    const nativeWeb = path.join(installedNative, 'bin/orbit-web');
    fs.renameSync(nativeWeb, `${nativeWeb}.removed`);
    const partial = spawnSync(cli, [], {encoding: 'utf8'}); check(partial.status === 1 && partial.stderr.includes('orbit-web is missing') && partial.stderr.includes('Reinstall'));
    fs.renameSync(`${nativeWeb}.removed`, nativeWeb);
    fs.chmodSync(nativeWeb, 0o644);
    const notExecutable = spawnSync(web, [], {encoding: 'utf8'}); check(notExecutable.status === 1 && notExecutable.stderr.includes('not executable') && notExecutable.stderr.includes('Reinstall'));
    fs.chmodSync(nativeWeb, 0o755);
    fs.renameSync(installedNative, `${installedNative}.removed`);
    const missing = spawnSync(cli, [], {encoding: 'utf8'}); check(missing.status === 1 && missing.stderr.includes('--include=optional') && missing.stderr.includes('@fufugita/orbit-linux-x64-gnu@0.2.0'));
    fs.renameSync(`${installedNative}.removed`, installedNative);
    npm(['uninstall', '--global', '--prefix', prefix, '@fufugita/orbit', '@fufugita/orbit-linux-x64-gnu']);
    check(!fs.existsSync(cli) && !fs.existsSync(web) && !fs.existsSync(installedNative));
  });
  console.log(`npm distribution: ${checks} checks passed`);
  console.log(`ORBIT_CHECK_RECEIPT ${JSON.stringify({scenarios})}`);
} finally {
  fs.rmSync(root, {recursive: true, force: true});
}
