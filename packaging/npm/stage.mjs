#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {platforms} from './lib/platform.mjs';
import {verifyArchive} from './lib/archive.mjs';

const source = path.dirname(fileURLToPath(import.meta.url));

function readLicense() {
  const file = path.resolve(source, '../../LICENSE');
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.size <= 0 || before.size > 65536) throw new Error('LICENSE must be a regular file of at most 64 KiB.');
    const bytes = Buffer.alloc(before.size);
    let received = 0;
    while (received < bytes.length) {
      const count = fs.readSync(fd, bytes, received, bytes.length - received, null);
      if (!count) break;
      received += count;
    }
    const overflow = fs.readSync(fd, Buffer.alloc(1), 0, 1, null);
    const after = fs.fstatSync(fd);
    if (received !== bytes.length || overflow || ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs'].some(key => before[key] !== after[key])) throw new Error('LICENSE changed during packaging.');
    return bytes;
  } finally {
    fs.closeSync(fd);
  }
}

export function stage(archives, output) {
  const wrapper = JSON.parse(fs.readFileSync(path.join(source, 'package.json'), 'utf8'));
  if (!archives.length) throw new Error('Supply at least one --archive release archive.');
  const releases = archives.map(archive => verifyArchive(archive, wrapper.version));
  if (new Set(releases.map(release => release.manifest.target)).size !== releases.length) throw new Error('Duplicate release target.');
  const license = readLicense();
  fs.mkdirSync(output, {mode: 0o700});
  try {
    const wrapperDirectory = path.join(output, 'orbit');
    fs.mkdirSync(wrapperDirectory, {mode: 0o755});
    fs.copyFileSync(path.join(source, 'package.json'), path.join(wrapperDirectory, 'package.json'), fs.constants.COPYFILE_EXCL);
    fs.writeFileSync(path.join(wrapperDirectory, 'LICENSE'), license, {flag: 'wx', mode: 0o644});
    for (const directory of ['bin', 'lib']) fs.mkdirSync(path.join(wrapperDirectory, directory), {mode: 0o755});
    for (const file of ['bin/orbit.mjs', 'bin/orbit-web.mjs', 'lib/launcher.mjs', 'lib/platform.mjs']) {
      fs.copyFileSync(path.join(source, file), path.join(wrapperDirectory, file), fs.constants.COPYFILE_EXCL);
      fs.chmodSync(path.join(wrapperDirectory, file), file.startsWith('bin/') ? 0o755 : 0o644);
    }
    for (const {manifest, members} of releases) {
      const platform = platforms[manifest.target];
      const directory = path.join(output, platform.name.split('/')[1]);
      fs.mkdirSync(directory, {mode: 0o755});
      fs.mkdirSync(path.join(directory, 'bin'), {mode: 0o755});
      const metadata = {
        name: platform.name, version: wrapper.version,
        description: `ORBIT native Linux ${platform.arch} executables`,
        license: wrapper.license, os: ['linux'], cpu: [platform.arch], libc: ['glibc'],
        engines: wrapper.engines, files: ['LICENSE', 'bin/', 'manifest.json'],
        repository: wrapper.repository, homepage: wrapper.homepage, bugs: wrapper.bugs,
        publishConfig: wrapper.publishConfig,
      };
      fs.writeFileSync(path.join(directory, 'package.json'), `${JSON.stringify(metadata, null, 2)}\n`, {flag: 'wx', mode: 0o644});
      fs.writeFileSync(path.join(directory, 'LICENSE'), license, {flag: 'wx', mode: 0o644});
      fs.writeFileSync(path.join(directory, 'manifest.json'), members.get('manifest.json'), {flag: 'wx', mode: 0o644});
      for (const name of ['orbit', 'orbit-web']) fs.writeFileSync(path.join(directory, 'bin', name), members.get(name), {flag: 'wx', mode: 0o755});
    }
    return releases.map(release => platforms[release.manifest.target].name);
  } catch (error) {
    fs.rmSync(output, {recursive: true, force: true});
    throw error;
  }
}

function main() {
  const archives = [];
  let output;
  const args = process.argv.slice(2);
  while (args.length) {
    const option = args.shift();
    if (!args.length || !['--archive', '--output'].includes(option)) throw new Error('Usage: node packaging/npm/stage.mjs --archive <release.tar.gz> [--archive <release.tar.gz>] --output <fresh-directory>');
    const value = args.shift();
    if (option === '--archive') archives.push(path.resolve(value));
    else if (output) throw new Error('Supply --output once.');
    else output = path.resolve(value);
  }
  if (!output) throw new Error('Supply --output <fresh-directory>.');
  console.log(JSON.stringify({version: JSON.parse(fs.readFileSync(path.join(source, 'package.json'), 'utf8')).version, packages: ['@fufugita/orbit', ...stage(archives, output)], output}));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) { console.error(`npm package: ${error.message}`); process.exitCode = 1; }
}
