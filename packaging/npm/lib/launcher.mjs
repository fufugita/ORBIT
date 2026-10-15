import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {nativePackage} from './platform.mjs';

const require = createRequire(import.meta.url);
const wrapper = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

export function launch(command) {
  try {
    if (!['orbit', 'orbit-web'].includes(command)) throw new Error('Unknown ORBIT executable.');
    if (typeof process.execve !== 'function') throw new Error('ORBIT requires Node.js 22.15+ or 23.11+. Upgrade Node.js and run the command again.');
    const packageName = nativePackage(process.platform, process.arch, process.report?.getReport().header.glibcVersionRuntime);
    let metadataPath;
    try {
      metadataPath = require.resolve(`${packageName}/package.json`);
    } catch {
      throw new Error(`Missing ${packageName}@${wrapper.version}. Reinstall with npm install --global --include=optional @fufugita/orbit@${wrapper.version}; do not use --omit=optional.`);
    }
    const native = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
    if (native.name !== packageName || native.version !== wrapper.version) {
      throw new Error(`ORBIT native package version mismatch. Reinstall @fufugita/orbit@${wrapper.version} with optional dependencies enabled.`);
    }
    const directory = path.join(path.dirname(metadataPath), 'bin');
    for (const name of ['orbit', 'orbit-web']) {
      let valid = false;
      try {
        const info = fs.lstatSync(path.join(directory, name));
        fs.accessSync(path.join(directory, name), fs.constants.X_OK);
        valid = info.isFile() && Boolean(info.mode & 0o111);
      } catch { /* A partial optional package receives the same repair advice. */ }
      if (!valid) throw new Error(`ORBIT native executable ${name} is missing or not executable. Reinstall @fufugita/orbit@${wrapper.version}.`);
    }
    const executable = path.join(directory, command);
    // Replacing this process preserves its PID, terminal, signal and exit status.
    process.execve(executable, [executable, ...process.argv.slice(2)], process.env);
  } catch (error) {
    process.stderr.write(`orbit: ${error.message}\n`);
    process.exitCode = 1;
  }
}
