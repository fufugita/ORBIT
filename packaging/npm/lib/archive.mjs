import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {platforms} from './platform.mjs';

const MAX_ARCHIVE = 512 * 1024 * 1024;
const MAX_BINARY = 256 * 1024 * 1024;
const names = ['manifest.json', 'orbit', 'orbit-web'];
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

function readRegular(file, limit) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.size <= 0 || before.size > limit) throw new Error(`Invalid or oversized input: ${path.basename(file)}`);
    const data = Buffer.alloc(before.size);
    let received = 0;
    while (received < data.length) {
      const count = fs.readSync(fd, data, received, data.length - received, null);
      if (!count) break;
      received += count;
    }
    const overflow = fs.readSync(fd, Buffer.alloc(1), 0, 1, null);
    const after = fs.fstatSync(fd);
    if (received !== data.length || overflow || ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs'].some(key => before[key] !== after[key])) throw new Error('Input changed during packaging.');
    return data;
  } finally {
    fs.closeSync(fd);
  }
}

function textField(bytes) {
  const nul = bytes.indexOf(0);
  if (nul !== -1 && bytes.subarray(nul).some(byte => byte !== 0)) throw new Error('Malformed tar string field.');
  const content = nul === -1 ? bytes : bytes.subarray(0, nul);
  if (content.some(byte => byte > 127)) throw new Error('Non-ASCII tar field.');
  return content.toString('ascii');
}

function octal(bytes) {
  const value = bytes.toString('ascii').replace(/[\0 ]+$/g, '').trim();
  if (!/^[0-7]+$/.test(value)) throw new Error('Malformed tar numeric field.');
  const number = Number.parseInt(value, 8);
  if (!Number.isSafeInteger(number)) throw new Error('Oversized tar numeric field.');
  return number;
}

export function readTar(tar) {
  if (tar.length % 512 !== 0) throw new Error('Truncated tar archive.');
  const members = new Map();
  let offset = 0;
  for (; offset + 512 <= tar.length; ) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every(byte => byte === 0)) break;
    const expected = octal(header.subarray(148, 156));
    const checksum = header.reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0);
    if (checksum !== expected) throw new Error('Invalid tar header checksum.');
    const name = textField(header.subarray(0, 100));
    if (!names.includes(name) || members.has(name)) throw new Error('Unexpected or duplicate archive member.');
    if (textField(header.subarray(345, 500)) || textField(header.subarray(157, 257)) || ![0, 48].includes(header[156])) throw new Error('Archive members must be plain regular files.');
    if (!header.subarray(257, 265).equals(Buffer.concat([Buffer.from('ustar\0'), Buffer.from('00')]))) throw new Error('Expected a USTAR release archive.');
    const size = octal(header.subarray(124, 136));
    const mode = octal(header.subarray(100, 108));
    if (size <= 0 || size > (name === 'manifest.json' ? 16384 : MAX_BINARY)) throw new Error('Invalid archive member size.');
    if (name !== 'manifest.json' && (!(mode & 0o111) || (mode & 0o7000))) throw new Error('Archive binaries require ordinary executable permissions.');
    const start = offset + 512;
    const end = start + size;
    const padded = start + Math.ceil(size / 512) * 512;
    if (padded > tar.length || tar.subarray(end, padded).some(byte => byte !== 0)) throw new Error('Truncated member or nonzero tar padding.');
    members.set(name, tar.subarray(start, end));
    offset = padded;
  }
  if (members.size !== 3 || tar.length - offset < 1024 || tar.subarray(offset).some(byte => byte !== 0)) throw new Error('Expected three members and a complete tar terminator.');
  return members;
}

function exactKeys(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

export function verifyMembers(members, version) {
  const manifest = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(members.get('manifest.json')));
  if (!exactKeys(manifest, ['schema_version', 'version', 'target', 'components', 'signature']) || manifest.schema_version !== 1 || manifest.version !== version || manifest.signature !== 'absent' || !Object.hasOwn(platforms, manifest.target)) throw new Error('Release manifest version, schema, signature or target is unsupported.');
  if (!exactKeys(manifest.components, ['orbit', 'orbit-web'])) throw new Error('Release manifest must describe both native executables.');
  const machine = platforms[manifest.target].arch === 'x64' ? 62 : 183;
  for (const name of ['orbit', 'orbit-web']) {
    const item = manifest.components[name];
    const bytes = members.get(name);
    if (!exactKeys(item, ['size', 'sha256']) || item.size !== bytes.length || !/^[0-9a-f]{64}$/.test(item.sha256) || sha256(bytes) !== item.sha256) throw new Error(`Release component ${name} checksum or size mismatch.`);
    if (bytes.length < 64 || !bytes.subarray(0, 7).equals(Buffer.from([127, 69, 76, 70, 2, 1, 1])) || ![0, 3].includes(bytes[7]) || ![2, 3].includes(bytes.readUInt16LE(16)) || bytes.readUInt16LE(18) !== machine || bytes.readUInt32LE(20) !== 1 || bytes.readUInt16LE(52) !== 64) throw new Error(`Release component ${name} does not match its Linux ELF architecture.`);
  }
  return manifest;
}

export function verifyArchive(file, version) {
  const archive = readRegular(file, MAX_ARCHIVE);
  const checksum = readRegular(`${file}.sha256`, 1024).toString('utf8');
  const match = /^([0-9a-f]{64})  ([^\r\n]+)\n?$/.exec(checksum);
  if (!match || match[2] !== path.basename(file) || sha256(archive) !== match[1]) throw new Error('Release archive SHA256 sidecar mismatch.');
  const tar = gunzipSync(archive, {maxOutputLength: MAX_ARCHIVE + 65536});
  const members = readTar(tar);
  return {manifest: verifyMembers(members, version), members};
}
