export const platforms = Object.freeze({
  'x86_64-unknown-linux-gnu': Object.freeze({arch: 'x64', name: '@fufugita/orbit-linux-x64-gnu'}),
  'aarch64-unknown-linux-gnu': Object.freeze({arch: 'arm64', name: '@fufugita/orbit-linux-arm64-gnu'}),
});

export function nativePackage(platform, arch, glibcVersion) {
  const sourceAdvice = 'Install with Homebrew or build from source: https://github.com/fufugita/ORBIT#install';
  if (platform !== 'linux' || !['x64', 'arm64'].includes(arch)) {
    throw new Error(`ORBIT supports Linux glibc on x64 and arm64; detected ${platform}/${arch}. ${sourceAdvice}`);
  }
  const match = typeof glibcVersion === 'string' && glibcVersion.length <= 32
    ? /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?$/.exec(glibcVersion) : null;
  if (!match || !match.slice(1).filter(value => value !== undefined).every(value => Number.isSafeInteger(Number(value)))) {
    throw new Error(`ORBIT's prebuilt Linux binaries require glibc 2.35 or newer; the glibc version could not be determined. ${sourceAdvice}`);
  }
  const major = Number(match[1]);
  const minor = Number(match[2]);
  if (major < 2 || (major === 2 && minor < 35)) throw new Error(`ORBIT's prebuilt Linux binaries require glibc 2.35 or newer; detected glibc ${glibcVersion}. ${sourceAdvice}`);
  return Object.values(platforms).find(value => value.arch === arch).name;
}
