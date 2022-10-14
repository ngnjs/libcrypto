// Identify JS runtime and version when possible
let runtime = globalThis.process !== undefined ? 'node' : (globalThis.hasOwnProperty('Deno') ? 'deno' : 'browser') // eslint-disable-line no-prototype-builtins
let runtimeVersion
const brands = globalThis?.navigator?.userAgentData?.brands || []

switch (runtime) {
  case 'node':
    runtimeVersion = process?.versions?.node
    break
  case 'deno':
    runtimeVersion = Deno?.version?.deno
    break
  case 'browser':
    if (brands && brands.length > 0) {
      const brand = brands.pop()
      runtime = brand.brand
      runtimeVersion = brand.version
    } else {
      const ua = globalThis?.navigator?.userAgent
      if (ua.includes('Firefox/')) {
        runtime = 'firefox'
        runtimeVersion = ua.split('Firefox/')[1]
      } else if (ua.includes('Safari/')) {
        runtime = 'safari'
        runtimeVersion = ua.split('Safari/')[1]
      }
    }
    break
}

export const version = runtimeVersion
export { runtime }
export const [major, minor, patch] = version.split('.').map(parseInt)

// Error on unsupported runtimes
if (runtime === 'node' && major < 15) {
  throw new Error('WebCrypto is only supported in Node.js 15.0.0 and higher')
}

// Normalize crypto library depending on runtime
let cryptography = globalThis?.crypto
if (runtime === 'node') {
  cryptography = (await import('crypto'))?.webcrypto
}

// Export common variables
export const HOUR = 60 * 60 * 1000
export { cryptography as crypto }
