const crypto = require('crypto');

// From: https://github.com/automerge/automerge-classic/blob/main/backend/sync.js

const BITS_PER_ENTRY = 10, NUM_PROBES = 7;

function getProbes(hash, byteLength) {
  const hashBytes = hexStringToBytes(hash), modulo = 8 * byteLength
  if (hashBytes.byteLength !== 32) throw new RangeError(`Not a 256-bit hash: ${hash}`)
  // on the next three lines, the right shift means interpret value as unsigned
  let x = ((hashBytes[0] | hashBytes[1] << 8 | hashBytes[2]  << 16 | hashBytes[3]  << 24) >>> 0) % modulo
  let y = ((hashBytes[4] | hashBytes[5] << 8 | hashBytes[6]  << 16 | hashBytes[7]  << 24) >>> 0) % modulo
  let z = ((hashBytes[8] | hashBytes[9] << 8 | hashBytes[10] << 16 | hashBytes[11] << 24) >>> 0) % modulo
  const probes = [x]
  for (let i = 1; i < NUM_PROBES; i++) {
    x = (x + y) % modulo
    y = (y + z) % modulo
    probes.push(x)
  }
  return probes
}


let numItems = 400;
let byteLength = 400 * 1.25;

let bucketsSeenNormal = {};
let bucketsSeenPoisoned = {};

for (let i = 0; i < 10000; i++) {
    let hash = crypto.createHash('sha256').update(`${i}`).digest();

    // Normal hash:

    for (let bucket of getProbes(hash.toString('hex'), byteLength)) {
        bucketsSeenNormal[bucket] = true;
    }

    // Poisoned hash:

    hash[0] &= ~7;
    hash[4] &= ~7;
    hash[8] &= ~7;

    for (let bucket of getProbes(hash.toString('hex'), byteLength)) {
        bucketsSeenPoisoned[bucket] = true;
    }
}

console.log("Normal: ", Object.keys(bucketsSeenNormal).length);
console.log("Poisoned: ", Object.keys(bucketsSeenPoisoned).length);




// Utils

function hexStringToBytes(value) {
  if (typeof value !== 'string') {
    throw new TypeError('value is not a string')
  }
  if (!/^([0-9a-f][0-9a-f])*$/.test(value)) {
    throw new RangeError('value is not hexadecimal')
  }
  if (value === '') {
    return new Uint8Array(0)
  } else {
    return new Uint8Array(value.match(/../g).map(b => parseInt(b, 16)))
  }
}
