// MinHash signature + Jaccard for bytecode similarity.
//
// - 128 permutations.
// - 4-byte shingles of raw bytecode (stride 1, overlapping).
// - Modulus 2^31 - 1 (Mersenne prime).
// - (a, b) pairs are deterministic from a fixed seed so signatures
//   are stable across runs, process boundaries, and language ports.

const PERMUTATIONS = 128;
const MOD = 0x7fffffff; // 2^31 - 1

function splitmix32(seed: number): () => number {
  let s = seed | 0;
  return () => {
    s = (s + 0x9e3779b9) | 0;
    let z = s;
    z = Math.imul(z ^ (z >>> 16), 0x21f0aaad);
    z = Math.imul(z ^ (z >>> 15), 0x735a2d97);
    return (z ^ (z >>> 15)) >>> 0;
  };
}

const A: number[] = new Array(PERMUTATIONS);
const B: number[] = new Array(PERMUTATIONS);
{
  const rng = splitmix32(0x1a2b3c4d);
  for (let i = 0; i < PERMUTATIONS; i++) {
    A[i] = (rng() % (MOD - 1)) + 1;
    B[i] = rng() % MOD;
  }
}

// (a * x) mod MOD computed safely — a * x overflows JS safe integers
// for large factors, so split a into hi/lo 16-bit halves.
function mulmod(a: number, x: number): number {
  const a_hi = (a >>> 16) & 0xffff;
  const a_lo = a & 0xffff;
  return ((a_hi * x) % MOD * 0x10000 + a_lo * x) % MOD;
}

export function hexToBytes(hex: string): Uint8Array {
  const s = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(s.length >> 1);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.substr(i << 1, 2), 16);
  }
  return out;
}

export function computeMinHash(bytecode: string): number[] | null {
  const bytes = hexToBytes(bytecode);
  if (bytes.length < 4) return null;
  const sig = new Array<number>(PERMUTATIONS).fill(MOD);
  const end = bytes.length - 4;
  for (let i = 0; i <= end; i++) {
    const x =
      ((bytes[i] << 24) | (bytes[i + 1] << 16) | (bytes[i + 2] << 8) | bytes[i + 3]) >>> 0;
    for (let j = 0; j < PERMUTATIONS; j++) {
      const h = (mulmod(A[j], x) + B[j]) % MOD;
      if (h < sig[j]) sig[j] = h;
    }
  }
  return sig;
}

export function jaccardSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length) return 0;
  let m = 0;
  for (let i = 0; i < a.length; i++) if (a[i] === b[i]) m++;
  return m / a.length;
}
