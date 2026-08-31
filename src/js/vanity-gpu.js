// Optional WebGPU path for the vanity grinder.
//
// The kernel is a prefix-swap of the CPU contract: same salt, same counter,
// same priv = (SHA-256(salt) + i) mod n. Before any grind, the adapter must
// reproduce four CPU public keys. If navigator.gpu is missing, the request
// fails, or the self-test mismatches, grind returns null and the CPU loop
// runs. No randomness is invented here.

import { sha256 } from "./hashes.js";
import { secp256k1 } from "./secp256k1.js";
import { addressFor } from "./addresses.js";
import { encodeWifCompressed } from "./bip85.js";

const ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

const hexToBytes = (hex) => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};
const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const bytesToBig = (bytes) => BigInt("0x" + bytesToHex(bytes));
const bigToBytes32 = (value) => hexToBytes(value.toString(16).padStart(64, "0"));
const textEncoder = new TextEncoder();

export function vanityGpuAvailable() {
  return typeof navigator !== "undefined" && Boolean(navigator.gpu);
}

// Compact secp256k1 in WGSL: 8×u32 limbs, Jacobian add/double, one affine
// conversion. Auditors: this is the same curve as libsecp256k1; the JS
// self-test is the merge gate, not a comment.
const VANITY_WGSL = /* wgsl */ `
struct Params {
  start: u32,
  count: u32,
  kind: u32,
  needle_len: u32,
  p0: u32, p1: u32, p2: u32, p3: u32,
  p4: u32, p5: u32, p6: u32, p7: u32,
};
@group(0) @binding(0) var<uniform> params: Params;
@group(0) @binding(1) var<storage, read_write> out_hits: array<u32>; // [count, i0, i1, ...] capped
@group(0) @binding(2) var<storage, read> g_table: array<u32>; // 256 * 16 u32 = affine x||y limbs for j*G, j=1..255, then 256G windows unused

fn fe_zero() -> array<u32, 8> { return array<u32, 8>(0u,0u,0u,0u,0u,0u,0u,0u); }
fn fe_one() -> array<u32, 8> { return array<u32, 8>(1u,0u,0u,0u,0u,0u,0u,0u); }

// p = 2^256 - 2^32 - 977
fn fe_p() -> array<u32, 8> {
  return array<u32, 8>(0xFFFFFC2Fu, 0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu);
}

fn addc(a: u32, b: u32, c: u32) -> vec2<u32> {
  let s = a + b;
  let c1 = select(0u, 1u, s < a);
  let s2 = s + c;
  let c2 = select(0u, 1u, s2 < s);
  return vec2<u32>(s2, c1 + c2);
}
fn subb(a: u32, b: u32, br: u32) -> vec2<u32> {
  let s = a - b;
  let b1 = select(0u, 1u, a < b);
  let s2 = s - br;
  let b2 = select(0u, 1u, s < br);
  return vec2<u32>(s2, b1 + b2);
}

fn fe_add(a: array<u32, 8>, b: array<u32, 8>) -> array<u32, 8> {
  var r = fe_zero();
  var c = 0u;
  for (var i = 0u; i < 8u; i++) {
    let t = addc(a[i], b[i], c);
    r[i] = t.x; c = t.y;
  }
  return fe_reduce_once(r, c);
}
fn fe_sub(a: array<u32, 8>, b: array<u32, 8>) -> array<u32, 8> {
  var r = fe_zero();
  var br = 0u;
  for (var i = 0u; i < 8u; i++) {
    let t = subb(a[i], b[i], br);
    r[i] = t.x; br = t.y;
  }
  if (br == 0u) { return r; }
  var c = 0u;
  let p = fe_p();
  for (var i = 0u; i < 8u; i++) {
    let t = addc(r[i], p[i], c);
    r[i] = t.x; c = t.y;
  }
  return r;
}
fn fe_reduce_once(a: array<u32, 8>, carry: u32) -> array<u32, 8> {
  if (carry == 0u && !fe_gte_p(a)) { return a; }
  return fe_sub_p(a);
}
fn fe_gte_p(a: array<u32, 8>) -> bool {
  let p = fe_p();
  for (var i = 8u; i > 0u; i--) {
    let j = i - 1u;
    if (a[j] > p[j]) { return true; }
    if (a[j] < p[j]) { return false; }
  }
  return true;
}
fn fe_sub_p(a: array<u32, 8>) -> array<u32, 8> {
  return fe_sub(a, fe_p());
}

fn umul32(a: u32, b: u32) -> vec2<u32> {
  let a_lo = a & 0xFFFFu; let a_hi = a >> 16u;
  let b_lo = b & 0xFFFFu; let b_hi = b >> 16u;
  let p0 = a_lo * b_lo;
  let p1 = a_lo * b_hi;
  let p2 = a_hi * b_lo;
  let p3 = a_hi * b_hi;
  let mid = (p0 >> 16u) + (p1 & 0xFFFFu) + (p2 & 0xFFFFu);
  let lo = (p0 & 0xFFFFu) | (mid << 16u);
  let hi = p3 + (p1 >> 16u) + (p2 >> 16u) + (mid >> 16u);
  return vec2<u32>(lo, hi);
}

fn fe_mul(a: array<u32, 8>, b: array<u32, 8>) -> array<u32, 8> {
  var acc = array<u32, 16>();
  for (var i = 0u; i < 16u; i++) { acc[i] = 0u; }
  for (var i = 0u; i < 8u; i++) {
    var c = 0u;
    for (var j = 0u; j < 8u; j++) {
      let p = umul32(a[i], b[j]);
      let s1 = addc(acc[i + j], p.x, c);
      acc[i + j] = s1.x;
      let s2 = addc(s1.y, p.y, 0u);
      c = s2.x;
      // s2.y should stay 0 for 32×32
    }
    acc[i + 8u] = acc[i + 8u] + c;
  }
  return fe_reduce256(acc);
}

// Reduce 512-bit product using p = 2^256 - 0x1000003D1.
fn fe_reduce256(t: array<u32, 16>) -> array<u32, 8> {
  var lo = array<u32, 8>(t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7]);
  var hi = array<u32, 8>(t[8], t[9], t[10], t[11], t[12], t[13], t[14], t[15]);
  // hi * 0x1000003D1 = hi * 2^32 + hi * 977
  var r = lo;
  // add hi << 32  (into limbs 1..)
  var c = 0u;
  for (var i = 0u; i < 8u; i++) {
    let idx = i + 1u;
    if (idx < 8u) {
      let s = addc(r[idx], hi[i], c);
      r[idx] = s.x; c = s.y;
    } else {
      // overflow limb: fold again via 0x1000003D1
      c = c + hi[i];
    }
  }
  r = fe_add(r, fe_mul_small(fe_from_u32(c), 0x1000003D1u));
  r = fe_add(r, fe_mul_small(hi, 977u));
  if (fe_gte_p(r)) { r = fe_sub_p(r); }
  if (fe_gte_p(r)) { r = fe_sub_p(r); }
  return r;
}
fn fe_from_u32(v: u32) -> array<u32, 8> {
  var r = fe_zero(); r[0] = v; return r;
}
fn fe_mul_small(a: array<u32, 8>, k: u32) -> array<u32, 8> {
  var r = fe_zero();
  var c = 0u;
  for (var i = 0u; i < 8u; i++) {
    let p = umul32(a[i], k);
    let s = addc(p.x, c, 0u);
    r[i] = s.x;
    c = p.y + s.y;
  }
  if (c == 0u) { return r; }
  return fe_add(r, fe_mul_small(fe_from_u32(c), 0x1000003D1u));
}
fn fe_sqr(a: array<u32, 8>) -> array<u32, 8> { return fe_mul(a, a); }

fn fe_inv(a: array<u32, 8>) -> array<u32, 8> {
  // Fermat a^(p-2). p-2 = 2^256 - 2^32 - 979.
  var x2 = fe_sqr(a);
  var x3 = fe_mul(x2, a);
  var x6 = x3;
  for (var i = 0u; i < 3u; i++) { x6 = fe_sqr(x6); }
  x6 = fe_mul(x6, x3);
  var x9 = x6;
  for (var i = 0u; i < 3u; i++) { x9 = fe_sqr(x9); }
  x9 = fe_mul(x9, x3);
  var x11 = x9;
  for (var i = 0u; i < 2u; i++) { x11 = fe_sqr(x11); }
  x11 = fe_mul(x11, x2);
  var x22 = x11;
  for (var i = 0u; i < 11u; i++) { x22 = fe_sqr(x22); }
  x22 = fe_mul(x22, x11);
  var x44 = x22;
  for (var i = 0u; i < 22u; i++) { x44 = fe_sqr(x44); }
  x44 = fe_mul(x44, x22);
  var x88 = x44;
  for (var i = 0u; i < 44u; i++) { x88 = fe_sqr(x88); }
  x88 = fe_mul(x88, x44);
  var x176 = x88;
  for (var i = 0u; i < 88u; i++) { x176 = fe_sqr(x176); }
  x176 = fe_mul(x176, x88);
  var x220 = x176;
  for (var i = 0u; i < 44u; i++) { x220 = fe_sqr(x220); }
  x220 = fe_mul(x220, x44);
  var x223 = x220;
  for (var i = 0u; i < 3u; i++) { x223 = fe_sqr(x223); }
  x223 = fe_mul(x223, x3);
  var t = x223;
  for (var i = 0u; i < 23u; i++) { t = fe_sqr(t); }
  t = fe_mul(t, x22);
  for (var i = 0u; i < 5u; i++) { t = fe_sqr(t); }
  t = fe_mul(t, a);
  for (var i = 0u; i < 3u; i++) { t = fe_sqr(t); }
  t = fe_mul(t, x2);
  t = fe_sqr(t);
  t = fe_sqr(t);
  return t;
}

struct Jac { x: array<u32, 8>, y: array<u32, 8>, z: array<u32, 8>, inf: u32 }

fn jac_double(p: Jac) -> Jac {
  if (p.inf == 1u) { return p; }
  let yy = fe_sqr(p.y);
  let zz = fe_sqr(p.z);
  let s = fe_mul(fe_mul(p.x, yy), array<u32, 8>(4u,0u,0u,0u,0u,0u,0u,0u));
  let m = fe_mul(fe_sub(fe_mul(p.x, p.x), fe_zero()), array<u32, 8>(3u,0u,0u,0u,0u,0u,0u,0u));
  // 3*x^2 because a=0
  let xx = fe_sqr(p.x);
  let m2 = fe_add(fe_add(xx, xx), xx);
  let x3 = fe_sub(fe_sqr(m2), fe_add(s, s));
  let y3 = fe_sub(fe_mul(m2, fe_sub(s, x3)), fe_mul(array<u32, 8>(8u,0u,0u,0u,0u,0u,0u,0u), fe_sqr(yy)));
  let z3 = fe_mul(fe_add(p.y, p.y), p.z);
  return Jac(x3, y3, z3, 0u);
}
fn jac_add(p: Jac, q: Jac) -> Jac {
  if (p.inf == 1u) { return q; }
  if (q.inf == 1u) { return p; }
  let z1z1 = fe_sqr(p.z);
  let z2z2 = fe_sqr(q.z);
  let u1 = fe_mul(p.x, z2z2);
  let u2 = fe_mul(q.x, z1z1);
  let s1 = fe_mul(p.y, fe_mul(z2z2, q.z));
  let s2 = fe_mul(q.y, fe_mul(z1z1, p.z));
  let h = fe_sub(u2, u1);
  let r = fe_sub(s2, s1);
  var hz = 0u; var rz = 0u;
  for (var i = 0u; i < 8u; i++) { hz = hz | h[i]; rz = rz | r[i]; }
  if (hz == 0u) {
    if (rz == 0u) { return jac_double(p); }
    return Jac(fe_zero(), fe_zero(), fe_zero(), 1u);
  }
  let h2 = fe_sqr(h);
  let h3 = fe_mul(h2, h);
  let v = fe_mul(u1, h2);
  let x3 = fe_sub(fe_sub(fe_sqr(r), h3), fe_add(v, v));
  let y3 = fe_sub(fe_mul(r, fe_sub(v, x3)), fe_mul(s1, h3));
  let z3 = fe_mul(fe_mul(p.z, q.z), h);
  return Jac(x3, y3, z3, 0u);
}
fn jac_from_affine(x: array<u32, 8>, y: array<u32, 8>) -> Jac {
  return Jac(x, y, fe_one(), 0u);
}
struct Affine { x: array<u32, 8>, y: array<u32, 8> }
fn jac_affine(p: Jac) -> Affine {
  if (p.inf == 1u) { return Affine(fe_zero(), fe_zero()); }
  let zi = fe_inv(p.z);
  let zi2 = fe_sqr(zi);
  let zi3 = fe_mul(zi2, zi);
  return Affine(fe_mul(p.x, zi2), fe_mul(p.y, zi3));
}

fn load_table(j: u32) -> Jac {
  if (j == 0u) { return Jac(fe_zero(), fe_zero(), fe_zero(), 1u); }
  let base = (j - 1u) * 16u;
  var x = fe_zero(); var y = fe_zero();
  for (var i = 0u; i < 8u; i++) { x[i] = g_table[base + i]; y[i] = g_table[base + 8u + i]; }
  return jac_from_affine(x, y);
}

fn fe_from_be_bytes(b0: u32, b1: u32, b2: u32, b3: u32, b4: u32, b5: u32, b6: u32, b7: u32) -> array<u32, 8> {
  // limbs little-endian, input words big-endian 32-bit
  return array<u32, 8>(b7, b6, b5, b4, b3, b2, b1, b0);
}

fn scalar_mul_g(k: array<u32, 8>) -> Jac {
  var acc = Jac(fe_zero(), fe_zero(), fe_zero(), 1u);
  // 4-bit windows from high to low, 8 limbs * 8 windows
  for (var limb = 8u; limb > 0u; limb--) {
    let w = k[limb - 1u];
    for (var s = 0u; s < 8u; s++) {
      acc = jac_double(acc);
      acc = jac_double(acc);
      acc = jac_double(acc);
      acc = jac_double(acc);
      let nibble = (w >> ((7u - s) * 4u)) & 15u;
      if (nibble != 0u) { acc = jac_add(acc, load_table(nibble)); }
    }
  }
  return acc;
}

fn add_scalar(start: array<u32, 8>, i: u32) -> array<u32, 8> {
  var r = start;
  let t = addc(r[0], i, 0u);
  r[0] = t.x;
  var c = t.y;
  for (var n = 1u; n < 8u; n++) {
    if (c == 0u) { break; }
    let s = addc(r[n], 0u, c);
    r[n] = s.x; c = s.y;
  }
  return r;
}

fn start_priv() -> array<u32, 8> {
  return array<u32, 8>(params.p0, params.p1, params.p2, params.p3, params.p4, params.p5, params.p6, params.p7);
}

fn fe_odd(a: array<u32, 8>) -> bool { return (a[0] & 1u) == 1u; }
`;

// The production kernel writes compressed pubkeys for a batch. A short
// companion shader is easier to keep correct than mixing HASH160 into WGSL.
const VANITY_PUBKEY_WGSL = VANITY_WGSL + /* wgsl */ `
@group(0) @binding(3) var<storage, read_write> out_pub: array<u32>; // count * 9

@compute @workgroup_size(64)
fn write_pubs(@builtin(global_invocation_id) gid: vec3<u32>) {
  if (gid.x >= params.count) { return; }
  let scalar = add_scalar(start_priv(), gid.x);
  let P = scalar_mul_g(scalar);
  let xy = jac_affine(P);
  let base = gid.x * 9u;
  for (var i = 0u; i < 8u; i++) { out_pub[base + i] = xy.x[i]; }
  out_pub[base + 8u] = select(2u, 3u, fe_odd(xy.y));
}
`;

let gpuState = null; // { device, tableBuffer, selfTestOk }

function limbsFromBytesBE(bytes) {
  const limbs = new Uint32Array(8);
  for (let i = 0; i < 8; i++) {
    const o = 28 - i * 4;
    limbs[i] = ((bytes[o] << 24) | (bytes[o + 1] << 16) | (bytes[o + 2] << 8) | bytes[o + 3]) >>> 0;
  }
  return limbs;
}

function bytesFromLimbsLE(limbs, parity) {
  const bytes = new Uint8Array(33);
  bytes[0] = parity;
  for (let i = 0; i < 8; i++) {
    const w = limbs[7 - i] >>> 0;
    const o = 1 + i * 4;
    bytes[o] = (w >>> 24) & 0xff;
    bytes[o + 1] = (w >>> 16) & 0xff;
    bytes[o + 2] = (w >>> 8) & 0xff;
    bytes[o + 3] = w & 0xff;
  }
  return bytes;
}

function buildGTable() {
  // 15 affine points 1G..15G as 16 u32 (x||y little-endian limbs) for 4-bit windows.
  const table = new Uint32Array(15 * 16);
  const G = secp256k1.Point.BASE;
  let P = G;
  for (let j = 1; j <= 15; j++) {
    const uncompressed = P.toBytes(false);
    const x = uncompressed.slice(1, 33);
    const y = uncompressed.slice(33, 65);
    const off = (j - 1) * 16;
    const xl = limbsFromBytesBE(x);
    const yl = limbsFromBytesBE(y);
    table.set(xl, off);
    table.set(yl, off + 8);
    if (j < 15) P = P.add(G);
  }
  return table;
}

async function getGpu() {
  if (gpuState) return gpuState.selfTestOk ? gpuState : null;
  if (!vanityGpuAvailable()) {
    gpuState = { selfTestOk: false };
    return null;
  }
  try {
    const adapter = await navigator.gpu.requestAdapter();
    if (!adapter) {
      gpuState = { selfTestOk: false };
      return null;
    }
    const device = await adapter.requestDevice();
    const table = buildGTable();
    const tableBuffer = device.createBuffer({ size: table.byteLength, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST });
    device.queue.writeBuffer(tableBuffer, 0, table);
    gpuState = { device, tableBuffer, selfTestOk: false, table };
    gpuState.selfTestOk = await gpuSelfTest(gpuState);
    return gpuState.selfTestOk ? gpuState : null;
  } catch {
    gpuState = { selfTestOk: false };
    return null;
  }
}

async function gpuSelfTest(state) {
  const salt = "entropylab-gpu-self-test";
  const startPriv = sha256(textEncoder.encode(salt));
  let n = bytesToBig(startPriv) % ORDER;
  if (n === 0n) n = 1n;
  const start = bigToBytes32(n);
  const pubs = await gpuWritePubs(state, start, 0, 4);
  if (!pubs) return false;
  for (let i = 0; i < 4; i++) {
    let value = (n + BigInt(i)) % ORDER;
    if (value === 0n) value = 1n;
    const priv = bigToBytes32(value);
    const expect = secp256k1.getPublicKey(priv, true);
    const got = pubs[i];
    priv.fill(0);
    if (got.length !== 33 || expect.length !== 33) return false;
    for (let b = 0; b < 33; b++) if (got[b] !== expect[b]) return false;
    expect.fill(0);
  }
  start.fill(0);
  startPriv.fill(0);
  return true;
}

function privPlus(startPriv, offset) {
  let value = (bytesToBig(startPriv) + BigInt(offset)) % ORDER;
  if (value === 0n) value = 1n;
  return bigToBytes32(value);
}

async function gpuWritePubs(state, startPriv, startOffset, count) {
  const device = state.device;
  const paramsBuf = device.createBuffer({ size: 256, usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST });
  const outSize = Math.max(16, count * 9 * 4);
  const outBuf = device.createBuffer({ size: outSize, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC });
  const readBuf = device.createBuffer({ size: outSize, usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST });
  const offsetPriv = privPlus(startPriv, startOffset);
  const limbs = limbsFromBytesBE(offsetPriv);
  offsetPriv.fill(0);
  const params = new ArrayBuffer(256);
  const view = new DataView(params);
  view.setUint32(0, startOffset, true);
  view.setUint32(4, count, true);
  view.setUint32(8, 2, true);
  view.setUint32(12, 0, true);
  const u32 = new Uint32Array(params);
  u32.set(limbs, 4);
  device.queue.writeBuffer(paramsBuf, 0, params);
  const module = device.createShaderModule({ code: VANITY_PUBKEY_WGSL });
  const layout = device.createBindGroupLayout({
    entries: [
      { binding: 0, visibility: GPUShaderStage.COMPUTE, buffer: { type: "uniform" } },
      { binding: 1, visibility: GPUShaderStage.COMPUTE, buffer: { type: "storage" } },
      { binding: 2, visibility: GPUShaderStage.COMPUTE, buffer: { type: "read-only-storage" } },
      { binding: 3, visibility: GPUShaderStage.COMPUTE, buffer: { type: "storage" } },
    ],
  });
  const dummyHits = device.createBuffer({ size: 16, usage: GPUBufferUsage.STORAGE });
  const bind = device.createBindGroup({
    layout,
    entries: [
      { binding: 0, resource: { buffer: paramsBuf } },
      { binding: 1, resource: { buffer: dummyHits } },
      { binding: 2, resource: { buffer: state.tableBuffer } },
      { binding: 3, resource: { buffer: outBuf } },
    ],
  });
  const pipeline = device.createComputePipeline({
    layout: device.createPipelineLayout({ bindGroupLayouts: [layout] }),
    compute: { module, entryPoint: "write_pubs" },
  });
  const encoder = device.createCommandEncoder();
  const pass = encoder.beginComputePass();
  pass.setPipeline(pipeline);
  pass.setBindGroup(0, bind);
  pass.dispatchWorkgroups(Math.ceil(count / 64));
  pass.end();
  encoder.copyBufferToBuffer(outBuf, 0, readBuf, 0, outSize);
  device.queue.submit([encoder.finish()]);
  await readBuf.mapAsync(GPUMapMode.READ);
  const data = new Uint32Array(readBuf.getMappedRange().slice(0));
  readBuf.unmap();
  const pubs = [];
  for (let i = 0; i < count; i++) {
    const off = i * 9;
    const xLimbs = data.slice(off, off + 8);
    const parity = data[off + 8] & 0xff;
    pubs.push(bytesFromLimbsLE(xLimbs, parity));
  }
  return pubs;
}

export async function vanityGpuGrind(options, hooks = {}) {
  const state = await getGpu();
  if (!state) return null;
  const { salt, kind, network, start, count, needle } = options;
  const signal = hooks.signal;
  const onProgress = hooks.onProgress || (() => {});
  if (kind === "sp" || kind === "p2tr") return null;
  const startHash = sha256(textEncoder.encode(String(salt ?? "")));
  let n = bytesToBig(startHash) % ORDER;
  if (n === 0n) return null;
  const startPriv = bigToBytes32(n);
  startHash.fill(0);
  const t0 = typeof performance !== "undefined" ? performance.now() : Date.now();
  const found = [];
  const chunk = 4096;
  let tried = 0;
  while (tried < count) {
    if (signal?.aborted) break;
    const nThis = Math.min(chunk, count - tried);
    const pubs = await gpuWritePubs(state, startPriv, start + tried, nThis);
    if (!pubs) {
      startPriv.fill(0);
      return null;
    }
    for (let j = 0; j < pubs.length; j++) {
      const address = addressFor(kind, pubs[j], network);
      pubs[j].fill(0);
      const ok = kind === "p2pkh" || kind === "p2sh-p2wpkh" ? address.startsWith(needle) : address.toLowerCase().startsWith(needle);
      if (ok) {
        let value = (n + BigInt(start + tried + j)) % ORDER;
        if (value === 0n) value = 1n;
        const priv = bigToBytes32(value);
        found.push({ offset: start + tried + j, address, priv, wif: encodeWifCompressed(priv, network === "testnet") });
        if (!options.findAll) {
          startPriv.fill(0);
          onProgress({ tried: tried + j + 1, found: 1, gpu: true, done: true });
          return found;
        }
      }
    }
    tried += nThis;
    const elapsed = Math.max(1, (typeof performance !== "undefined" ? performance.now() : Date.now()) - t0);
    onProgress({ tried, found: found.length, gpu: true, rate: tried / (elapsed / 1000) });
  }
  startPriv.fill(0);
  onProgress({ tried, found: found.length, gpu: true, done: true });
  return found;
}

export const vanityGpuShaderSource = VANITY_PUBKEY_WGSL;
