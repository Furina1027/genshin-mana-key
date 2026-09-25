#!/usr/bin/env node
/**
 * usm_decrypt.mjs — 原神 7.1 USM 视频解密（method2 / AES-128-CTR）
 *
 * ★ 已实测确认的参数（2026-09-24，BCryptGenerateSymmetricKey + BCryptEncrypt 截获）：
 *   key      = F5AC17FFE4B4B430553AE073EB8A8A1D
 *              （全局固定，跨会话/跨视频不变；CRI 用 BCrypt + ChainingModeECB 构造 CTR）
 *   counter  = nonce(8B) || BE32(frameTime) || BE32(blockIndex)
 *              blockIndex 从 0 起、16 字节大端递增
 *   keystream = AES-128-ECB(counter)  ← 只加密 counter 块，再与数据 XOR
 *   加密区   = 每个 chunk 的 payload[0x40:]
 *              · 首个 chunk 含 32 字节 IVF 文件头：payload = IVF头(32) + 帧条目(12) + 帧数据
 *                → payload[0x40:] 对应帧数据偏移 20
 *              · 其余 chunk：payload = 帧条目(12) + 帧数据
 *                → payload[0x40:] 对应帧数据偏移 52
 *   注意：长度 <= 0x40 的 chunk 没有加密区（小帧整体明文），解密时自动跳过。
 *
 * 用法：
 *   node usm_decrypt.mjs <file.usm> [-o out.ivf] [--key HEX32] [--nomkv]
 */
import { createCipheriv } from 'node:crypto'
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs'
import { execFileSync } from 'node:child_process'

const o = { key: 'F5AC17FFE4B4B430553AE073EB8A8A1D', nomkv: false, keepivf: false }
const a = process.argv.slice(2)
o.usm = a[0]
// 注意：必须剥掉所有前导 '-'，否则 '-o' 会变成 o['-o'] 而不是 o.o
for (let i = 1; i < a.length; i += 2) o[a[i].replace(/^-+/, '')] = a[i + 1]

const KEY = Buffer.from(o.key, 'hex')
const buf = readFileSync(o.usm)

// ---- nonce ----
const ij = buf.indexOf(Buffer.from('<NULL>\x00VIDEO_HDRINFO', 'latin1'))
if (ij < 8) { console.error('找不到 VIDEO_HDRINFO / nonce'); process.exit(1) }
const nonce = buf.subarray(ij - 8, ij)
console.log('nonce =', nonce.toString('hex'))

// ---- chunks ----
function parseChunks(b) {
  const out = []; let pos = 0; const n = b.length
  while (pos + 24 <= n) {
    const size = b.readUInt32BE(pos + 4)
    if (size === 0 || pos + size + 8 > n) break
    const dof = b[pos + 9], pad = b.readUInt16BE(pos + 10)
    out.push({ typ: b.subarray(pos, pos + 4).toString('latin1'), dt: b[pos + 15] & 3,
      ft: b.readUInt32BE(pos + 16), ds: pos + 8 + dof, dl: size - dof - pad })
    pos += size + 8
  }
  return out
}
const vid = parseChunks(buf).filter(c => c.typ === '@SFV' && c.dt === 0)
console.log('视频块 =', vid.length)

// ---- 解密 ----
const cipher = createCipheriv('aes-128-ecb', KEY, null)
cipher.setAutoPadding(false)
function keystream(counter0, blocks) {
  const src = Buffer.alloc(blocks * 16)
  for (let i = 0; i < blocks; i++) {
    counter0.copy(src, i * 16, 0, 12)
    src.writeUInt32BE(i, i * 16 + 12)
  }
  const c = createCipheriv('aes-128-ecb', KEY, null); c.setAutoPadding(false)
  return Buffer.concat([c.update(src), c.final()])
}

let ivf = null
const frames = []     // { ts, data }
let decBytes = 0
for (let i = 0; i < vid.length; i++) {
  const c = vid[i]
  const p = Buffer.from(buf.subarray(c.ds, c.ds + c.dl))   // 可写副本
  // 加密区 = payload[0x40:]
  if (p.length > 0x40) {
    const nblocks = Math.ceil((p.length - 0x40) / 16)
    const c0 = Buffer.alloc(16)
    nonce.copy(c0, 0)
    c0.writeUInt32BE(c.ft >>> 0, 8)
    c0.writeUInt32BE(0, 12)
    const ks = keystream(c0, nblocks)
    for (let j = 0; j < p.length - 0x40; j++) p[0x40 + j] ^= ks[j]
    decBytes += p.length - 0x40
  }
  if (i === 0) {
    ivf = Buffer.from(p.subarray(0, 32))
    frames.push({ ts: Number(p.readBigUInt64LE(36)), data: p.subarray(44) })
  } else {
    frames.push({ ts: Number(p.readBigUInt64LE(4)), data: p.subarray(12) })
  }
}

// ---- 重组 IVF ----
const parts = [ivf]
for (const f of frames) {
  const h = Buffer.alloc(12)
  h.writeUInt32LE(f.data.length, 0)
  h.writeBigUInt64LE(BigInt(f.ts), 4)
  parts.push(h, f.data)
}
const out = Buffer.concat(parts)
const base = o.usm.replace(/\.usm$/i, '')
const outIvf = o.o || (base + '.dec.ivf')
writeFileSync(outIvf, out)
console.log('解密 %d 字节 → %s  (%d 帧, %.1f MB)', decBytes, outIvf, frames.length, out.length / 1048576)

// ---- 转 MKV（可选）----
if (!o.nomkv) {
  const outMkv = outIvf.replace(/\.ivf$/, '.mkv')
  try {
    execFileSync('ffmpeg', ['-v', 'error', '-y', '-i', outIvf, '-c', 'copy', outMkv], { stdio: 'inherit' })
    console.log('→ MKV:', outMkv)
    if (!o.keepivf) { unlinkSync(outIvf); console.log('（已删除中间 IVF）') }
  } catch (e) {
    console.log('（转 MKV 失败，IVF 仍保留:', outIvf + '）')
  }
}
