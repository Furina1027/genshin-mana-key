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
 *   加密区   = 每个 chunk 的 payload[0x40:]（payload 前 0x40 字节永远是明文）
 *              · 首个 chunk 含 32 字节 IVF 文件头：payload = IVF头(32) + [条目(12)+帧数据]…
 *                → 该块第 0 个条目的帧数据明文前缀 = 0x40-32-12 = 0x14
 *              · 其余 chunk：payload = [条目(12)+帧数据]…
 *                → 帧数据明文前缀 = 0x40-12 = 0x34
 *   注意：长度 <= 0x40 的 payload 没有加密区（小帧整体明文），解密时自动跳过。
 *
 * ★ 计数器与 Python 侧（tools/usm.py）逐字节一致：
 *   Node 的 'aes-128-ctr' 把 16 字节 IV 当成一个**大端整数**整块递增，
 *   所以 IV = nonce(8B) || BE32(frameTime) || BE32(0) 就是上面那条公式。
 *
 * ★ 一个 chunk 里可能有多个 IVF 条目（entry,data,entry,data,… 交替）：
 *   逐个条目解密，且计数器用**该条目自己的 frameTime**（不是 chunk 头的 frameTime）。
 *   条目头本身永远不加密（否则容器都解析不出来）。
 *
 * 用法：
 *   node usm_decrypt.mjs <file.usm> [-o out.ivf] [--key HEX32] [--nomkv] [--keepivf] [--json]
 *   node usm_decrypt.mjs --help
 *
 * 退出码：0=成功；1=没有可抽取的视频；2=参数/IO 错误；3=密钥/nonce 问题；4=容器结构畸形。
 */
import { createDecipheriv } from 'node:crypto'
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs'
import { execFileSync } from 'node:child_process'

const DEFAULT_KEY = 'F5AC17FFE4B4B430553AE073EB8A8A1D'
const NONCE_MARKER = Buffer.from('<NULL>\x00VIDEO_HDRINFO', 'latin1')
const ENCRYPTED_PLAIN_PREFIX = 0x40
const IVF_HEADER_SIZE = 32
const IVF_ENTRY_SIZE = 12
const MIN_CHUNK_SIZE = 0x10
const KNOWN_CHUNK_TAGS = new Set(['@SFV', '@SFA', '@UTF', '@CMS', '@CUE', '@ALP',
  '@SBT', '@SQV', '@SQA', '@SHK', 'CRID'])

const EXIT = { OK: 0, NOTHING: 1, PARAM: 2, KEY: 3, FORMAT: 4 }

const HELP = `usm_decrypt.mjs — 原神 7.1 USM 视频解密（method2 / AES-128-CTR）

用法:
  node usm_decrypt.mjs <file.usm> [选项]

选项:
  -o, --out <file.ivf>   输出 IVF 路径（默认 <输入名>.dec.ivf）
  --key <HEX32>          AES-128 密钥，32 个十六进制字符（默认${DEFAULT_KEY}）
  --nomkv                不调用 ffmpeg 转 MKV
  --keepivf              转 MKV 后保留中间 IVF（用户显式 -o 时反正不会删除）
  --json                 以 JSON 输出结果摘要
  -h, --help             显示本帮助

加密区语义: 每个 chunk 的 payload[0x40:]；计数器 = nonce(8B)||BE32(条目 frameTime)||BE32(block)。
退出码: 0=成功 1=没有视频 2=参数/IO 错误 3=密钥/nonce 问题 4=容器结构畸形`

function fail(msg, code) {
  console.error(`错误：${msg}`)
  process.exit(code)
}

function parseArgs(argv) {
  const o = { key: DEFAULT_KEY, nomkv: false, keepivf: false, json: false,
    out: null, usm: null }
  for (let i = 0; i < argv.length; i++) {
    let tok = argv[i]
    let inlineValue = null
    const eq = tok.indexOf('=')
    if (tok.startsWith('-') && eq > 0) {
      inlineValue = tok.slice(eq + 1)
      tok = tok.slice(0, eq)
    }
    if (tok === '-h' || tok === '--help') {
      console.log(HELP)
      process.exit(EXIT.OK)
    }
    // ★ 无值开关必须单独判断：旧实现按 for (i += 2) 成对解析，
    //   会把 '--nomkv' 当成键、把后面的文件名当成它的值吃掉。
    if (tok === '--nomkv') { o.nomkv = true; continue }
    if (tok === '--keepivf') { o.keepivf = true; continue }
    if (tok === '--json') { o.json = true; continue }
    if (tok === '-o' || tok === '--out') {
      o.out = inlineValue !== null ? inlineValue : argv[++i]
      if (o.out === undefined || o.out === null || o.out.startsWith('-')) {
        fail(`--out 需要一个输出路径`, EXIT.PARAM)
      }
      continue
    }
    if (tok === '--key') {
      o.key = inlineValue !== null ? inlineValue : argv[++i]
      if (o.key === undefined) fail('--key 需要一个十六进制密钥', EXIT.PARAM)
      continue
    }
    if (tok.startsWith('-') && tok !== '-') {
      fail(`未知选项 ${tok}（用 --help 看用法）`, EXIT.PARAM)
    }
    if (o.usm === null) { o.usm = tok; continue }
    fail(`多余的位置参数 ${tok}（只接受一个 .usm 文件）`, EXIT.PARAM)
  }
  if (!o.usm) fail('缺少输入 .usm 文件（用 --help 看用法）', EXIT.PARAM)
  return o
}

function parseKey(text) {
  let s = String(text).trim().replace(/\s+/g, '')
  if (s.toLowerCase().startsWith('0x')) s = s.slice(2)
  if (!/^[0-9a-fA-F]*$/.test(s)) fail(`--key 含非十六进制字符：${text}`, EXIT.PARAM)
  // ★ Buffer.from(s, 'hex') 会静默截断/忽略非法字符，必须先自己卡住长度
  if (s.length !== 32) {
    fail(`--key 必须是 32 个十六进制字符（16 字节 AES-128），收到 ${s.length} 个：${text}`,
      EXIT.PARAM)
  }
  return Buffer.from(s, 'hex')
}

/** 解析 chunk 链；畸形块直接抛错（带偏移）。 */
function parseChunks(b) {
  const out = []
  let pos = 0
  while (pos + 24 <= b.length) {
    const typ = b.subarray(pos, pos + 4).toString('latin1')
    if (!KNOWN_CHUNK_TAGS.has(typ)) break          // 容器尾部（MKV 头）
    const size = b.readUInt32BE(pos + 4)
    if (size < MIN_CHUNK_SIZE) {
      throw new Error(`偏移 0x${pos.toString(16)} 的 ${typ} 块 size=0x${size.toString(16)} 过小`)
    }
    if (pos + 8 + size > b.length) {
      throw new Error(`偏移 0x${pos.toString(16)} 的 ${typ} 块声明 size=0x${size.toString(16)}，`
        + `超出文件大小 0x${b.length.toString(16)}（截断/畸形）`)
    }
    const dof = b[pos + 9]
    const pad = b.readUInt16BE(pos + 10)
    if (dof + pad > size) {
      throw new Error(`偏移 0x${pos.toString(16)} 的 ${typ} 块 data_offset+padding > size`)
    }
    out.push({ typ, dt: b[pos + 15] & 3, ft: b.readUInt32BE(pos + 16),
      ds: pos + 8 + dof, dl: size - dof - pad })
    pos += size + 8
  }
  return out
}

/** 把一个 chunk payload 切成 IVF 条目（entry,data 交替；首个块先跳过 32B IVF 头）。 */
function parseEntries(payload, first) {
  const entries = []
  let off = first ? IVF_HEADER_SIZE : 0
  if (first && payload.length < IVF_HEADER_SIZE) return entries
  let idx = 0
  while (off + IVF_ENTRY_SIZE <= payload.length) {
    const size = payload.readUInt32LE(off)
    const ts = Number(payload.readBigUInt64LE(off + 4))
    const dataOff = off + IVF_ENTRY_SIZE
    const avail = payload.length - dataOff
    if (size === 0) break
    entries.push({ index: idx, ts, size, dataOff, dataLen: Math.min(size, avail),
      truncated: size > avail })
    if (size > avail) break
    off = dataOff + size
    idx++
  }
  return entries
}

/** 解密一个条目的帧数据里落在 payload[0x40:] 之后的部分（原地改副本）。 */
function decryptEntry(p, entry, key, nonce) {
  const start = Math.max(ENCRYPTED_PLAIN_PREFIX, entry.dataOff)
  const end = Math.min(entry.dataOff + entry.dataLen, p.length)
  if (start >= end) return 0
  const iv = Buffer.alloc(16)
  nonce.copy(iv, 0)
  iv.writeUInt32BE(entry.ts >>> 0, 8)
  iv.writeUInt32BE(0, 12)
  const c = createDecipheriv('aes-128-ctr', key, iv)
  const plain = Buffer.concat([c.update(p.subarray(start, end)), c.final()])
  plain.copy(p, start)
  return end - start
}

function main() {
  const o = parseArgs(process.argv.slice(2))
  const key = parseKey(o.key)

  let buf
  try {
    buf = readFileSync(o.usm)
  } catch (e) {
    fail(`无法读取 ${o.usm}：${e.message}`, EXIT.PARAM)
  }

  const ij = buf.indexOf(NONCE_MARKER)
  if (ij < 8) {
    fail('文件里找不到 VIDEO_HDRINFO 标记 → 拿不到 nonce，拒绝输出「已解密」的假文件',
      EXIT.KEY)
  }
  const nonce = buf.subarray(ij - 8, ij)
  if (nonce.length !== 8) fail('nonce 长度不是 8 字节', EXIT.KEY)

  let chunks
  try {
    chunks = parseChunks(buf)
  } catch (e) {
    fail(`USM 容器结构畸形：${e.message}`, EXIT.FORMAT)
  }

  const vid = chunks.filter((c) => c.typ === '@SFV' && c.dt === 0)
  if (vid.length === 0) fail('没有 @SFV 视频数据块', EXIT.NOTHING)

  let ivfHeader = null
  const frames = []
  let decBytes = 0
  const warnings = []
  for (let i = 0; i < vid.length; i++) {
    const first = ivfHeader === null
    const p = Buffer.from(buf.subarray(vid[i].ds, vid[i].ds + vid[i].dl))
    if (first) {
      if (p.length < IVF_HEADER_SIZE || p.subarray(0, 4).toString('latin1') !== 'DKIF') {
        fail(`首个 @SFV 数据块不以 DKIF 开头（${p.subarray(0, 4).toString('hex')}）`, EXIT.FORMAT)
      }
      ivfHeader = Buffer.from(p.subarray(0, IVF_HEADER_SIZE))
    }
    const entries = parseEntries(p, first)
    for (const e of entries) {
      if (e.truncated) {
        warnings.push(`块 ${i} 的条目 #${e.index} 声明 ${e.size} B，实际只有 ${e.dataLen} B`)
      }
      decBytes += decryptEntry(p, e, key, nonce)
      frames.push({ ts: e.ts, data: Buffer.from(p.subarray(e.dataOff, e.dataOff + e.dataLen)) })
    }
  }

  // ---- 重组 IVF ----
  const parts = [ivfHeader]
  for (const f of frames) {
    const h = Buffer.alloc(12)
    h.writeUInt32LE(f.data.length, 0)
    h.writeBigUInt64LE(BigInt(f.ts), 4)
    parts.push(h, f.data)
  }
  const out = Buffer.concat(parts)
  const base = o.usm.replace(/\.usm$/i, '')
  const userOut = Boolean(o.out)
  const outIvf = o.out || (base + '.dec.ivf')

  try {
    writeFileSync(outIvf, out)
  } catch (e) {
    fail(`写 ${outIvf} 失败：${e.message}`, EXIT.PARAM)
  }
  if (!o.json) {
    console.log(`nonce = ${nonce.toString('hex')}`)
    console.log(`视频块 = ${vid.length}，帧 = ${frames.length}，解密 ${decBytes} 字节`)
    for (const w of warnings) console.log(`  ⚠ ${w}`)
    console.log(`→ ${outIvf}  (${(out.length / 1048576).toFixed(2)} MB)`)
  }

  // ---- 转 MKV（可选）----
  let mkvPath = null
  let mkvError = null
  if (!o.nomkv) {
    mkvPath = outIvf.replace(/\.ivf$/, '.mkv')
    try {
      execFileSync('ffmpeg', ['-v', 'error', '-y', '-i', outIvf, '-c', 'copy', mkvPath],
        { stdio: 'inherit' })
      if (!o.json) console.log(`→ MKV: ${mkvPath}`)
      // ★ 用户显式 -o 指定的文件绝不删除；只有我们自己生成的默认 .dec.ivf 才删
      if (!o.keepivf && !userOut) {
        unlinkSync(outIvf)
        if (!o.json) console.log('（已删除中间 IVF）')
      }
    } catch (e) {
      mkvError = e.message
      mkvPath = null
      if (!o.json) console.log(`（转 MKV 失败，IVF 仍保留: ${outIvf}）`)
    }
  }

  if (o.json) {
    console.log(JSON.stringify({
      usm: o.usm, size: buf.length, chunks: chunks.length, video_chunks: vid.length,
      frames: frames.length, decrypted_bytes: decBytes,
      nonce: nonce.toString('hex'), ivf: outIvf, ivf_bytes: out.length,
      ivf_deleted: Boolean(!o.nomkv && !o.keepivf && !userOut && mkvPath),
      mkv: mkvPath, mkv_error: mkvError, warnings,
    }, null, 2))
  }
  return EXIT.OK
}

process.exit(main())
