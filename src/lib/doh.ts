/**
 * DNS over HTTPS クライアント。
 *
 * Cloudflare / Google はいずれも `Access-Control-Allow-Origin: *` を返すため、
 * バックエンドなしのブラウザから直接叩ける。mitori の検査はほぼ全てここに乗る。
 */

export interface DnsAnswer {
  name: string
  type: number
  TTL: number
  data: string
}

export interface DnsResponse {
  Status: number
  Answer?: DnsAnswer[]
  Authority?: DnsAnswer[]
  Comment?: string
}

const ENDPOINTS = [
  (name: string, type: string) =>
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
  (name: string, type: string) =>
    `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`,
]

/** NOERROR */
export const RCODE_NOERROR = 0
/** NXDOMAIN。ドメインそのものが存在しない */
export const RCODE_NXDOMAIN = 3

const MAX_CONCURRENCY = 8
let active = 0
const waiting: Array<() => void> = []

function schedule<T>(task: () => Promise<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const run = () => {
      active += 1
      task()
        .then(resolve, reject)
        .finally(() => {
          active -= 1
          waiting.shift()?.()
        })
    }
    if (active < MAX_CONCURRENCY) run()
    else waiting.push(run)
  })
}

const cache = new Map<string, Promise<DnsResponse>>()

/** 同一ドメインを何度も検査するので、プロセス内でキャッシュする */
export function resetCache(): void {
  cache.clear()
}

async function fetchOnce(url: string): Promise<DnsResponse> {
  const res = await fetch(url, { headers: { accept: 'application/dns-json' } })
  if (!res.ok) throw new Error(`DoH ${res.status}`)
  return (await res.json()) as DnsResponse
}

export function resolve(name: string, type: string): Promise<DnsResponse> {
  const key = `${name}|${type}`
  const hit = cache.get(key)
  if (hit) return hit

  const promise = schedule(async () => {
    let lastError: unknown
    for (const build of ENDPOINTS) {
      try {
        return await fetchOnce(build(name, type))
      } catch (err) {
        lastError = err
      }
    }
    throw lastError instanceof Error ? lastError : new Error('DoH 失敗')
  })

  cache.set(key, promise)
  return promise
}

/** 指定タイプのレコード値だけを取り出す。存在しなければ空配列 */
export async function records(name: string, type: string): Promise<string[]> {
  const res = await resolve(name, type)
  if (res.Status !== RCODE_NOERROR || !res.Answer) return []
  const wanted = TYPE_CODE[type]
  return res.Answer.filter((a) => wanted === undefined || a.type === wanted).map((a) => a.data)
}

export const TYPE_CODE: Record<string, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  DS: 43,
  CAA: 257,
}

/**
 * TXT レコードは `"..."` で引用され、255 バイト超は複数文字列に分割される。
 * 分割片は結合しないと SPF などの判定を誤る。
 */
export function unquoteTxt(data: string): string {
  const parts = data.match(/"(?:[^"\\]|\\.)*"/g)
  if (!parts) return data
  return parts.map((p) => p.slice(1, -1).replace(/\\(.)/g, '$1')).join('')
}

export async function txtRecords(name: string): Promise<string[]> {
  return (await records(name, 'TXT')).map(unquoteTxt)
}

export interface CaaRecord {
  flags: number
  tag: string
  value: string
}

/**
 * CAA の表現はリゾルバによって割れる。
 * Google は `0 issue "letsencrypt.org"` を返すが、Cloudflare は RFC 3597 の
 * 汎用形式 `\# 19 00 05 69 73 ...` を返すため、どちらも復号する。
 */
export function parseCaa(data: string): CaaRecord | null {
  const generic = data.match(/^\\#\s+\d+\s+([0-9a-fA-F\s]+)$/)
  if (generic) {
    const hex = generic[1]!.replace(/\s+/g, '')
    if (hex.length < 4 || hex.length % 2 !== 0) return null
    const bytes = new Uint8Array(hex.length / 2)
    for (let i = 0; i < bytes.length; i += 1) {
      bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
    }
    const tagLength = bytes[1]!
    const decoder = new TextDecoder()
    return {
      flags: bytes[0]!,
      tag: decoder.decode(bytes.slice(2, 2 + tagLength)),
      value: decoder.decode(bytes.slice(2 + tagLength)),
    }
  }

  const plain = data.match(/^(\d+)\s+(\S+)\s+"?([^"]*)"?\s*$/)
  if (plain) return { flags: Number(plain[1]), tag: plain[2]!, value: plain[3]! }
  return null
}

export function formatCaa(record: CaaRecord): string {
  return `${record.flags} ${record.tag} "${record.value}"`
}

/** そのホスト名が何らかの形で解決するか（A / AAAA / CNAME） */
export async function isAlive(name: string): Promise<boolean> {
  const [a, aaaa, cname] = await Promise.all([
    records(name, 'A'),
    records(name, 'AAAA'),
    records(name, 'CNAME'),
  ])
  return a.length > 0 || aaaa.length > 0 || cname.length > 0
}

/** ドメイン自体が DNS 上に存在するか（NXDOMAIN でないか） */
export async function domainExists(name: string): Promise<boolean> {
  const res = await resolve(name, 'SOA')
  return res.Status !== RCODE_NXDOMAIN
}
