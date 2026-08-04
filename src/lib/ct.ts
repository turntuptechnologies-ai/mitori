/**
 * 証明書透明性ログ (certspotter) からサブドメインを列挙する。
 *
 * crt.sh は CORS ヘッダを返さず、可用性も安定しないため採用しない。
 * certspotter は `Access-Control-Allow-Origin: *` を返すが、
 * 未認証だと IP あたりのレート制限が厳しいので 429 を明示的に扱う。
 */

export interface Issuance {
  dns_names: string[]
  not_before: string
  not_after: string
  revoked?: boolean
  issuer?: { name?: string }
}

export interface CtResult {
  ok: boolean
  /** 重複を除いたホスト名 */
  names: string[]
  /** 現時点で有効期間内の証明書の数 */
  activeCerts: number
  /** 最も遅い失効日 */
  latestNotAfter?: string
  reason?: string
}

// サブドメイン列挙と証明書残存の 2 検査が同じ結果を使うため、
// 未認証のレート制限を無駄に消費しないようキャッシュする
const cache = new Map<string, Promise<CtResult>>()

export function resetCtCache(): void {
  cache.clear()
}

export function fetchIssuances(domain: string): Promise<CtResult> {
  const hit = cache.get(domain)
  if (hit) return hit
  const promise = fetchIssuancesUncached(domain)
  cache.set(domain, promise)
  return promise
}

async function fetchIssuancesUncached(domain: string): Promise<CtResult> {
  const url =
    `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}` +
    `&include_subdomains=true&expand=dns_names&expand=issuer`

  let list: Issuance[]
  try {
    const res = await fetch(url)
    if (res.status === 429) {
      return { ok: false, names: [], activeCerts: 0, reason: 'certspotter のレート制限に達しました。時間をおいて再試行してください' }
    }
    if (!res.ok) throw new Error(`certspotter ${res.status}`)
    list = (await res.json()) as Issuance[]
  } catch {
    return { ok: false, names: [], activeCerts: 0, reason: 'CT ログを取得できませんでした' }
  }

  const now = Date.now()
  const names = new Set<string>()
  let activeCerts = 0
  let latest: number | undefined

  for (const issuance of list) {
    for (const name of issuance.dns_names ?? []) {
      // ワイルドカードは実ホストではないので除外し、別途フラグで扱う
      names.add(name.toLowerCase())
    }
    const notAfter = Date.parse(issuance.not_after)
    const notBefore = Date.parse(issuance.not_before)
    if (!Number.isNaN(notAfter) && !Number.isNaN(notBefore)) {
      if (notBefore <= now && now <= notAfter && !issuance.revoked) activeCerts += 1
      if (latest === undefined || notAfter > latest) latest = notAfter
    }
  }

  return {
    ok: true,
    names: [...names].sort(),
    activeCerts,
    latestNotAfter: latest === undefined ? undefined : new Date(latest).toISOString(),
  }
}
