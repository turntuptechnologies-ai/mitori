/**
 * RDAP による登録情報の取得。
 *
 * IANA のブートストラップ (data.iana.org) は CORS 許可済みで、そこから引いた
 * 各レジストリの RDAP エンドポイントも多くは CORS を返す。
 *
 * ただし .jp は 2026-08 時点で IANA の RDAP ブートストラップに登録がなく、
 * JPRS は WHOIS しか提供していないためブラウザからは取得できない。
 * その場合は「判定不能」として扱い、有効期限は利用者の手入力に委ねる。
 */

export interface RdapInfo {
  supported: boolean
  registrar?: string
  registeredAt?: string
  expiresAt?: string
  lastChangedAt?: string
  statuses: string[]
  /** 取得できなかった理由 */
  reason?: string
}

interface BootstrapFile {
  services: Array<[string[], string[]]>
}

let bootstrapPromise: Promise<BootstrapFile> | null = null

function loadBootstrap(): Promise<BootstrapFile> {
  bootstrapPromise ??= fetch('https://data.iana.org/rdap/dns.json').then((r) => {
    if (!r.ok) throw new Error(`bootstrap ${r.status}`)
    return r.json() as Promise<BootstrapFile>
  })
  return bootstrapPromise
}

function tldOf(domain: string): string {
  const parts = domain.split('.')
  return parts[parts.length - 1]!.toLowerCase()
}

interface RdapEvent {
  eventAction: string
  eventDate: string
}

interface RdapEntity {
  roles?: string[]
  vcardArray?: unknown
}

interface RdapDomain {
  events?: RdapEvent[]
  status?: string[]
  entities?: RdapEntity[]
}

function nameFromVcard(vcard: unknown): string | undefined {
  if (!Array.isArray(vcard) || vcard.length < 2) return undefined
  const entries = vcard[1]
  if (!Array.isArray(entries)) return undefined
  for (const entry of entries) {
    if (Array.isArray(entry) && entry[0] === 'fn' && typeof entry[3] === 'string') {
      return entry[3]
    }
  }
  return undefined
}

export async function lookupRdap(domain: string): Promise<RdapInfo> {
  const tld = tldOf(domain)

  let base: string | undefined
  try {
    const bootstrap = await loadBootstrap()
    for (const [tlds, urls] of bootstrap.services) {
      if (tlds.some((t) => t.toLowerCase() === tld)) {
        base = urls[0]
        break
      }
    }
  } catch {
    return { supported: false, statuses: [], reason: 'IANA ブートストラップを取得できませんでした' }
  }

  if (!base) {
    return {
      supported: false,
      statuses: [],
      reason: `.${tld} は RDAP に対応していません（WHOIS のみ）。有効期限は手動で確認してください`,
    }
  }

  const url = `${base.replace(/\/$/, '')}/domain/${encodeURIComponent(domain)}`
  let data: RdapDomain
  try {
    const res = await fetch(url, { headers: { accept: 'application/rdap+json' } })
    if (res.status === 404) {
      return { supported: true, statuses: [], reason: 'レジストリに登録がありません（未登録・廃止済み）' }
    }
    if (!res.ok) throw new Error(`rdap ${res.status}`)
    data = (await res.json()) as RdapDomain
  } catch {
    return {
      supported: false,
      statuses: [],
      reason: 'RDAP サーバに到達できないか、CORS が許可されていません',
    }
  }

  const eventDate = (action: string) =>
    data.events?.find((e) => e.eventAction === action)?.eventDate

  const registrar = data.entities?.find((e) => e.roles?.includes('registrar'))
  return {
    supported: true,
    registrar: registrar ? nameFromVcard(registrar.vcardArray) : undefined,
    registeredAt: eventDate('registration'),
    expiresAt: eventDate('expiration'),
    lastChangedAt: eventDate('last changed'),
    statuses: data.status ?? [],
  }
}
