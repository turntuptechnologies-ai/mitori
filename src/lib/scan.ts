import {
  formatCaa,
  isAlive,
  parseCaa,
  records,
  resetCache,
  resolve,
  txtRecords,
  RCODE_NXDOMAIN,
  type CaaRecord,
} from './doh'
import { fetchIssuances, resetCtCache } from './ct'
import { describeVerdict, inspectCname, isServiceName, type CnameInspection } from './dangling'
import { NSEC_MODE_LABEL, WALK_STOP_LABEL, walkZone, type WalkResult } from './nsec'
import { lookupRdap } from './rdap'
import { checkWayback, formatWaybackTimestamp } from './wayback'
import { fetchWikimediaLinks, WIKIMEDIA_PROJECTS, type WikimediaResult } from './wikimedia'
import {
  COMMON_SUBDOMAINS,
  DKIM_SELECTORS,
  MICROSOFT_HOSTS,
  SRV_PROBES,
  TOKEN_SIGNATURES,
} from './signatures'
import { makeResult, type CheckResult, type ScanReport } from './types'

/** 入力を検査可能なホスト名に正規化する。URL・スキーム・末尾ドットを許容する */
export function normalizeDomain(input: string): string | null {
  const trimmed = input.trim().replace(/\.$/, '')
  if (!trimmed) return null
  let host = trimmed
  try {
    host = new URL(trimmed.includes('://') ? trimmed : `http://${trimmed}`).hostname
  } catch {
    return null
  }
  host = host.toLowerCase()
  if (!host.includes('.') || /\s/.test(host)) return null
  return host
}

interface ScanContext {
  /** ドメインが DNS 上に存在するか。false なら DNS 設定を要求する検査は評価対象外にする */
  exists: boolean
}

interface Check {
  id: string
  label: string
  run: (domain: string, ctx: ScanContext) => Promise<CheckResult | CheckResult[]>
}

/** RFC 7505 の null MX (`0 .`) は「このドメインはメールを受け取らない」の明示宣言 */
function isNullMx(mx: string[]): boolean {
  return mx.length === 1 && /^0\s+\.?$/.test(mx[0]!.trim())
}

/** サブドメインの生存確認は DoH クエリ数がかさむため上限を設ける */
const SUBDOMAIN_PROBE_LIMIT = 40

/**
 * NSEC ウォークは 1 名前 1 クエリの直列処理で、他の検査と違って並列化できない。
 * 件数だけで縛ると回線が遅いときに何十秒も待たされるため、時間でも縛る。
 * どちらで打ち切ったかは必ず結果に出す。
 */
const NSEC_WALK_LIMITS = { maxNames: 60, budgetMs: 6000 }

interface Candidates {
  /** 実際に検査したホスト名 */
  probed: string[]
  /** 上限を掛ける前の候補総数 */
  total: number
  ct: Awaited<ReturnType<typeof fetchIssuances>>
  /** 網羅性に関する但し書き。結果に必ず添える */
  notes: string[]
}

// ウォークは直列で時間がかかるため、検査間で共有する
const walkCache = new Map<string, Promise<WalkResult>>()

function walkOnce(domain: string): Promise<WalkResult> {
  const hit = walkCache.get(domain)
  if (hit) return hit
  const promise = walkZone(domain, NSEC_WALK_LIMITS)
  walkCache.set(domain, promise)
  return promise
}

/**
 * サブドメイン候補を組み立てる。
 * CT ログと辞書の和集合。呼び出し元が複数あるが、CT も DoH もキャッシュされるため
 * 実際の通信は 1 回で済む。
 */
async function collectCandidates(domain: string): Promise<Candidates> {
  const [ct, walk] = await Promise.all([fetchIssuances(domain), walkOnce(domain)])

  // NSEC で得た名前は実在が確定しているので、上限を掛けるときに優先して残す
  const ordered: string[] = [...walk.names]
  const push = (name: string) => {
    if (name !== domain && !ordered.includes(name)) ordered.push(name)
  }
  for (const name of ct.names) {
    // ワイルドカードは実ホストではないので候補にしない
    if (name.startsWith('*.')) continue
    if (name.endsWith(`.${domain}`)) push(name)
  }
  for (const sub of COMMON_SUBDOMAINS) push(`${sub}.${domain}`)

  const list = ordered.filter((name) => name !== domain)
  const notes: string[] = []
  if (walk.names.length) {
    notes.push(
      `NSEC ウォークでゾーンから ${walk.names.length} 件の名前を列挙しました。${WALK_STOP_LABEL[walk.stop]}`,
    )
  }
  if (!ct.ok && ct.reason) {
    notes.push(`CT ログ: ${ct.reason}（辞書のみで検査しました）`)
  } else {
    // 未認証の certspotter は有効期限内の証明書しか返さない。
    // 忘れられたホストほど証明書が失効しているため、ここは網羅ではない
    notes.push(
      'CT ログからは有効期限内の証明書しか取得できないため、証明書が失効したサブドメインは候補に入りません',
    )
  }
  if (list.length > SUBDOMAIN_PROBE_LIMIT) {
    notes.push(
      `候補 ${list.length} 件のうち上限 ${SUBDOMAIN_PROBE_LIMIT} 件のみ検査しました。未検査 ${list.length - SUBDOMAIN_PROBE_LIMIT} 件`,
    )
  }

  return { probed: list.slice(0, SUBDOMAIN_PROBE_LIMIT), total: list.length, ct, notes }
}

/** 根拠として並べるページ名の上限。超えた分は件数だけ出す */
const BACKLINK_EVIDENCE_LIMIT = 12

function backlinkEvidence(wm: WikimediaResult): string[] {
  const lines: string[] = []

  for (const p of wm.found) {
    const counts = [`本文 ${p.articles.length} ページ`]
    if (p.others.length) counts.push(`本文以外 ${p.others.length} ページ`)
    lines.push(`${p.project.label}: ${counts.join(' / ')}${p.truncated ? '（上限で打ち切り）' : ''}`)
    for (const title of p.articles.slice(0, BACKLINK_EVIDENCE_LIMIT)) {
      lines.push(`${p.project.host} — ${title}`)
    }
    const rest = p.articles.length - BACKLINK_EVIDENCE_LIMIT
    if (rest > 0) lines.push(`${p.project.host} — ほか ${rest} ページ`)
  }

  // 照会できなかったプロジェクトを 0 件と混ぜない
  for (const p of wm.projects) {
    if (p.state !== 'ok') lines.push(`${p.project.label}: ${p.reason}`)
  }

  // 「見つからなかった」を「参照が無い」と読ませないための但し書き
  lines.push(
    `調査対象は Wikimedia の ${WIKIMEDIA_PROJECTS.length} プロジェクトだけです。` +
      '言語版は 300 以上あり、Wikimedia 以外の被リンクは調べていません',
  )

  // 表示側がリストのキーに使うため、同一行は残さない
  return [...new Set(lines)]
}

const CHECKS: Check[] = [
  {
    id: 'domain-exists',
    label: 'ドメインの存在',
    run: async (domain) => {
      const soa = await resolve(domain, 'SOA')
      const gone = soa.Status === RCODE_NXDOMAIN
      return makeResult({
        id: 'domain-exists',
        phase: 'inventory',
        title: 'DNS 上の存在',
        severity: 'info',
        status: 'clear',
        summary: gone
          ? 'DNS に存在しません（NXDOMAIN）。既に沈黙状態か、登録が切れています'
          : 'DNS に存在します。以降の検査を実施します',
        evidence: [`SOA rcode = ${soa.Status}`],
      })
    },
  },
  {
    id: 'mail-mx',
    label: 'メール受信',
    run: async (domain) => {
      const mx = await records(domain, 'MX')
      const nullMx = isNullMx(mx)
      const alive = mx.length > 0 && !nullMx
      return makeResult({
        id: 'mail-mx',
        phase: 'detach',
        title: 'メール受信が生きているか',
        severity: 'critical',
        status: alive ? 'action' : 'clear',
        summary: alive
          ? `MX レコードが ${mx.length} 件あります。第三者が取得した瞬間にこのドメイン宛のメールを受信できます`
          : nullMx
            ? 'null MX (RFC 7505) が設定されており、メールを受け取らないことを明示できています'
            : 'MX レコードはありません。メール受信は停止しています',
        advice: alive
          ? 'このドメイン宛に届いている内容を棚卸ししたうえで MX を削除してください。アカウント復旧メールが届く状態は最も危険です'
          : nullMx
            ? undefined
            : 'MX を単に消すより、null MX（`0 .`）を置くほうが「受け取らない」意思を送信側に伝えられます',
        evidence: mx,
      })
    },
  },
  {
    id: 'saas-tokens',
    label: 'SaaS 所有権トークン',
    run: async (domain) => {
      const txt = await txtRecords(domain)
      const found: string[] = []
      const services = new Set<string>()
      const hints: string[] = []

      for (const value of txt) {
        for (const sig of TOKEN_SIGNATURES) {
          if (sig.pattern.test(value)) {
            found.push(`${sig.service}: ${value}`)
            services.add(sig.service)
            if (sig.hint) hints.push(`${sig.service} … ${sig.hint}`)
          }
        }
      }

      const hit = services.size > 0
      return makeResult({
        id: 'saas-tokens',
        phase: 'detach',
        title: 'SaaS のドメイン所有権トークン',
        severity: 'critical',
        status: hit ? 'action' : 'clear',
        summary: hit
          ? `${services.size} 件のサービスにまだ紐付いています: ${[...services].join(' / ')}`
          : '既知の所有権確認トークンは残っていません',
        advice: hit
          ? `各サービス側でドメイン登録を解除してから TXT を削除してください。${hints.length ? '\n' + hints.join('\n') : ''}`
          : undefined,
        evidence: found,
      })
    },
  },
  {
    id: 'ms365',
    label: 'Microsoft 365 連携',
    run: async (domain) => {
      const hostHits = await Promise.all(
        MICROSOFT_HOSTS.map(async (h) => {
          const cname = await records(`${h.host}.${domain}`, 'CNAME')
          return cname.length ? `${h.host}.${domain} → ${cname.join(', ')} (${h.label})` : null
        }),
      )
      const srvHits = await Promise.all(
        SRV_PROBES.map(async (s) => {
          const srv = await records(`${s.name}.${domain}`, 'SRV')
          return srv.length ? `${s.name}.${domain} → ${srv.join(', ')} (${s.label})` : null
        }),
      )
      const evidence = [...hostHits, ...srvHits].filter((x): x is string => x !== null)
      const hit = evidence.length > 0
      return makeResult({
        id: 'ms365',
        phase: 'detach',
        title: 'グループウェア連携の痕跡',
        severity: 'high',
        status: hit ? 'action' : 'clear',
        summary: hit
          ? `${evidence.length} 件の連携レコードが残っています`
          : '自動検出・フェデレーション系のレコードは残っていません',
        advice: hit
          ? 'テナントからドメインを削除したうえで、CNAME / SRV を消してください'
          : undefined,
        evidence,
      })
    },
  },
  {
    id: 'web-alive',
    label: 'Web の生存',
    run: async (domain) => {
      const [apex, www] = await Promise.all([isAlive(domain), isAlive(`www.${domain}`)])
      const alive = apex || www
      const evidence: string[] = []
      if (apex) evidence.push(`${domain} は解決します`)
      if (www) evidence.push(`www.${domain} は解決します`)
      return makeResult({
        id: 'web-alive',
        phase: 'cooldown',
        title: 'Web サイトの生存',
        severity: 'high',
        status: alive ? 'action' : 'clear',
        summary: alive
          ? 'まだ名前解決します。コンテンツの縮退が完了していません'
          : '名前解決しません。Web としては沈黙しています',
        advice: alive
          ? 'コンテンツを案内 1 枚まで削り、段階的にリダイレクトを弱めてから A / AAAA / CNAME を削除してください'
          : undefined,
        evidence,
      })
    },
  },
  {
    id: 'subdomains',
    label: 'サブドメインの残骸',
    run: async (domain) => {
      const { probed, ct, notes } = await collectCandidates(domain)

      const alive: string[] = []
      await Promise.all(
        probed.map(async (host) => {
          if (await isAlive(host)) alive.push(host)
        }),
      )
      alive.sort()

      return makeResult({
        id: 'subdomains',
        phase: 'inventory',
        title: '生存しているサブドメイン',
        severity: 'high',
        status: alive.length ? 'action' : ct.ok ? 'clear' : 'warn',
        summary: alive.length
          ? `${alive.length} 件のサブドメインがまだ解決します`
          : ct.ok
            ? '解決するサブドメインは見つかりませんでした'
            : 'CT ログを取得できず、網羅性が落ちています',
        advice: alive.length
          ? '各サブドメインの用途を確認し、参照元を切り替えてから DNS レコードを削除してください'
          : undefined,
        evidence: [...alive, ...notes],
      })
    },
  },
  {
    id: 'nsec',
    label: 'ゾーンの列挙可能性',
    run: async (domain, ctx) => {
      if (!ctx.exists) {
        return makeResult({
          id: 'nsec',
          phase: 'inventory',
          title: 'ゾーンの列挙可能性（NSEC）',
          severity: 'low',
          status: 'unknown',
          summary: 'ドメインが DNS 上に存在しないため、評価対象外です',
        })
      }

      const walk = await walkOnce(domain)
      const label = NSEC_MODE_LABEL[walk.mode]

      if (walk.mode !== 'nsec') {
        return makeResult({
          id: 'nsec',
          phase: 'inventory',
          title: 'ゾーンの列挙可能性（NSEC）',
          severity: 'low',
          status: 'clear',
          summary: `${label}。ゾーンの全名前を第三者に列挙されることはありません`,
          advice:
            walk.mode === 'unavailable'
              ? undefined
              : 'この方式なら、棚卸しの網羅性は CT ログと辞書に頼ることになります',
        })
      }

      return makeResult({
        id: 'nsec',
        phase: 'inventory',
        title: 'ゾーンの列挙可能性（NSEC）',
        severity: 'low',
        // 列挙できたことは棚卸しには有利だが、裏を返せば誰にでも全名前が見えている
        status: 'warn',
        summary:
          `${label}。${walk.names.length} 件の名前を列挙しました。` +
          WALK_STOP_LABEL[walk.stop],
        advice:
          'ここで得た名前は推測ではなくゾーンが公開しているものです。棚卸しには有利ですが、' +
          '同じ手順を誰でも実行できます。運用を続けるなら NSEC3 への移行を検討してください。',
        evidence: walk.names,
      })
    },
  },
  {
    id: 'dangling-cname',
    label: 'dangling CNAME',
    run: async (domain) => {
      const { probed, notes } = await collectCandidates(domain)
      const hosts = [domain, ...probed].filter((h) => !isServiceName(h))

      const inspections = (await Promise.all(hosts.map(inspectCname))).filter(
        (i): i is CnameInspection => i !== null,
      )

      const dangling = inspections.filter((i) => i.verdict === 'dangling')
      const nodata = inspections.filter((i) => i.verdict === 'nodata')
      const prone = inspections.filter((i) => i.verdict === 'takeover-prone')

      const evidence = [
        ...dangling.map(describeVerdict),
        ...nodata.map(describeVerdict),
        ...prone.map(describeVerdict),
        ...notes,
      ]

      if (dangling.length || nodata.length) {
        return makeResult({
          id: 'dangling-cname',
          phase: 'detach',
          title: '向き先が切れた CNAME',
          severity: 'critical',
          status: 'action',
          summary:
            `${dangling.length + nodata.length} 件の CNAME が、解決できない向き先を指しています` +
            (prone.length ? `（ほかに乗っ取られやすい向き先が ${prone.length} 件）` : ''),
          advice:
            '向き先のリソースを第三者が再取得すると、このサブドメインを名乗られます。' +
            'ドメインを手放す前に CNAME を削除してください。',
          evidence,
        })
      }

      if (prone.length) {
        return makeResult({
          id: 'dangling-cname',
          phase: 'detach',
          title: '向き先が切れた CNAME',
          severity: 'critical',
          status: 'warn',
          summary: `${prone.length} 件の CNAME が、解放後に再取得されうるサービスを指しています`,
          advice:
            'これらは名前解決には成功するため、DNS だけでは生きているか判断できません。' +
            '各サービス側でリソースが実在するかを確認してください。',
          evidence,
        })
      }

      return makeResult({
        id: 'dangling-cname',
        phase: 'detach',
        title: '向き先が切れた CNAME',
        severity: 'critical',
        status: 'clear',
        summary: '向き先が切れた CNAME は見つかりませんでした',
        evidence: notes,
      })
    },
  },
  {
    id: 'cert-active',
    label: '有効な証明書',
    run: async (domain) => {
      const ct = await fetchIssuances(domain)
      if (!ct.ok) {
        return makeResult({
          id: 'cert-active',
          phase: 'release',
          title: '有効な証明書の残存',
          severity: 'high',
          status: 'unknown',
          summary: ct.reason ?? 'CT ログを取得できませんでした',
        })
      }
      const active = ct.activeCerts > 0
      return makeResult({
        id: 'cert-active',
        phase: 'release',
        title: '有効な証明書の残存',
        severity: 'high',
        status: active ? 'action' : 'clear',
        summary: active
          ? `有効期間内の証明書が ${ct.activeCerts} 件あります` +
            (ct.latestNotAfter ? `（最終失効 ${ct.latestNotAfter.slice(0, 10)}）` : '')
          : '有効期間内の証明書は残っていません',
        advice: active
          ? '手放す前に証明書を失効させてください。失効させないまま第三者に渡ると、旧証明書が悪用される余地が残ります'
          : undefined,
      })
    },
  },
  {
    id: 'caa',
    label: 'CAA による発行制限',
    run: async (domain, ctx) => {
      if (!ctx.exists) {
        return makeResult({
          id: 'caa',
          phase: 'release',
          title: '証明書発行を塞げているか',
          severity: 'medium',
          status: 'unknown',
          summary: 'ドメインが DNS 上に存在しないため、CAA は評価対象外です',
        })
      }
      const raw = await records(domain, 'CAA')
      const parsed = raw.map(parseCaa).filter((r): r is CaaRecord => r !== null)
      const issueTags = parsed.filter((r) => r.tag === 'issue' || r.tag === 'issuewild')
      // `issue ";"` は「どの CA にも発行を許可しない」の意味
      const blocked =
        issueTags.length > 0 && issueTags.every((r) => r.value.trim() === ';')
      const has = parsed.length > 0

      return makeResult({
        id: 'caa',
        phase: 'release',
        title: '証明書発行を塞げているか',
        severity: 'medium',
        status: blocked ? 'clear' : has ? 'warn' : 'action',
        summary: !has
          ? 'CAA レコードがありません。誰でも新しい証明書を取得できます'
          : blocked
            ? 'CAA で全 CA からの証明書発行を禁止しています'
            : `CAA はありますが、${issueTags.length} 件の CA への発行を許可したままです`,
        advice: blocked
          ? undefined
          : '冷却期間に入ったら `0 issue ";"` を設定して、新規の証明書発行を止めておくと安全です',
        evidence: parsed.map(formatCaa),
      })
    },
  },
  {
    id: 'wildcard',
    label: 'ワイルドカード DNS',
    run: async (domain) => {
      const probe = `mitori-probe-${Math.random().toString(36).slice(2, 10)}.${domain}`
      const alive = await isAlive(probe)
      return makeResult({
        id: 'wildcard',
        phase: 'cooldown',
        title: 'ワイルドカード DNS',
        severity: 'medium',
        status: alive ? 'action' : 'clear',
        summary: alive
          ? '存在しないはずのサブドメインが解決します。ワイルドカードが設定されています'
          : 'ワイルドカードは設定されていません',
        advice: alive
          ? 'ワイルドカードは全サブドメインを生かし続けます。畳む段階では削除してください'
          : undefined,
        evidence: alive ? [probe] : undefined,
      })
    },
  },
  {
    id: 'mail-spf',
    label: 'SPF',
    run: async (domain) => {
      const txt = await txtRecords(domain)
      const spf = txt.filter((t) => /^v=spf1\b/i.test(t))
      return makeResult({
        id: 'mail-spf',
        phase: 'detach',
        title: 'SPF レコード',
        severity: 'low',
        status: spf.length ? 'action' : 'clear',
        summary: spf.length
          ? 'SPF が残っています。他システムがこのドメインを送信元として参照している可能性があります'
          : 'SPF は残っていません',
        advice: spf.length
          ? '他ドメインの SPF から include: されていないかを確認してから削除してください'
          : undefined,
        evidence: spf,
      })
    },
  },
  {
    id: 'mail-dmarc',
    label: 'DMARC',
    run: async (domain, ctx) => {
      if (!ctx.exists) {
        return makeResult({
          id: 'mail-dmarc',
          phase: 'cooldown',
          title: 'DMARC による なりすまし防止',
          severity: 'medium',
          status: 'unknown',
          summary: 'ドメインが DNS 上に存在しないため、DMARC は評価対象外です',
        })
      }
      const txt = await txtRecords(`_dmarc.${domain}`)
      const dmarc = txt.find((t) => /^v=DMARC1\b/i.test(t))
      const policy = dmarc?.match(/\bp\s*=\s*(none|quarantine|reject)/i)?.[1]?.toLowerCase()
      const strict = policy === 'reject' || policy === 'quarantine'
      return makeResult({
        id: 'mail-dmarc',
        phase: 'cooldown',
        title: 'DMARC による なりすまし防止',
        severity: 'medium',
        status: strict ? 'clear' : 'action',
        summary: !dmarc
          ? 'DMARC がありません。冷却期間中のなりすまし送信を抑止できません'
          : `DMARC のポリシーは p=${policy ?? '不明'} です`,
        advice: strict
          ? undefined
          : '畳む過程では `v=DMARC1; p=reject;` を置き、このドメインを名乗るメールを拒否させるのが安全です',
        evidence: dmarc ? [dmarc] : undefined,
      })
    },
  },
  {
    id: 'mail-dkim',
    label: 'DKIM',
    run: async (domain) => {
      const hits: string[] = []
      await Promise.all(
        DKIM_SELECTORS.map(async (sel) => {
          const txt = await txtRecords(`${sel}._domainkey.${domain}`)
          if (txt.some((t) => /v=DKIM1|p=/i.test(t))) hits.push(`${sel}._domainkey`)
        }),
      )
      hits.sort()
      return makeResult({
        id: 'mail-dkim',
        phase: 'detach',
        title: 'DKIM 鍵の残存',
        severity: 'low',
        status: hits.length ? 'action' : 'clear',
        summary: hits.length
          ? `${hits.length} 件の DKIM セレクタが残っています（辞書照合のため網羅ではありません）`
          : '既知のセレクタでは DKIM は見つかりませんでした',
        evidence: hits,
      })
    },
  },
  {
    id: 'acme',
    label: 'ACME チャレンジ',
    run: async (domain) => {
      const txt = await txtRecords(`_acme-challenge.${domain}`)
      return makeResult({
        id: 'acme',
        phase: 'detach',
        title: 'ACME チャレンジの残骸',
        severity: 'low',
        status: txt.length ? 'action' : 'clear',
        summary: txt.length
          ? '_acme-challenge の TXT が残っています。証明書の自動更新がまだ動いている可能性があります'
          : '_acme-challenge の残骸はありません',
        advice: txt.length ? '自動更新のジョブを止めてから TXT を削除してください' : undefined,
        evidence: txt,
      })
    },
  },
  {
    id: 'ns',
    label: '委譲先',
    run: async (domain) => {
      const ns = await records(domain, 'NS')
      return makeResult({
        id: 'ns',
        phase: 'inventory',
        title: 'DNS の委譲先',
        severity: 'info',
        status: 'clear',
        summary: ns.length ? `${ns.length} 台の権威サーバに委譲されています` : '委譲先を取得できませんでした',
        advice: ns.length
          ? '管理を外部業者に委ねている場合、契約終了時にゾーンごと消える／乗っ取られる経路になります。手放す前に自分の管理下へ戻してください'
          : undefined,
        evidence: ns,
      })
    },
  },
  {
    id: 'dnssec',
    label: 'DNSSEC',
    run: async (domain) => {
      const ds = await records(domain, 'DS')
      return makeResult({
        id: 'dnssec',
        phase: 'release',
        title: 'DNSSEC',
        severity: 'low',
        status: ds.length ? 'warn' : 'clear',
        summary: ds.length
          ? 'DS レコードがあります。DNSSEC を有効にしたまま委譲を外すと名前解決が壊れます'
          : 'DNSSEC は設定されていません',
        advice: ds.length
          ? '手放す前に DNSSEC を無効化してください。DS を残したままにすると意図しない解決失敗を招きます'
          : undefined,
        evidence: ds,
      })
    },
  },
  {
    id: 'registry',
    label: '登録情報',
    run: async (domain) => {
      const info = await lookupRdap(domain)
      if (!info.supported || info.reason) {
        return makeResult({
          id: 'registry',
          phase: 'release',
          title: '登録情報と有効期限',
          severity: 'info',
          status: 'unknown',
          summary: info.reason ?? 'RDAP から情報を取得できませんでした',
        })
      }
      const evidence: string[] = []
      if (info.registrar) evidence.push(`レジストラ: ${info.registrar}`)
      if (info.registeredAt) evidence.push(`登録日: ${info.registeredAt.slice(0, 10)}`)
      if (info.expiresAt) evidence.push(`有効期限: ${info.expiresAt.slice(0, 10)}`)
      if (info.statuses.length) evidence.push(`ステータス: ${info.statuses.join(', ')}`)

      return makeResult({
        id: 'registry',
        phase: 'release',
        title: '登録情報と有効期限',
        severity: 'info',
        status: 'clear',
        summary: info.expiresAt
          ? `有効期限は ${info.expiresAt.slice(0, 10)} です`
          : '登録情報を取得しました',
        evidence,
      })
    },
  },
  {
    id: 'wayback',
    label: 'アーカイブ',
    run: async (domain) => {
      const wb = await checkWayback(domain)
      if (!wb.ok) {
        return makeResult({
          id: 'wayback',
          phase: 'inventory',
          title: '消せない参照（Web アーカイブ）',
          severity: 'info',
          status: 'unknown',
          summary: wb.reason ?? 'Wayback Machine を確認できませんでした',
        })
      }
      return makeResult({
        id: 'wayback',
        phase: 'inventory',
        title: '消せない参照（Web アーカイブ）',
        severity: 'info',
        status: 'clear',
        summary: wb.archived
          ? `アーカイブが存在します（最新 ${wb.timestamp ? formatWaybackTimestamp(wb.timestamp) : '不明'}）。これは削除できない参照です`
          : 'アーカイブは見つかりませんでした',
        advice: wb.archived
          ? '過去の内容は残り続けます。冷却期間の長さは、この種の消せない参照の寿命で決めてください'
          : undefined,
        evidence: wb.url ? [wb.url] : undefined,
      })
    },
  },
  {
    id: 'backlinks-wikimedia',
    label: '百科事典からの参照',
    run: async (domain) => {
      const title = '百科事典からの参照（Wikipedia ほか）'
      const wm = await fetchWikimediaLinks(domain)

      if (!wm.ok) {
        return makeResult({
          id: 'backlinks-wikimedia',
          phase: 'inventory',
          title,
          severity: 'high',
          status: 'unknown',
          summary: 'Wikimedia のどのプロジェクトにも問い合わせできませんでした',
        })
      }

      const evidence = backlinkEvidence(wm)
      const unchecked = wm.failed.length + wm.skipped.length

      if (wm.pages === 0) {
        return makeResult({
          id: 'backlinks-wikimedia',
          phase: 'inventory',
          title,
          severity: 'high',
          // 照会できていないプロジェクトがあるなら「痕跡なし」とは言えない
          status: unchecked ? 'warn' : 'clear',
          summary: unchecked
            ? `照会できた ${wm.queried} プロジェクトからの参照は見つかりませんでしたが、` +
              `残る ${unchecked} プロジェクトは確認できていません`
            : `調査した ${wm.queried} プロジェクトからの参照は見つかりませんでした`,
          advice: unchecked
            ? '時間をおいて再検査すると、確認できなかったプロジェクトも照会できます。'
            : undefined,
          evidence,
        })
      }

      // 本文からの参照だけが百科事典としての信頼を引き継ぐ。
      // ノートや利用者ページからの言及は残っていても実害が小さいので区別する
      const fromArticles = wm.articles > 0

      return makeResult({
        id: 'backlinks-wikimedia',
        phase: 'inventory',
        title,
        severity: 'high',
        status: fromArticles ? 'action' : 'warn',
        summary:
          (fromArticles
            ? `百科事典の本文 ${wm.articles} ページから参照されています`
            : `ノート・利用者ページなど ${wm.pages} ページから参照されています。本文からの参照はありません`) +
          // 打ち切りと未照会は原因が違うが、読み手にとっての意味は同じ「まだ下がある」
          (wm.truncated || unchecked
            ? '（確認できていない範囲があるため、実際はこれより多い可能性があります）'
            : ''),
        advice: fromArticles
          ? '出典に書かれた URL は、ドメインを手放しても書き換わりません。' +
            '新しい所有者が百科事典の信頼をそのまま引き継ぎ、出典元の内容を差し替えられます。' +
            '手放す前に、各出典をアーカイブ版へ差し替えてください（自分で編集するか、ノートで依頼する）。' +
            'アーカイブが無いページは、消える前にスナップショットを取っておく必要があります。'
          : '本文からの参照ではないため急ぎませんが、リンク先が第三者のものになることは変わりません。',
        evidence,
      })
    },
  },
]

export interface ScanProgress {
  completed: number
  total: number
  current: string
}

export async function runScan(
  domain: string,
  onResult: (result: CheckResult) => void,
  onProgress: (progress: ScanProgress) => void,
): Promise<ScanReport> {
  resetCache()
  resetCtCache()
  walkCache.clear()
  const startedAt = new Date().toISOString()
  const results: CheckResult[] = []
  const notes: string[] = []
  let completed = 0

  onProgress({ completed: 0, total: CHECKS.length, current: '開始' })

  // 各検査の前提となるので、ドメインの存在確認だけは先に済ませる（結果は DoH 側でキャッシュされる）
  let ctx: ScanContext = { exists: true }
  try {
    const soa = await resolve(domain, 'SOA')
    ctx = { exists: soa.Status !== RCODE_NXDOMAIN }
  } catch {
    notes.push('ドメインの存在確認に失敗したため、存在するものとして検査を続けます')
  }

  await Promise.all(
    CHECKS.map(async (check) => {
      try {
        const produced = await check.run(domain, ctx)
        for (const r of Array.isArray(produced) ? produced : [produced]) {
          results.push(r)
          onResult(r)
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err)
        notes.push(`${check.label}: 検査に失敗しました (${message})`)
        const failed = makeResult({
          id: check.id,
          phase: 'inventory',
          title: check.label,
          severity: 'info',
          status: 'unknown',
          summary: `検査に失敗しました: ${message}`,
        })
        results.push(failed)
        onResult(failed)
      } finally {
        completed += 1
        onProgress({ completed, total: CHECKS.length, current: check.label })
      }
    }),
  )

  const decidable = results.filter((r) => r.weight > 0 && r.status !== 'unknown')
  const total = decidable.reduce((sum, r) => sum + r.weight, 0)
  const earned = decidable.reduce(
    (sum, r) => sum + (r.status === 'clear' ? r.weight : r.status === 'warn' ? r.weight / 2 : 0),
    0,
  )

  return {
    domain,
    startedAt,
    finishedAt: new Date().toISOString(),
    results,
    score: total === 0 ? 0 : Math.round((earned / total) * 100),
    decidable: decidable.length,
    notes,
  }
}
