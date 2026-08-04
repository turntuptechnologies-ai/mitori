import { RCODE_NXDOMAIN, records, resolve } from './doh'

/**
 * dangling CNAME（向き先が消えた CNAME）の検出。
 *
 * 放置されたサブドメインが乗っ取られる典型的な経路。CNAME だけが残り、
 * 向き先のリソースが解放されていると、そこを再取得した第三者が
 * そのサブドメインを名乗れてしまう。手放す前にこそ潰しておきたい。
 *
 * 実測して分かった DNS 側の現実（2026-08 時点、Cloudflare DoH）:
 *
 *   no-such.wikipedia.org      → NXDOMAIN(3), 応答なし
 *   no-such.github.com         → NOERROR(0),  応答なし   ← 存在しないのに NXDOMAIN ではない
 *   no-such.example.com        → NOERROR(0),  応答なし   ← 同上
 *   no-such-bucket.s3.amazonaws.com → NOERROR(0), A が 10 件  ← 解放済みでも解決する
 *   no-such.netlify.app        → NOERROR(0),  A が 2 件
 *   no-such.github.io          → NOERROR(0),  A が 4 件
 *
 * つまり NXDOMAIN は「切れている」の十分条件でしかなく、必要条件ではない。
 * 判定の主軸は rcode ではなく「向き先がアドレスを持つか」に置く必要がある。
 * 逆にプロバイダがワイルドカードを持つ場合は、リソースが解放されていても解決するため、
 * HTTP 応答を見ないと確定できない（ブラウザからは CORS で読めない）。
 * そこで「アドレスを持たない＝切れている」と「乗っ取られやすい向き先」を分けて報告する。
 */

/** 解放後に第三者が同じ名前を再取得しうるサービス群 */
export const TAKEOVER_PRONE: Array<{ suffix: string; service: string }> = [
  { suffix: '.s3.amazonaws.com', service: 'Amazon S3' },
  { suffix: '.s3-website.amazonaws.com', service: 'Amazon S3 (静的サイト)' },
  { suffix: '.cloudfront.net', service: 'Amazon CloudFront' },
  { suffix: '.elasticbeanstalk.com', service: 'AWS Elastic Beanstalk' },
  { suffix: '.github.io', service: 'GitHub Pages' },
  { suffix: '.herokuapp.com', service: 'Heroku' },
  { suffix: '.herokudns.com', service: 'Heroku' },
  { suffix: '.azurewebsites.net', service: 'Azure App Service' },
  { suffix: '.cloudapp.azure.com', service: 'Azure' },
  { suffix: '.trafficmanager.net', service: 'Azure Traffic Manager' },
  { suffix: '.blob.core.windows.net', service: 'Azure Blob Storage' },
  { suffix: '.netlify.app', service: 'Netlify' },
  { suffix: '.netlify.com', service: 'Netlify' },
  { suffix: '.vercel.app', service: 'Vercel' },
  { suffix: '.vercel-dns.com', service: 'Vercel' },
  { suffix: '.pages.dev', service: 'Cloudflare Pages' },
  { suffix: '.workers.dev', service: 'Cloudflare Workers' },
  { suffix: '.firebaseapp.com', service: 'Firebase' },
  { suffix: '.web.app', service: 'Firebase Hosting' },
  { suffix: '.surge.sh', service: 'Surge' },
  { suffix: '.ghost.io', service: 'Ghost' },
  { suffix: '.wpengine.com', service: 'WP Engine' },
  { suffix: '.zendesk.com', service: 'Zendesk' },
  { suffix: '.freshdesk.com', service: 'Freshdesk' },
  { suffix: '.statuspage.io', service: 'Statuspage' },
  { suffix: '.uservoice.com', service: 'UserVoice' },
  { suffix: '.readthedocs.io', service: 'Read the Docs' },
  { suffix: '.bitbucket.io', service: 'Bitbucket Cloud' },
  { suffix: '.gitlab.io', service: 'GitLab Pages' },
  { suffix: '.myshopify.com', service: 'Shopify' },
  { suffix: '.tumblr.com', service: 'Tumblr' },
  { suffix: '.wixdns.net', service: 'Wix' },
  { suffix: '.squarespace.com', service: 'Squarespace' },
  { suffix: '.pantheonsite.io', service: 'Pantheon' },
  { suffix: '.unbouncepages.com', service: 'Unbounce' },
  { suffix: '.webflow.io', service: 'Webflow' },
  { suffix: '.createsend.com', service: 'Campaign Monitor' },
  { suffix: '.hs-sites.com', service: 'HubSpot' },
  { suffix: '.intercom.help', service: 'Intercom' },
  { suffix: '.canny.io', service: 'Canny' },
  { suffix: '.gitbook.io', service: 'GitBook' },
  { suffix: '.notion.site', service: 'Notion' },
  { suffix: '.hatenablog.com', service: 'はてなブログ' },
  { suffix: '.sendgrid.net', service: 'SendGrid' },
  { suffix: '.desk.com', service: 'Desk.com' },
  { suffix: '.launchrock.com', service: 'LaunchRock' },
  { suffix: '.strikingly.com', service: 'Strikingly' },
  { suffix: '.cargocollective.com', service: 'Cargo Collective' },
  { suffix: '.acquia-sites.com', service: 'Acquia' },
]

/**
 * `_dmarc` `_acme-challenge` `_25._tcp` `_openpgpkey` のようなアンダースコア始まりの名前は
 * プロトコル専用で、TXT / TLSA / OPENPGPKEY など A 以外のレコード型を使う。
 *
 * これらを dangling 判定に掛けると、正常な設定を軒並み「向き先にアドレスが無い」と
 * 誤検出する（実測で nlnetlabs.nl の 6 件中 6 件が該当した）。
 * 型ごとに引き直せば厳密に判定できるがクエリ数が跳ね上がるうえ、
 * これらの名前はブラウザから到達する先ではないので、乗っ取りの主経路にもならない。
 * よって dangling 検査の対象から外す。
 */
export function isServiceName(host: string): boolean {
  return host.split('.').some((label) => label.startsWith('_'))
}

export function matchTakeoverService(target: string): string | undefined {
  const normalized = target.replace(/\.$/, '').toLowerCase()
  return TAKEOVER_PRONE.find((s) => normalized.endsWith(s.suffix))?.service
}

export type CnameVerdict = 'ok' | 'dangling' | 'nodata' | 'takeover-prone'

export interface TargetProbe {
  /** 向き先に A を引いたときの rcode */
  rcode: number
  /** 向き先が A / AAAA / CNAME のいずれかを持つか */
  hasAddress: boolean
  /**
   * アドレス以外のレコード（TXT など）を持つか。
   * `_acme-challenge` や `_domainkey` の CNAME は、TXT しか持たないホストを指すのが
   * 正当な使い方なので、これを見ないと正常な設定を「切れている」と誤判定する。
   */
  hasOtherRecords: boolean
  /** 乗っ取られやすいサービスに該当するならその名前 */
  service?: string
}

/** 向き先の解決結果から判定する純粋関数 */
export function classifyCnameTarget(probe: TargetProbe): CnameVerdict {
  // 向き先の名前自体が存在しない。CNAME は確実に切れている
  if (probe.rcode === RCODE_NXDOMAIN) return 'dangling'

  if (!probe.hasAddress) {
    // TXT だけを持つ向き先は、DKIM や ACME の委譲として正当
    if (probe.hasOtherRecords) return 'ok'
    // NXDOMAIN を返さないゾーンが多いため、アドレスを持たないことのほうが実用上の主軸になる。
    // dangling ほど断定的ではないが、扱いは同じ「要対応」
    return 'nodata'
  }

  // 解決はする。プロバイダのワイルドカードで生きているだけかもしれない
  if (probe.service) return 'takeover-prone'
  return 'ok'
}

export interface CnameInspection {
  host: string
  target: string
  verdict: CnameVerdict
  service?: string
}

/** host に CNAME があれば、その向き先を調べる。CNAME が無ければ null */
export async function inspectCname(host: string): Promise<CnameInspection | null> {
  const cnames = await records(host, 'CNAME')
  if (!cnames.length) return null

  const target = cnames[0]!.replace(/\.$/, '')
  const [aRes, aaaa, targetCname, txt] = await Promise.all([
    resolve(target, 'A'),
    records(target, 'AAAA'),
    records(target, 'CNAME'),
    records(target, 'TXT'),
  ])

  const hasAddress = (aRes.Answer?.length ?? 0) > 0 || aaaa.length > 0 || targetCname.length > 0
  const service = matchTakeoverService(target)

  return {
    host,
    target,
    verdict: classifyCnameTarget({
      rcode: aRes.Status,
      hasAddress,
      hasOtherRecords: txt.length > 0,
      service,
    }),
    service,
  }
}

export function describeVerdict(inspection: CnameInspection): string {
  const { host, target, verdict, service } = inspection
  switch (verdict) {
    case 'dangling':
      return `${host} → ${target}（向き先が存在しません）`
    case 'nodata':
      return `${host} → ${target}（向き先にアドレスがありません）`
    case 'takeover-prone':
      return `${host} → ${target}（${service}）`
    default:
      return `${host} → ${target}`
  }
}
