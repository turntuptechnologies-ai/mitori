import { resolve, TYPE_CODE, type DnsAnswer } from './doh'

/**
 * NSEC ウォーキングによるゾーン列挙。
 *
 * DNSSEC は「名前が存在しない」ことも署名して証明する必要があるが、
 * 問い合わせのたびに署名するのは秘密鍵をオンラインに置くことになる。
 * そこで既存の名前を正規順序に並べ「X の次は Y だ」という文を事前に署名しておく。
 * これが NSEC。
 *
 * 副作用として、不在を証明するたびに「実在する次の名前」が漏れる。
 * 返ってきた名前の直後をまた聞けば、ゾーンの全名前が順番に手に入る。
 * CT ログにも辞書にも出てこない名前が取れるので、mitori に足りない網羅性を補える。
 *
 * ただし歩けるのは NSEC を素直に返すゾーンだけで、実際には次の 3 つに割れる:
 *
 *   NSEC        … 歩ける（ルートゾーン、nlnetlabs.nl で確認）
 *   NSEC3       … 名前がハッシュ化されており歩けない（iana.org）
 *   ホワイトライ … 聞かれた名前のすぐ隣までしか無い NSEC をその場で合成して返す。
 *                 一歩も進まない（ietf.org, RFC 4470）。NXDOMAIN ではなく NOERROR を返す
 *
 * 公開されている記録を読んでいるだけで攻撃ではない。NSEC3 やホワイトライが
 * 普及しているのは、運用者がこの性質を承知しているため。
 */

export type ZoneNsecMode = 'nsec' | 'nsec3' | 'white-lies' | 'unavailable'

export const NSEC_MODE_LABEL: Record<ZoneNsecMode, string> = {
  nsec: 'NSEC（列挙可能）',
  nsec3: 'NSEC3（ハッシュ化されており列挙不可）',
  'white-lies': 'ホワイトライ（合成 NSEC により列挙不可）',
  unavailable: 'NSEC を返さない（未署名、または非対応）',
}

function normalizeName(name: string): string {
  return name.replace(/\.$/, '').toLowerCase()
}

/** NSEC の RDATA は「次の名前 タイプ列」の形。先頭が次の名前 */
export function nextNameOf(nsecData: string): string {
  return normalizeName(nsecData.trim().split(/\s+/)[0] ?? '')
}

/**
 * Authority セクションからゾーンの方式を判定する純粋関数。
 *
 * @param authority DO ビット付きで存在しない名前を引いたときの Authority
 * @param probeName そのとき問い合わせた名前
 */
export function classifyAuthority(authority: DnsAnswer[], probeName: string): ZoneNsecMode {
  if (authority.some((a) => a.type === TYPE_CODE.NSEC3)) return 'nsec3'

  const nsec = authority.filter((a) => a.type === TYPE_CODE.NSEC)
  if (!nsec.length) return 'unavailable'

  const probe = normalizeName(probeName)
  // 問い合わせた名前そのものを所有者とする NSEC は、その場で合成されたもの。
  // 実在する名前の NSEC なら所有者は別の名前になる
  const synthesized = nsec.some(
    (a) => normalizeName(a.name) === probe || nextNameOf(a.data) === `\\000.${probe}`,
  )
  return synthesized ? 'white-lies' : 'nsec'
}

/** 正規順序で name の直後に来る名前。最小バイトのラベルを足す */
export function successorProbe(name: string): string {
  return `\\000.${name}`
}

/**
 * name の配下をまるごと飛ばして、その次の名前を探すためのプローブ。
 *
 * name が子ゾーンへの委譲点だと、`\000.name` はリゾルバが子ゾーンに問い合わせてしまい、
 * 親の NSEC が返らない（子が NSEC3 なら特にそうなる）。
 * 最左ラベルの末尾に最小バイトを足した兄弟名なら子ゾーンに入らず、
 * かつ name 配下の全名前より後にソートされるので、委譲を飛び越えられる。
 */
export function siblingProbe(name: string): string {
  const dot = name.indexOf('.')
  if (dot === -1) return `${name}\\000`
  return `${name.slice(0, dot)}\\000${name.slice(dot)}`
}

export interface ZoneProbe {
  mode: ZoneNsecMode
  /** 判定に使った Authority の中身（表示用） */
  evidence: string[]
}

/** 存在しない名前を 1 回引いて、ゾーンが歩けるかどうかだけを判定する */
export async function probeZone(zone: string): Promise<ZoneProbe> {
  const probeName = `mitori-nsec-probe.${zone}`
  try {
    const res = await resolve(probeName, 'A', { dnssec: true })
    const authority = res.Authority ?? []
    const mode = classifyAuthority(authority, probeName)
    const evidence = authority
      .filter((a) => a.type === TYPE_CODE.NSEC || a.type === TYPE_CODE.NSEC3)
      .slice(0, 3)
      .map((a) => `${normalizeName(a.name)} → ${a.data.slice(0, 80)}`)
    return { mode, evidence }
  } catch {
    return { mode: 'unavailable', evidence: [] }
  }
}

/** 歩き終えた理由。「取りこぼしたかどうか」を呼び出し元が判断できるようにする */
export type WalkStop = 'complete' | 'limit' | 'timeout' | 'blocked' | 'not-walkable'

export const WALK_STOP_LABEL: Record<WalkStop, string> = {
  complete: 'ゾーンを一周し、列挙し切りました',
  limit: '件数の上限に達したため打ち切りました。実際にはさらに名前があります',
  timeout: '時間の上限に達したため打ち切りました。実際にはさらに名前があります',
  blocked: '途中で NSEC を辿れなくなり打ち切りました。以降の名前は取得できていません',
  'not-walkable': '列挙できないゾーンです',
}

export interface WalkLimits {
  /** 取得する名前の上限 */
  maxNames: number
  /** 打ち切るまでの時間（ミリ秒）。1 名前 1 クエリの直列処理なので時間で縛らないと待たされる */
  budgetMs: number
}

export interface WalkResult {
  mode: ZoneNsecMode
  /** 発見した名前（ゾーン頂点は含まない） */
  names: string[]
  stop: WalkStop
}

/**
 * NSEC を辿ってゾーンの名前を列挙する。
 *
 * 各ステップが前のステップの結果に依存するため直列で、1 名前あたり 1 クエリかかる。
 * 上限に達したら打ち切り、打ち切ったことを呼び出し元に必ず伝える。
 */
export async function walkZone(zone: string, limits: WalkLimits): Promise<WalkResult> {
  const probe = await probeZone(zone)
  if (probe.mode !== 'nsec') {
    return { mode: probe.mode, names: [], stop: 'not-walkable' }
  }

  const deadline = Date.now() + limits.budgetMs
  const zoneName = normalizeName(zone)
  const names: string[] = []
  const seen = new Set<string>([zoneName])
  let current = zoneName
  let stop: WalkStop = 'limit'

  /** current の次の名前を取る。委譲で止まったらサブツリーを飛ばして再挑戦する */
  const nextAfter = async (name: string): Promise<string | null> => {
    for (const buildProbe of [successorProbe, siblingProbe]) {
      let res
      try {
        res = await resolve(buildProbe(name), 'A', { dnssec: true })
      } catch {
        continue
      }
      const nsec = (res.Authority ?? []).filter((a) => a.type === TYPE_CODE.NSEC)
      const record =
        nsec.find((a) => normalizeName(a.name) === name) ??
        nsec.find((a) => normalizeName(a.name).endsWith(zoneName))
      if (record) return nextNameOf(record.data)
    }
    return null
  }

  for (let step = 0; step < limits.maxNames; step += 1) {
    if (Date.now() >= deadline) {
      stop = 'timeout'
      break
    }
    const next = await nextAfter(current)
    if (next === null) {
      stop = 'blocked'
      break
    }
    // ゾーン頂点に戻ったら一周した
    if (next === zoneName) {
      stop = 'complete'
      break
    }
    // ゾーン外に出た、または同じ名前に戻った場合は打ち切る（無限ループ防止）
    if (!next.endsWith(`.${zoneName}`) || seen.has(next)) {
      stop = 'blocked'
      break
    }

    seen.add(next)
    names.push(next)
    current = next
  }

  return { mode: 'nsec', names, stop }
}
