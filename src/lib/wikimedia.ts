/**
 * Wikimedia の外部リンク検索 (list=exturlusage) で、このドメインを参照している
 * ページを拾う。
 *
 * 被リンクを網羅する索引は無料では手に入らない。商用の被リンク API は鍵と課金が要り、
 * 検索エンジンの `link:` は廃止済み、Common Crawl の被リンクデータ (webgraph) は
 * 数十 GB ある上にファイル全体が gzip なので、ブラウザからは部分取得すらできない。
 *
 * ただし供養の観点で危ないのは被リンクの「数」ではなく、手放した後に新しい所有者へ
 * 権威を引き継いでしまう参照で、百科事典の出典はその筆頭にあたる。
 * 失効したドメインを買って出典元ごと差し替える手口は実在する。
 * だから網羅を諦めて、権威の高い参照先だけを名指しで取りにいく。
 *
 * API の実測メモ:
 * - `origin=*` を付けると匿名リクエストにも CORS ヘッダが返る（付けないとブラウザから読めない）
 * - `eulimit` は匿名でも 500 まで通る
 * - euquery はホスト名の前方一致で、bare でもサブドメインを含む。
 *   `nhk.or.jp` は `www.nhk.or.jp` や `archives.nhk.or.jp` を拾う。
 *   逆に `www.nhk.or.jp` と書くとそのホストだけに絞られるので、bare で渡すこと
 * - 返るのは (ページ, URL) の組なので、同じページが何度も現れる。
 *   実測では ja.wikipedia の 387 hits がユニーク記事 144 件だった
 * - **匿名リクエストの同時接続が IP 単位で絞られている。**
 *   7 プロジェクトを並列に投げると後続が 429 になる（実測: 並列 2 で既に 4/7 が 429、
 *   直列なら 0 件失敗）。しかも一度当たるとしばらく尾を引く。だから直列に回す
 */

export interface WikimediaProject {
  host: string
  label: string
}

/**
 * 調査対象。言語版は 300 以上あるので網羅はしない。
 * 日本語圏のドメインで実際に収穫があったものを選んでいる。
 */
export const WIKIMEDIA_PROJECTS: WikimediaProject[] = [
  { host: 'ja.wikipedia.org', label: '日本語版 Wikipedia' },
  { host: 'en.wikipedia.org', label: '英語版 Wikipedia' },
  { host: 'www.wikidata.org', label: 'Wikidata' },
  { host: 'commons.wikimedia.org', label: 'Wikimedia Commons' },
  { host: 'zh.wikipedia.org', label: '中国語版 Wikipedia' },
  { host: 'ko.wikipedia.org', label: '韓国語版 Wikipedia' },
  { host: 'ja.wikivoyage.org', label: '日本語版 Wikivoyage' },
]

/** 匿名で通る上限 */
const PAGE_SIZE = 500

/** 1 プロジェクトあたりのリクエスト数。ここで打ち切った場合は必ず結果に出す */
const MAX_REQUESTS_PER_PROJECT = 2

/**
 * レート制限のせいで直列にしか回せず、1 プロジェクトあたり 0.6〜1.3 秒かかる。
 * NSEC ウォークと同じように時間で上限を掛け、回りきらなかったプロジェクトは
 * 「参照なし」ではなく「未照会」として区別する。
 */
export const WIKIMEDIA_BUDGET_MS = 6000

/**
 * 本文の名前空間。ノートや利用者ページからの言及は、残っていても
 * 百科事典としての権威を引き継がないので、記事とは分けて数える。
 */
export const ARTICLE_NAMESPACE = 0

export interface ExturlusageHit {
  ns: number
  title: string
  url: string
}

export interface ExturlusagePage {
  hits: ExturlusageHit[]
  /** 続きがある場合の継続トークン */
  cont?: string
}

interface ExturlusageResponse {
  query?: { exturlusage?: { ns?: number; title?: string; url?: string }[] }
  continue?: { eucontinue?: string }
}

export function buildExturlusageUrl(host: string, domain: string, cont?: string): string {
  const params = new URLSearchParams({
    action: 'query',
    list: 'exturlusage',
    euquery: domain,
    eulimit: String(PAGE_SIZE),
    euprop: 'title|url',
    format: 'json',
    formatversion: '2',
    // 匿名リクエストに CORS ヘッダを返させる。これが無いとブラウザから読めない
    origin: '*',
  })
  if (cont) params.set('eucontinue', cont)
  return `https://${host}/w/api.php?${params}`
}

export function parseExturlusage(body: unknown): ExturlusagePage {
  const data = body as ExturlusageResponse | null
  const hits: ExturlusageHit[] = []
  for (const raw of data?.query?.exturlusage ?? []) {
    if (typeof raw.title !== 'string' || typeof raw.url !== 'string') continue
    hits.push({ ns: typeof raw.ns === 'number' ? raw.ns : -1, title: raw.title, url: raw.url })
  }
  return { hits, cont: data?.continue?.eucontinue }
}

export interface PageGroups {
  /** 本文（記事・項目）のページ名。重複を除く */
  articles: string[]
  /** ノート・利用者ページなど、本文以外のページ名。重複を除く */
  others: string[]
  /** 参照されている URL。重複を除く */
  urls: string[]
}

export function groupHits(hits: ExturlusageHit[]): PageGroups {
  const articles = new Set<string>()
  const others = new Set<string>()
  const urls = new Set<string>()
  for (const hit of hits) {
    if (hit.ns === ARTICLE_NAMESPACE) articles.add(hit.title)
    else others.add(hit.title)
    urls.add(hit.url)
  }
  return {
    articles: [...articles].sort(),
    others: [...others].sort(),
    urls: [...urls].sort(),
  }
}

/**
 * ok      … 照会できた
 * failed  … 照会したが応答が得られなかった
 * skipped … 上限に達したので照会していない
 *
 * failed と skipped を ok と混ぜると「参照が無い」と誤読される。必ず分けて数える。
 */
export type ProjectState = 'ok' | 'failed' | 'skipped'

export interface ProjectLinks extends PageGroups {
  project: WikimediaProject
  state: ProjectState
  /** リクエスト数の上限で打ち切ったか */
  truncated: boolean
  /** レート制限に当たったか。当たったら以降のプロジェクトは照会しない */
  rateLimited: boolean
  reason?: string
}

export interface WikimediaResult {
  /** 1 つでも照会できたか */
  ok: boolean
  projects: ProjectLinks[]
  /** 参照が 1 件でも見つかったプロジェクト */
  found: ProjectLinks[]
  /** 実際に照会できたプロジェクト数 */
  queried: number
  /** 本文からの参照。プロジェクト横断の合計 */
  articles: number
  /** 本文以外も含めた参照ページ数 */
  pages: number
  truncated: boolean
  /** 照会に失敗したプロジェクト名 */
  failed: string[]
  /** 上限に達して照会しなかったプロジェクト名 */
  skipped: string[]
}

export function summarize(projects: ProjectLinks[]): WikimediaResult {
  const ok = projects.filter((p) => p.state === 'ok')
  return {
    ok: ok.length > 0,
    projects,
    found: ok.filter((p) => p.articles.length > 0 || p.others.length > 0),
    queried: ok.length,
    articles: ok.reduce((n, p) => n + p.articles.length, 0),
    pages: ok.reduce((n, p) => n + p.articles.length + p.others.length, 0),
    truncated: ok.some((p) => p.truncated),
    failed: projects.filter((p) => p.state === 'failed').map((p) => p.project.label),
    skipped: projects.filter((p) => p.state === 'skipped').map((p) => p.project.label),
  }
}

function emptyLinks(
  project: WikimediaProject,
  state: ProjectState,
  reason: string,
  rateLimited = false,
): ProjectLinks {
  return {
    project,
    state,
    articles: [],
    others: [],
    urls: [],
    truncated: false,
    rateLimited,
    reason,
  }
}

async function fetchProjectLinks(
  project: WikimediaProject,
  domain: string,
  deadline: number,
): Promise<ProjectLinks> {
  const hits: ExturlusageHit[] = []
  let cont: string | undefined
  let truncated = false

  for (let i = 0; i < MAX_REQUESTS_PER_PROJECT; i += 1) {
    // 2 ページ目に入る前にも残り時間を見る。1 プロジェクトで budget を食い潰さない
    if (i > 0 && Date.now() >= deadline) {
      truncated = true
      break
    }

    let page: ExturlusagePage
    try {
      const res = await fetch(buildExturlusageUrl(project.host, domain, cont))
      if (res.status === 429) {
        if (hits.length) {
          truncated = true
          break
        }
        return emptyLinks(project, 'failed', 'レート制限に達しました', true)
      }
      if (!res.ok) throw new Error(`${project.host} ${res.status}`)
      page = parseExturlusage(await res.json())
    } catch {
      // 途中まで取れているなら打ち切り扱いで返す。全部捨てるより手掛かりが残る
      if (hits.length) {
        truncated = true
        break
      }
      return emptyLinks(project, 'failed', '問い合わせできませんでした')
    }

    hits.push(...page.hits)
    cont = page.cont
    if (!cont) break
    if (i === MAX_REQUESTS_PER_PROJECT - 1) truncated = true
  }

  return { project, state: 'ok', ...groupHits(hits), truncated, rateLimited: false }
}

/**
 * 全プロジェクトを直列に照会する。
 * 並列にすると Wikimedia のレート制限に当たって半分以上が 429 になるため、
 * 速さではなく取りこぼさないことを優先する。
 */
export async function fetchWikimediaLinks(
  domain: string,
  budgetMs: number = WIKIMEDIA_BUDGET_MS,
): Promise<WikimediaResult> {
  const deadline = Date.now() + budgetMs
  const projects: ProjectLinks[] = []
  let rateLimited = false

  for (const project of WIKIMEDIA_PROJECTS) {
    if (rateLimited) {
      // 一度当たると尾を引くので、残りを叩いても 429 を増やすだけ
      projects.push(
        emptyLinks(project, 'skipped', 'レート制限に達したため照会していません', true),
      )
      continue
    }
    if (Date.now() >= deadline) {
      projects.push(emptyLinks(project, 'skipped', '時間の上限に達したため照会していません'))
      continue
    }

    const links = await fetchProjectLinks(project, domain, deadline)
    if (links.rateLimited) rateLimited = true
    projects.push(links)
  }

  return summarize(projects)
}
