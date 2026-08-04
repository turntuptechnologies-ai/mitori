import { describe, expect, it } from 'vitest'
import {
  buildExturlusageUrl,
  groupHits,
  parseExturlusage,
  summarize,
  type ExturlusageHit,
  type ProjectLinks,
  type WikimediaProject,
} from './wikimedia'

describe('buildExturlusageUrl', () => {
  it('匿名で CORS を通すための origin と、匿名上限の eulimit を付ける', () => {
    const url = buildExturlusageUrl('ja.wikipedia.org', 'example.com')
    // URLSearchParams は * を符号化しない。%2A に符号化されても解釈されることは確認済みだが、
    // 実際に飛ぶのはこの形
    expect(url).toContain('origin=*')
    expect(url).toContain('eulimit=500')
    expect(url).toContain('formatversion=2')
    expect(url.startsWith('https://ja.wikipedia.org/w/api.php?')).toBe(true)
  })

  it('サブドメインを取りこぼさないよう、ドメインをそのまま渡す', () => {
    // euquery はホスト名の前方一致。bare なら www. や archives. も拾うが、
    // www. を付けるとそのホストだけに絞られてしまう
    expect(buildExturlusageUrl('ja.wikipedia.org', 'nhk.or.jp')).toContain('euquery=nhk.or.jp')
  })

  it('継続トークンがあれば eucontinue として渡す', () => {
    expect(buildExturlusageUrl('ja.wikipedia.org', 'example.com', '958836')).toContain(
      'eucontinue=958836',
    )
  })

  it('継続トークンが無ければ eucontinue を付けない', () => {
    expect(buildExturlusageUrl('ja.wikipedia.org', 'example.com')).not.toContain('eucontinue')
  })
})

describe('parseExturlusage', () => {
  // ja.wikipedia.org の実応答をそのまま固定している
  const real = {
    batchcomplete: true,
    continue: { eucontinue: '21605', continue: '-||' },
    query: {
      exturlusage: [
        {
          ns: 4,
          title: 'Wikipedia:秀逸な画像の推薦/ファイル:Lake Towada from Ohanabe 2008.jpg',
          url: 'http://commons.wikimedia.org/wiki/User:Soica2001',
        },
        {
          ns: 2,
          title: '利用者:朝彦/memo',
          url: 'http://commons.wikimedia.org/wiki/File:Farm-Fresh_document_properties.png',
        },
        {
          ns: 14,
          title: 'Category:前橋市の画像提供依頼',
          url: 'http://commons.wikimedia.org/w/index.php?title=Special:UserLogin',
        },
      ],
    },
  }

  it('実応答から名前空間・ページ名・URL を取り出す', () => {
    const page = parseExturlusage(real)
    expect(page.hits).toHaveLength(3)
    expect(page.hits[0]).toEqual({
      ns: 4,
      title: 'Wikipedia:秀逸な画像の推薦/ファイル:Lake Towada from Ohanabe 2008.jpg',
      url: 'http://commons.wikimedia.org/wiki/User:Soica2001',
    })
  })

  it('続きがあれば継続トークンを返す', () => {
    expect(parseExturlusage(real).cont).toBe('21605')
  })

  it('続きが無ければ継続トークンは undefined', () => {
    expect(parseExturlusage({ query: { exturlusage: [] } }).cont).toBeUndefined()
  })

  it('参照が 0 件でも空として扱う', () => {
    expect(parseExturlusage({ batchcomplete: true }).hits).toEqual([])
    expect(parseExturlusage(null).hits).toEqual([])
  })

  it('ページ名か URL を欠く要素は落とす', () => {
    const page = parseExturlusage({
      query: { exturlusage: [{ ns: 0, title: 'あり', url: 'https://example.com/' }, { ns: 0 }] },
    })
    expect(page.hits).toHaveLength(1)
  })
})

describe('groupHits', () => {
  const hit = (ns: number, title: string, url: string): ExturlusageHit => ({ ns, title, url })

  it('本文（名前空間 0）とそれ以外を分ける', () => {
    // ノートや利用者ページからの言及は残っていても百科事典の権威を引き継がない
    const groups = groupHits([
      hit(0, '2025年日本国際博覧会', 'https://www.expo2025.or.jp/'),
      hit(2, '利用者:someone', 'https://www.expo2025.or.jp/'),
      hit(4, 'Wikipedia:井戸端', 'https://www.expo2025.or.jp/news/'),
    ])
    expect(groups.articles).toEqual(['2025年日本国際博覧会'])
    expect(groups.others).toEqual(['Wikipedia:井戸端', '利用者:someone'])
  })

  it('同じページが複数回現れても 1 件に畳む', () => {
    // API が返すのは (ページ, URL) の組なので、1 記事が何度も出てくる
    const groups = groupHits([
      hit(0, '同じ記事', 'https://example.com/a'),
      hit(0, '同じ記事', 'https://example.com/b'),
      hit(0, '同じ記事', 'https://example.com/a'),
    ])
    expect(groups.articles).toEqual(['同じ記事'])
    expect(groups.urls).toEqual(['https://example.com/a', 'https://example.com/b'])
  })

  it('参照が無ければすべて空', () => {
    expect(groupHits([])).toEqual({ articles: [], others: [], urls: [] })
  })
})

describe('summarize', () => {
  const project = (label: string): WikimediaProject => ({ host: `${label}.example.org`, label })

  const links = (label: string, over: Partial<ProjectLinks> = {}): ProjectLinks => ({
    project: project(label),
    state: 'ok',
    articles: [],
    others: [],
    urls: [],
    truncated: false,
    rateLimited: false,
    ...over,
  })

  it('プロジェクトを横断して本文とページ数を合計する', () => {
    const result = summarize([
      links('ja', { articles: ['A', 'B'], others: ['ノート:A'] }),
      links('en', { articles: ['C'] }),
    ])
    expect(result.articles).toBe(3)
    expect(result.pages).toBe(4)
  })

  it('参照が見つかったプロジェクトだけを found に入れる', () => {
    const result = summarize([links('ja', { articles: ['A'] }), links('en')])
    expect(result.found.map((p) => p.project.label)).toEqual(['ja'])
  })

  it('失敗したプロジェクトは集計から外し、名前を残す', () => {
    // 失敗を 0 件と混ぜると「参照が無い」と誤読される
    const result = summarize([
      links('ja', { articles: ['A'] }),
      links('en', { state: 'failed', reason: '問い合わせできませんでした' }),
    ])
    expect(result.articles).toBe(1)
    expect(result.queried).toBe(1)
    expect(result.failed).toEqual(['en'])
    expect(result.ok).toBe(true)
  })

  it('未照会のプロジェクトを失敗とは別に数える', () => {
    // 「レート制限で叩けなかった」と「叩いたが応答が無かった」は別の話
    const result = summarize([
      links('ja', { articles: ['A'] }),
      links('en', { state: 'failed', reason: 'レート制限に達しました', rateLimited: true }),
      links('zh', { state: 'skipped', reason: '時間の上限に達したため照会していません' }),
    ])
    expect(result.failed).toEqual(['en'])
    expect(result.skipped).toEqual(['zh'])
    expect(result.queried).toBe(1)
  })

  it('照会できたプロジェクトが 1 つも無いときだけ ok を false にする', () => {
    expect(
      summarize([links('ja', { state: 'failed' }), links('en', { state: 'skipped' })]).ok,
    ).toBe(false)
    expect(summarize([links('ja'), links('en', { state: 'failed' })]).ok).toBe(true)
  })

  it('1 つでも打ち切られていれば打ち切りとして扱う', () => {
    expect(summarize([links('ja', { truncated: true }), links('en')]).truncated).toBe(true)
    expect(summarize([links('ja'), links('en')]).truncated).toBe(false)
  })
})
