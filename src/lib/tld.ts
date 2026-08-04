/**
 * ドメイン名の種別から「手放した後に誰が取得しうるか」を判定する。
 *
 * ドロップキャッチの危険度は、痕跡の量と同じくらいドメイン名の種別で決まる。
 * 属性型 JP（lg.jp / ac.jp / go.jp など）は登録資格の審査があるため、
 * 無関係の第三者は制度上取得できない。一方、汎用 JP は日本国内に住所があれば
 * 誰でもいくつでも登録でき、gTLD は全世界の誰でも先着順で取得できる。
 *
 * 実際に国内で転用が報告されている事例は、調べた限りすべて汎用 JP か gTLD だった。
 * 同じ組織の属性型ドメインは無事なまま、キャンペーン用に取った独自ドメインだけが落ちている。
 *
 * 出典:
 * - 種類と対象 https://jprs.jp/about/jp-dom/spec/
 * - JPドメイン名のライフサイクル https://jprs.jp/about/dom-rule/lifecycle/
 * - 属性型・地域型JPドメイン名登録等に関する規則 https://jprs.jp/doc/rule/rule.html
 * - .com Registry Agreement Appendix 7 / ICANN ERRP
 */

export type DomainKind =
  | 'attribute-jp'
  | 'prefecture-jp'
  | 'general-jp'
  | 'gtld'
  | 'other-cctld'

/**
 * 手放した後、どこまで開かれているか。
 * closed … 制度上、誰も新規登録できない
 * screened … 登録資格の審査を通る組織だけが取得できる
 * domestic … 日本国内に住所があれば誰でも取得できる
 * global … 全世界の誰でも先着順で取得できる
 * unclear … 制度が特定できない
 */
export type Exposure = 'closed' | 'screened' | 'domestic' | 'global' | 'unclear'

/** 属性型 JP の第 2 レベルラベルと、その登録資格 */
export const ATTRIBUTE_LABELS: Record<string, string> = {
  co: '日本国内で登記されている会社等',
  or: '財団法人・社団法人・医療法人・NPO 法人等',
  ne: '日本国内のネットワークサービス提供者',
  gr: '複数の個人または法人で構成される任意団体',
  ac: '高等教育機関・学校法人等',
  ed: '初等中等教育機関・18 歳未満を対象とする教育機関',
  go: '日本の政府機関・各省庁所管の研究所・独立行政法人等',
  lg: '地方公共団体、およびそれらが行う行政サービス',
}

/** 都道府県型 JP と地域型 JP の第 2 レベルに現れる 47 都道府県 */
const PREFECTURES = new Set([
  'hokkaido', 'aomori', 'iwate', 'miyagi', 'akita', 'yamagata', 'fukushima',
  'ibaraki', 'tochigi', 'gunma', 'saitama', 'chiba', 'tokyo', 'kanagawa',
  'niigata', 'toyama', 'ishikawa', 'fukui', 'yamanashi', 'nagano', 'gifu',
  'shizuoka', 'aichi', 'mie', 'shiga', 'kyoto', 'osaka', 'hyogo', 'nara',
  'wakayama', 'tottori', 'shimane', 'okayama', 'hiroshima', 'yamaguchi',
  'tokushima', 'kagawa', 'ehime', 'kochi', 'fukuoka', 'saga', 'nagasaki',
  'kumamoto', 'oita', 'miyazaki', 'kagoshima', 'okinawa',
])

export interface KindProfile {
  kind: DomainKind
  label: string
  exposure: Exposure
  /** 廃止してから第三者が登録できるようになるまで */
  freeze: string
  /** 誰が取得しうるか */
  whoCanTake: string
  /** 種別特有の但し書き */
  notes: string[]
}

/** 属性型 JP なら第 2 レベルのラベルを返す */
export function attributeLabelOf(domain: string): string | null {
  const labels = domain.split('.')
  if (labels.length < 3 || labels[labels.length - 1] !== 'jp') return null
  const second = labels[labels.length - 2]!
  return second in ATTRIBUTE_LABELS ? second : null
}

export function classify(domain: string): DomainKind {
  const labels = domain.split('.')
  const tld = labels[labels.length - 1]!

  if (tld !== 'jp') {
    // 2 文字は ISO 3166 の国コード。国ごとに制度が違うので判定しない
    return tld.length === 2 ? 'other-cctld' : 'gtld'
  }
  if (labels.length < 2) return 'other-cctld'
  if (attributeLabelOf(domain)) return 'attribute-jp'
  if (labels.length >= 3 && PREFECTURES.has(labels[labels.length - 2]!)) {
    return 'prefecture-jp'
  }
  return 'general-jp'
}

export function profileOf(domain: string): KindProfile {
  const kind = classify(domain)

  if (kind === 'attribute-jp') {
    const attr = attributeLabelOf(domain)!
    return {
      kind,
      label: `属性型 JP ドメイン名（${attr}.jp）`,
      exposure: 'screened',
      freeze: '廃止の翌月から 6 ヶ月間は誰も登録できません',
      whoCanTake: `${ATTRIBUTE_LABELS[attr]}だけが登録できます`,
      notes: [
        '登録時に資格の確認があるため、無関係の第三者がこの名前を取得することは制度上できません',
        '凍結期間が汎用 JP の 6 倍あり、手放した後に気づいても間に合う余地があります',
        // 手放さないという最強の手が、組織が消えると使えなくなる
        '組織が登録資格を失ったときは廃止の届け出が義務です（登録規則 第 26 条第 2 項）。' +
          '解散・廃校の場合は「保持し続ける」を選べません',
        '合併・組織名変更・事業譲渡であれば、承継した組織が 1 組織 1 ドメイン名の制限緩和により継続保持できます',
      ],
    }
  }

  if (kind === 'prefecture-jp') {
    return {
      kind,
      label: '都道府県型 JP ドメイン名、または地域型 JP ドメイン名',
      // 文字列だけではどちらの制度か決まらない。断定せず両方を示す
      exposure: 'unclear',
      freeze: '都道府県型なら 1 ヶ月、地域型なら 6 ヶ月',
      whoCanTake: 'どちらの制度かによって変わります',
      notes: [
        '都道府県型（2012 年 11 月開始）なら、日本国内に住所があれば誰でも登録できます',
        '地域型は 2012 年 3 月 31 日で新規登録の受け付けが終了しているため、' +
          '地域型であれば廃止後に第三者が取得することはできません',
        '名前だけではどちらの制度で登録されたものか判別できません。指定事業者に確認してください',
        '市区町村名と一致するラベルは JPRS の予約ドメイン名リストに載っており、当該市区町村しか登録できません',
      ],
    }
  }

  if (kind === 'general-jp') {
    return {
      kind,
      label: '汎用 JP ドメイン名',
      exposure: 'domestic',
      freeze: '廃止の翌月から 1 ヶ月間の凍結を経て、誰でも登録できるようになります',
      whoCanTake: '日本国内に住所を持つ個人・団体・組織であれば誰でも、いくつでも登録できます',
      notes: [
        '登録資格の審査がありません。国内で転用が報告されている事例は、ほぼすべてこの種別です',
        'キャンペーンやイベントのために取得した独自ドメインの多くがここに該当します',
        '公的機関向けのガイドラインで保持期間に年数が明示されているのは go ドメインだけで、' +
          'この種別には「一定期間」としか書かれていません',
      ],
    }
  }

  if (kind === 'gtld') {
    return {
      kind,
      label: 'gTLD（分野別トップレベルドメイン）',
      exposure: 'global',
      freeze: '有効期限から最短 35 日、最長でも 80 日ほどで誰でも登録できるようになります',
      whoCanTake: '全世界の誰でも、先着順で登録できます',
      notes: [
        '内訳は Auto-Renew Grace Period が最大 45 日、Redemption Grace Period が 30 日、' +
          'Pending Delete が 5 日です（.com の場合）',
        '解放される瞬間が正確に予測できるため、専門のドロップキャッチ業者が待ち構えています',
        '削除の前に最低 8 日間は名前解決が止まります（ICANN ERRP）。' +
          '名前解決が止まったら、削除の直前だと考えてください',
      ],
    }
  }

  return {
    kind,
    label: '国別コードトップレベルドメイン（.jp 以外）',
    exposure: 'unclear',
    freeze: '判定できません',
    whoCanTake: '判定できません',
    notes: ['国ごとにレジストリの規則が異なるため、mitori では失効後の扱いを判定していません'],
  }
}
