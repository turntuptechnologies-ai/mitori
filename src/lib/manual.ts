/**
 * 機械的に判定できない項目。
 *
 * mitori は DNS から見えるものしか判定できない。しかし実務上の危険の多くは
 * 「どのサービスにこのドメインのメールアドレスを登録したか」「配布済みの印刷物」
 * のように、外部からは観測できないところにある。
 * 自動判定できる項目だけを見せると「full clear なので手放してよい」と誤読されるため、
 * 判定不能な項目こそ明示的に並べる。
 */
import type { CheckResult, DerivedTask } from './types'

/**
 * 何を対象にした作業か。フェーズ（いつやるか）とは独立した軸で、
 * 「これはメールの話か、Web の話か」を一覧から拾えるようにするためのもの。
 */
export type ManualCategory = 'mail' | 'web' | 'service' | 'domain' | 'offline' | 'record'

export interface ManualItem {
  id: string
  phase: 'judge' | 'inventory' | 'detach' | 'cooldown' | 'release' | 'after'
  category: ManualCategory
  text: string
  /** なぜ危険か */
  note?: string
}

export const MANUAL_PHASE_LABEL: Record<ManualItem['phase'], string> = {
  judge: 'A. 判断',
  inventory: 'B. 棚卸し',
  detach: 'C. 切り離し',
  cooldown: 'D. 冷却',
  release: 'E. 手放す',
  after: 'F. 事後監視',
}

export const MANUAL_CATEGORY_LABEL: Record<ManualCategory, string> = {
  mail: 'メール',
  web: 'ウェブ',
  service: '外部サービス',
  domain: 'ドメイン登録',
  offline: '紙・現物',
  record: '記録・連絡',
}

export const MANUAL_CATEGORY_ORDER: ManualCategory[] = [
  'mail',
  'web',
  'service',
  'domain',
  'offline',
  'record',
]

// `as const satisfies` で id を文字列リテラルのまま保つ。これが ManualItemId の素になり、
// 存在しない項目へタスクを流し込む書き間違いを型で弾く。
// 表示側は note の有無を気にせず扱いたいので、公開するのは下の広げた型のほう
const ITEMS = [
  {
    id: 'judge-keep',
    phase: 'judge',
    category: 'domain',
    text: 'そもそも手放す必要があるか再検討した',
    note: '年間数千円で持ち続けられるなら、それが最も安全で最も安いドメイン対策になる',
  },
  {
    id: 'judge-successor',
    phase: 'judge',
    category: 'domain',
    text: '名義人がいなくなる場合の引き継ぎ先を決めた',
    note: '放棄より譲渡のほうが常に安全',
  },
  {
    id: 'judge-multiyear',
    phase: 'judge',
    category: 'domain',
    text: '複数年分の前払いで延命できないか確認した',
  },

  {
    id: 'inv-accounts',
    phase: 'inventory',
    category: 'mail',
    text: 'このドメインのメールアドレスを、どのサービスに登録したか洗い出した',
    note: '最大の危険。第三者がパスワードリセットでアカウントを奪える',
  },
  {
    id: 'inv-mailflow',
    phase: 'inventory',
    category: 'mail',
    text: '実際に届いているメールの内容と送信元を確認した',
  },
  {
    id: 'inv-backlink',
    phase: 'inventory',
    category: 'web',
    text: 'Search Console / Bing Webmaster で外部リンクを取得した',
  },
  {
    id: 'inv-offline',
    phase: 'inventory',
    category: 'offline',
    text: '印刷物・看板・QR コード・名刺の参照を台帳化した',
    note: '回収不能なものは「消せない参照」として、冷却期間の長さを決める材料になる',
  },

  {
    id: 'det-recovery',
    phase: 'detach',
    category: 'mail',
    text: '各サービスの登録メールと二要素認証のリカバリ先を新しいアドレスへ変更した',
  },
  {
    id: 'det-tenant',
    phase: 'detach',
    category: 'service',
    text: 'Workspace / Microsoft 365 / Slack などのドメイン所有権を解除した',
    note: '「同じドメインのメールなら自動参加」設定は特に危険',
  },
  {
    id: 'det-oauth',
    phase: 'detach',
    category: 'service',
    text: 'OAuth の redirect_uri、SAML/OIDC の issuer を廃止した',
  },
  {
    id: 'det-assets',
    phase: 'detach',
    category: 'web',
    text: '外部サイトから参照されている JS / CSS / 画像を移設した',
    note: '生きている script src は、新所有者に任意コード実行を渡すことになる',
  },
  {
    id: 'det-package',
    phase: 'detach',
    category: 'service',
    text: 'パッケージのメタデータを更新した（npm / PyPI / Go module / Maven）',
    note: 'Go の module path や Maven の groupId はドメインそのもの。サプライチェーン攻撃の経路になる',
  },
  {
    id: 'det-spf-include',
    phase: 'detach',
    category: 'mail',
    text: '他システムの SPF include: と CSP allowlist から外した',
  },
  {
    id: 'det-legal',
    phase: 'detach',
    category: 'offline',
    text: '契約書・登記・公的届出に記載した連絡先を更新した',
  },
  {
    id: 'det-selflink',
    phase: 'detach',
    category: 'web',
    text: '自分が管理する全サイト・SNS プロフィール・メール署名からリンクを削除した',
  },
  {
    id: 'det-request',
    phase: 'detach',
    category: 'web',
    text: '依頼可能な第三者に、リンクの削除・書き換えを依頼した',
  },

  {
    id: 'cool-content',
    phase: 'cooldown',
    category: 'web',
    text: 'コンテンツを削除し、案内 1 枚に縮退した',
  },
  {
    id: 'cool-noindex',
    phase: 'cooldown',
    category: 'web',
    text: 'noindex と robots.txt で検索インデックスから外した',
    note: 'ブラウザからは CORS で確認できないため、手動で確認する',
  },
  {
    id: 'cool-deadline',
    phase: 'cooldown',
    category: 'web',
    text: '案内ページに廃止予定日を明示した',
  },
  {
    id: 'cool-degrade',
    phase: 'cooldown',
    category: 'web',
    text: 'リダイレクトを段階的に弱めた（自動 301 → 手動クリック → 404）',
    note: '301 を張り続けると「壊れていない」ので参照側が更新しない。あえて不便にすることが供養の本体',
  },

  {
    id: 'rel-autorenew',
    phase: 'release',
    category: 'domain',
    text: '自動更新の設定を意図した状態にした',
    note: 'うっかり更新も、うっかり失効も防ぐ',
  },
  {
    id: 'rel-notify',
    phase: 'release',
    category: 'record',
    text: '手放すことを、参照が残る相手に通知した',
  },
  {
    id: 'rel-record',
    phase: 'release',
    category: 'record',
    text: '廃止した事実を、このドメイン以外の場所に記録した',
    note: '自ドメインに書くと、記録が供養対象と一緒に消える',
  },

  {
    id: 'after-watch',
    phase: 'after',
    category: 'record',
    text: '誰が取得したかを定期的に確認する仕組みを作った',
  },
  {
    id: 'after-cleanup',
    phase: 'after',
    category: 'record',
    text: '自分の側に残った設定・ブックマーク・ドキュメントを掃除した',
  },
] as const satisfies readonly ManualItem[]

export const MANUAL_ITEMS: readonly ManualItem[] = ITEMS

export type ManualItemId = (typeof ITEMS)[number]['id']

/**
 * 観測結果から具体タスクを作る。
 *
 * `key` には件数のような変動する値ではなく、観測対象そのもの（サービス名・ホスト名）を渡す。
 * ここが変わると id が変わり、利用者がチェック済みにした状態が失われる。
 * 逆に文言はいくら変わってもよい。
 */
export function makeTask(target: ManualItemId, key: string, text: string): DerivedTask {
  return { target, id: `${target}:${key.trim().toLowerCase().replace(/\s+/g, '-')}`, text }
}

const KNOWN_ITEMS = new Set<string>(MANUAL_ITEMS.map((i) => i.id))

/**
 * 検査結果から、チェックリスト項目ごとの具体タスクを集める。
 *
 * 同じ相手を複数の検査が指すことがある（Microsoft 365 は所有権トークンと
 * グループウェア連携の両方から出る）ため、id で重複を落とす。
 */
export function collectTasks(results: CheckResult[]): Map<string, DerivedTask[]> {
  const byTarget = new Map<string, DerivedTask[]>()

  for (const result of results) {
    for (const task of result.tasks ?? []) {
      // 存在しない項目に紐づいたタスクは表示先が無いので捨てる
      if (!KNOWN_ITEMS.has(task.target)) continue
      const list = byTarget.get(task.target) ?? []
      if (!list.some((t) => t.id === task.id)) list.push(task)
      byTarget.set(task.target, list)
    }
  }

  return byTarget
}
