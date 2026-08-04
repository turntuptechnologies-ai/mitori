/**
 * 機械的に判定できない項目。
 *
 * mitori は DNS から見えるものしか判定できない。しかし実務上の危険の多くは
 * 「どのサービスにこのドメインのメールアドレスを登録したか」「配布済みの印刷物」
 * のように、外部からは観測できないところにある。
 * 自動判定できる項目だけを見せると「full clear なので手放してよい」と誤読されるため、
 * 判定不能な項目こそ明示的に並べる。
 */
export interface ManualItem {
  id: string
  phase: 'judge' | 'inventory' | 'detach' | 'cooldown' | 'release' | 'after'
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

export const MANUAL_ITEMS: ManualItem[] = [
  {
    id: 'judge-keep',
    phase: 'judge',
    text: 'そもそも手放す必要があるか再検討した',
    note: '年間数千円で持ち続けられるなら、それが最も安全で最も安いドメイン対策になる',
  },
  {
    id: 'judge-successor',
    phase: 'judge',
    text: '名義人がいなくなる場合の引き継ぎ先を決めた',
    note: '放棄より譲渡のほうが常に安全',
  },
  {
    id: 'judge-multiyear',
    phase: 'judge',
    text: '複数年分の前払いで延命できないか確認した',
  },

  {
    id: 'inv-accounts',
    phase: 'inventory',
    text: 'このドメインのメールアドレスを、どのサービスに登録したか洗い出した',
    note: '最大の危険。第三者がパスワードリセットでアカウントを奪える',
  },
  {
    id: 'inv-mailflow',
    phase: 'inventory',
    text: '実際に届いているメールの内容と送信元を確認した',
  },
  {
    id: 'inv-backlink',
    phase: 'inventory',
    text: 'Search Console / Bing Webmaster で外部リンクを取得した',
  },
  {
    id: 'inv-offline',
    phase: 'inventory',
    text: '印刷物・看板・QR コード・名刺の参照を台帳化した',
    note: '回収不能なものは「消せない参照」として、冷却期間の長さを決める材料になる',
  },

  {
    id: 'det-recovery',
    phase: 'detach',
    text: '各サービスの登録メールと二要素認証のリカバリ先を新しいアドレスへ変更した',
  },
  {
    id: 'det-tenant',
    phase: 'detach',
    text: 'Workspace / Microsoft 365 / Slack などのドメイン所有権を解除した',
    note: '「同じドメインのメールなら自動参加」設定は特に危険',
  },
  {
    id: 'det-oauth',
    phase: 'detach',
    text: 'OAuth の redirect_uri、SAML/OIDC の issuer を廃止した',
  },
  {
    id: 'det-assets',
    phase: 'detach',
    text: '外部サイトから参照されている JS / CSS / 画像を移設した',
    note: '生きている script src は、新所有者に任意コード実行を渡すことになる',
  },
  {
    id: 'det-package',
    phase: 'detach',
    text: 'パッケージのメタデータを更新した（npm / PyPI / Go module / Maven）',
    note: 'Go の module path や Maven の groupId はドメインそのもの。サプライチェーン攻撃の経路になる',
  },
  {
    id: 'det-spf-include',
    phase: 'detach',
    text: '他システムの SPF include: と CSP allowlist から外した',
  },
  {
    id: 'det-legal',
    phase: 'detach',
    text: '契約書・登記・公的届出に記載した連絡先を更新した',
  },
  {
    id: 'det-selflink',
    phase: 'detach',
    text: '自分が管理する全サイト・SNS プロフィール・メール署名からリンクを削除した',
  },
  {
    id: 'det-request',
    phase: 'detach',
    text: '依頼可能な第三者に、リンクの削除・書き換えを依頼した',
  },

  {
    id: 'cool-content',
    phase: 'cooldown',
    text: 'コンテンツを削除し、案内 1 枚に縮退した',
  },
  {
    id: 'cool-noindex',
    phase: 'cooldown',
    text: 'noindex と robots.txt で検索インデックスから外した',
    note: 'ブラウザからは CORS で確認できないため、手動で確認する',
  },
  {
    id: 'cool-deadline',
    phase: 'cooldown',
    text: '案内ページに廃止予定日を明示した',
  },
  {
    id: 'cool-degrade',
    phase: 'cooldown',
    text: 'リダイレクトを段階的に弱めた（自動 301 → 手動クリック → 404）',
    note: '301 を張り続けると「壊れていない」ので参照側が更新しない。あえて不便にすることが供養の本体',
  },

  {
    id: 'rel-autorenew',
    phase: 'release',
    text: '自動更新の設定を意図した状態にした',
    note: 'うっかり更新も、うっかり失効も防ぐ',
  },
  {
    id: 'rel-notify',
    phase: 'release',
    text: '手放すことを、参照が残る相手に通知した',
  },
  {
    id: 'rel-record',
    phase: 'release',
    text: '廃止した事実を、このドメイン以外の場所に記録した',
    note: '自ドメインに書くと、記録が供養対象と一緒に消える',
  },

  {
    id: 'after-watch',
    phase: 'after',
    text: '誰が取得したかを定期的に確認する仕組みを作った',
  },
  {
    id: 'after-cleanup',
    phase: 'after',
    text: '自分の側に残った設定・ブックマーク・ドキュメントを掃除した',
  },
]
