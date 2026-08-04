/**
 * DNS に残る「まだ他サービスと繋がっている」痕跡の辞書。
 *
 * ドメイン所有権の確認トークンは、一度置くと役目を終えても消されないまま残りやすい。
 * しかしこれが残っているということは、そのサービス側でドメインがまだ有効な資産として
 * 登録されている可能性が高いということで、手放した先の第三者が同じトークンを再現できれば
 * 所有権を主張できてしまう。mitori が最も重視する検査。
 */
export interface TokenSignature {
  /** 表示名 */
  service: string
  /** TXT レコード値の先頭一致・部分一致パターン */
  pattern: RegExp
  /** 残っていた場合の危険度 */
  severity: 'critical' | 'high' | 'medium' | 'low'
  /** 解除の手がかり */
  hint?: string
}

export const TOKEN_SIGNATURES: TokenSignature[] = [
  {
    service: 'Google (Search Console / Workspace)',
    pattern: /^google-site-verification=/i,
    severity: 'high',
    hint: 'Search Console のプロパティ削除、Workspace のドメイン解除を行う',
  },
  {
    service: 'Microsoft 365 / Entra ID',
    pattern: /^(ms=|v=verifydomain\s+ms=)/i,
    severity: 'critical',
    hint: 'テナントからカスタムドメインを削除する。残すと第三者がテナント参加を試みうる',
  },
  {
    service: 'Slack',
    pattern: /^slack-domain-verification=/i,
    severity: 'critical',
    hint: 'ワークスペースのドメイン承認を解除する。メール自動参加設定に直結する',
  },
  {
    service: 'Atlassian',
    pattern: /^atlassian-domain-verification=/i,
    severity: 'critical',
    hint: 'Atlassian 組織のドメイン申請を取り下げる',
  },
  {
    service: 'Meta / Facebook',
    pattern: /^facebook-domain-verification=/i,
    severity: 'high',
  },
  {
    service: 'Meta Workplace',
    pattern: /^workplace-domain-verification=/i,
    severity: 'high',
  },
  {
    service: 'Apple',
    pattern: /^apple-domain-verification=/i,
    severity: 'high',
  },
  {
    service: 'Adobe',
    pattern: /^adobe-(idp|sign)-site-verification=/i,
    severity: 'high',
  },
  {
    service: 'Stripe',
    pattern: /^stripe-verification=/i,
    severity: 'critical',
    hint: '決済関連。ダッシュボードからドメイン登録を解除する',
  },
  {
    service: 'Zoom',
    pattern: /^zoom(-domain)?-verification=/i,
    severity: 'high',
  },
  {
    service: 'Dropbox',
    pattern: /^dropbox-domain-verification=/i,
    severity: 'high',
  },
  {
    service: 'DocuSign',
    pattern: /^docusign=/i,
    severity: 'critical',
    hint: '電子署名。ドメイン権限が残ると署名者の偽装余地になる',
  },
  {
    service: 'Zoho',
    pattern: /^zoho(-domain)?-verification=/i,
    severity: 'high',
  },
  {
    service: 'Notion',
    pattern: /^notion-domain-verification=/i,
    severity: 'medium',
  },
  {
    service: 'Canva',
    pattern: /^canva-site-verification=/i,
    severity: 'medium',
  },
  {
    service: 'Miro',
    pattern: /^miro-verification=/i,
    severity: 'medium',
  },
  {
    service: 'Loom',
    pattern: /^loom-(site|domain)-verification=/i,
    severity: 'medium',
  },
  {
    service: 'OpenAI',
    pattern: /^openai-domain-verification=/i,
    severity: 'high',
  },
  {
    service: 'Cisco Webex',
    pattern: /^(webexdomainverification|cisco-ci-domain-verification)/i,
    severity: 'high',
  },
  {
    service: 'Citrix',
    pattern: /^citrix-verification-code=/i,
    severity: 'high',
  },
  {
    service: 'MongoDB',
    pattern: /^mongodb-site-verification=/i,
    severity: 'medium',
  },
  {
    service: 'Twilio',
    pattern: /^twilio-domain-verification=/i,
    severity: 'high',
  },
  {
    service: 'HubSpot',
    pattern: /^hubspot-developer-verification=/i,
    severity: 'medium',
  },
  {
    service: 'Klaviyo',
    pattern: /^klaviyo-site-verification=/i,
    severity: 'medium',
  },
  {
    service: 'Brevo (Sendinblue)',
    pattern: /^(brevo|sendinblue)-code:/i,
    severity: 'medium',
  },
  {
    service: 'Postman',
    pattern: /^postman-domain-verification=/i,
    severity: 'medium',
  },
  {
    service: 'Pinterest',
    pattern: /^p:domain_verify=/i,
    severity: 'low',
  },
  {
    service: 'TikTok',
    pattern: /^tiktok-developers-site-verification=/i,
    severity: 'medium',
  },
  {
    service: 'Yandex',
    pattern: /^yandex-verification:/i,
    severity: 'medium',
  },
  {
    service: 'GlobalSign',
    pattern: /^_?globalsign-domain-verification=/i,
    severity: 'high',
    hint: '証明書発行に関わる。CA 側の登録を解除する',
  },
  {
    service: 'OneTrust',
    pattern: /^onetrust-domain-verification=/i,
    severity: 'medium',
  },
  {
    service: 'Smartsheet',
    pattern: /^smartsheet-domain-validation=/i,
    severity: 'medium',
  },
  {
    service: 'Detectify',
    pattern: /^detectify-verification=/i,
    severity: 'medium',
  },
  {
    service: 'Have I Been Pwned',
    pattern: /^have-i-been-pwned-verification=/i,
    severity: 'medium',
  },
  {
    service: 'Firebase',
    pattern: /^firebase=/i,
    severity: 'high',
  },
  {
    service: 'Segment',
    pattern: /^segment-site-verification=/i,
    severity: 'medium',
  },
  {
    service: 'Bugcrowd',
    pattern: /^bugcrowd-verification=/i,
    severity: 'medium',
  },
]

/** Microsoft 365 テナント連携の痕跡（TXT 以外の形で残るもの） */
export const MICROSOFT_HOSTS = [
  { host: 'autodiscover', type: 'CNAME', label: 'Exchange Online の自動検出' },
  { host: 'lyncdiscover', type: 'CNAME', label: 'Teams / Skype for Business' },
  { host: 'enterpriseregistration', type: 'CNAME', label: 'デバイス登録 (Entra ID)' },
  { host: 'enterpriseenrollment', type: 'CNAME', label: 'Intune 登録' },
  { host: 'msoid', type: 'CNAME', label: 'Microsoft アカウント連携' },
] as const

export const SRV_PROBES = [
  { name: '_autodiscover._tcp', label: 'Exchange 自動検出' },
  { name: '_sipfederationtls._tcp', label: 'Skype/Teams フェデレーション' },
  { name: '_sip._tls', label: 'SIP' },
  { name: '_submission._tcp', label: 'メール送信' },
  { name: '_imaps._tcp', label: 'IMAP over TLS' },
  { name: '_caldav._tcp', label: 'カレンダー' },
  { name: '_carddav._tcp', label: '連絡先' },
  { name: '_xmpp-client._tcp', label: 'XMPP' },
] as const

/** DKIM セレクタは公開情報から推測するしかないため、実運用で頻出のものを辞書化する */
export const DKIM_SELECTORS = [
  'default',
  'google',
  'selector1',
  'selector2',
  'k1',
  'k2',
  'mail',
  'dkim',
  's1',
  's2',
  'zoho',
  'sendgrid',
  'smtp',
  'mandrill',
  'everlytickey1',
  'mxvault',
  'pic',
] as const

/**
 * CT ログが引けなかった場合の補助。
 * 総当たりではなく「畳み残しが起きやすい場所」に絞る。
 */
export const COMMON_SUBDOMAINS = [
  'www',
  'mail',
  'webmail',
  'smtp',
  'imap',
  'pop',
  'blog',
  'shop',
  'api',
  'dev',
  'staging',
  'test',
  'old',
  'admin',
  'portal',
  'vpn',
  'remote',
  'cdn',
  'static',
  'img',
  'files',
  'docs',
  'wiki',
  'support',
  'status',
  'git',
  'ci',
  'ns1',
  'ns2',
] as const
