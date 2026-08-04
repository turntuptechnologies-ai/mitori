/** 検査結果の重大度。手放した瞬間に悪用できるものほど上位。 */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

/**
 * clear   … 痕跡なし。供養が進んでいる
 * action  … 痕跡が残っている。対処が必要
 * warn    … 対処済みだが確認が要る
 * unknown … 判定不能（API 未対応・取得失敗など）
 */
export type CheckStatus = 'clear' | 'action' | 'warn' | 'unknown'

/** チェックリストの Phase B〜E に対応 */
export type Phase = 'inventory' | 'detach' | 'cooldown' | 'release'

export const PHASE_LABEL: Record<Phase, string> = {
  inventory: '棚卸し',
  detach: '切り離し',
  cooldown: '冷却',
  release: '手放す',
}

export const PHASE_ORDER: Phase[] = ['inventory', 'detach', 'cooldown', 'release']

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: '致命的',
  high: '高',
  medium: '中',
  low: '低',
  info: '参考',
}

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

/**
 * 観測結果から作った、このドメイン固有の作業。手動チェックリストの項目にぶら下げる。
 *
 * チェックリストは「Microsoft 365 などのドメイン所有権を解除した」のような一般論でしか
 * 書けない。一方で検査のほうは、実際にどのサービスが紐付いているかを知っている。
 * 知っている側から具体名を流し込むことで、汎用の心得をそのドメインの作業に変える。
 */
export interface DerivedTask {
  /** 流し込み先の手動チェックリスト項目 id */
  target: string
  /** チェック状態の保存に使う id。同じものが観測され続ける限り変わらない */
  id: string
  text: string
}

export interface CheckResult {
  id: string
  phase: Phase
  title: string
  severity: Severity
  status: CheckStatus
  /** 進捗率の重み。severity から自動決定される */
  weight: number
  /** 一行の結論 */
  summary: string
  /** どうすればよいか */
  advice?: string
  /** 判定根拠の生データ */
  evidence?: string[]
  /** この観測から導いた具体的な作業 */
  tasks?: DerivedTask[]
}

export interface ScanReport {
  domain: string
  startedAt: string
  finishedAt: string
  results: CheckResult[]
  /** 供養進捗率（0-100）。判定できた項目のみを母数にする */
  score: number
  decidable: number
  notes: string[]
}

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 10,
  high: 6,
  medium: 3,
  low: 1,
  info: 0,
}

export function makeResult(
  r: Omit<CheckResult, 'weight'> & { weight?: number },
): CheckResult {
  return { ...r, weight: r.weight ?? SEVERITY_WEIGHT[r.severity] }
}
