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
