import type { ScanReport } from './types'
import { SEVERITY_LABEL } from './types'
import { MANUAL_ITEMS, MANUAL_PHASE_LABEL, type ManualItem } from './manual'

const STATUS_MARK: Record<string, string> = {
  clear: '✓',
  action: '要対応',
  warn: '△',
  unknown: '判定不能',
}

/**
 * 供養の記録を Markdown で書き出す。
 *
 * チェックリストの「廃止した事実を、このドメイン以外の場所に記録した」に対応する。
 * 記録が供養対象のドメイン上にしか無ければ、ドメインと一緒に消えてしまう。
 */
export function toMarkdown(report: ScanReport, checked: Set<string>): string {
  const lines: string[] = []
  lines.push(`# ドメイン看取り記録: ${report.domain}`)
  lines.push('')
  lines.push(`- 検査日時: ${report.finishedAt}`)
  lines.push(`- 自動判定の進捗: ${report.score}%（判定できた項目 ${report.decidable} 件）`)
  lines.push('')

  const action = report.results.filter((r) => r.status === 'action')
  const warn = report.results.filter((r) => r.status === 'warn')
  const clear = report.results.filter((r) => r.status === 'clear')
  const unknown = report.results.filter((r) => r.status === 'unknown')

  const section = (title: string, items: typeof report.results) => {
    if (!items.length) return
    lines.push(`## ${title}`)
    lines.push('')
    for (const r of items) {
      lines.push(`### ${STATUS_MARK[r.status]} ${r.title}（重大度: ${SEVERITY_LABEL[r.severity]}）`)
      lines.push('')
      lines.push(r.summary)
      if (r.advice) {
        lines.push('')
        lines.push(`> ${r.advice.replace(/\n/g, '\n> ')}`)
      }
      if (r.evidence?.length) {
        lines.push('')
        for (const e of r.evidence) lines.push(`- \`${e}\``)
      }
      lines.push('')
    }
  }

  section('対応が必要な項目', action)
  section('確認が必要な項目', warn)
  section('判定できなかった項目', unknown)
  section('痕跡が残っていない項目', clear)

  lines.push('## 手動確認項目')
  lines.push('')
  lines.push('DNS からは観測できないため、mitori では判定できない項目。')
  lines.push('')

  const byPhase = new Map<ManualItem['phase'], ManualItem[]>()
  for (const item of MANUAL_ITEMS) {
    const list = byPhase.get(item.phase) ?? []
    list.push(item)
    byPhase.set(item.phase, list)
  }
  for (const [phase, items] of byPhase) {
    lines.push(`### ${MANUAL_PHASE_LABEL[phase]}`)
    lines.push('')
    for (const item of items) {
      lines.push(`- [${checked.has(item.id) ? 'x' : ' '}] ${item.text}`)
    }
    lines.push('')
  }

  if (report.notes.length) {
    lines.push('## 検査上の注記')
    lines.push('')
    for (const n of report.notes) lines.push(`- ${n}`)
    lines.push('')
  }

  lines.push('---')
  lines.push('')
  lines.push(
    'mitori (看取り) で生成 — 自動判定は DNS / CT ログ / RDAP / Wikimedia から観測できる範囲に限られます。',
  )
  return lines.join('\n')
}

export function download(filename: string, content: string): void {
  const blob = new Blob([content], { type: 'text/markdown;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}
