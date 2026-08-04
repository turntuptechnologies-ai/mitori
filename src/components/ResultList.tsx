import { useState } from 'react'
import { SEVERITY_LABEL, type CheckResult, type CheckStatus } from '../lib/types'

const STATUS_STYLE: Record<CheckStatus, { label: string; badge: string; bar: string }> = {
  action: {
    label: '要対応',
    badge: 'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300',
    bar: 'bg-rose-500',
  },
  warn: {
    label: '確認',
    badge: 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300',
    bar: 'bg-amber-500',
  },
  clear: {
    label: '痕跡なし',
    badge: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300',
    bar: 'bg-emerald-500',
  },
  unknown: {
    label: '判定不能',
    badge: 'bg-stone-200 text-stone-700 dark:bg-stone-800 dark:text-stone-400',
    bar: 'bg-stone-400',
  },
}

function ResultCard({ result }: { result: CheckResult }) {
  const [open, setOpen] = useState(result.status === 'action')
  const style = STATUS_STYLE[result.status]
  const hasDetail = Boolean(result.advice) || Boolean(result.evidence?.length)

  return (
    <li className="mitori-fade overflow-hidden rounded-lg border border-stone-200 bg-white dark:border-stone-800 dark:bg-stone-900">
      <div className="flex">
        <div className={`w-1 shrink-0 ${style.bar}`} aria-hidden />
        <div className="min-w-0 flex-1 p-4">
          <div className="flex flex-wrap items-center gap-2">
            <span className={`rounded px-2 py-0.5 text-xs font-semibold ${style.badge}`}>
              {style.label}
            </span>
            <h3 className="font-semibold text-stone-900 dark:text-stone-100">{result.title}</h3>
            <span className="text-xs text-stone-500 dark:text-stone-500">
              重大度 {SEVERITY_LABEL[result.severity]}
            </span>
          </div>

          <p className="mt-2 text-sm leading-relaxed text-stone-700 dark:text-stone-300">
            {result.summary}
          </p>

          {hasDetail && (
            <button
              type="button"
              onClick={() => setOpen((v) => !v)}
              className="mt-2 text-xs text-stone-500 underline underline-offset-2 hover:text-stone-800 dark:hover:text-stone-200"
            >
              {open ? '詳細を閉じる' : '詳細と根拠を見る'}
            </button>
          )}

          {open && result.advice && (
            <p className="mt-3 rounded border-l-2 border-stone-300 bg-stone-50 py-2 pl-3 text-sm whitespace-pre-wrap text-stone-700 dark:border-stone-700 dark:bg-stone-950 dark:text-stone-300">
              {result.advice}
            </p>
          )}

          {open && result.evidence && result.evidence.length > 0 && (
            <ul className="mt-3 space-y-1">
              {result.evidence.map((line) => (
                <li
                  key={line}
                  className="overflow-x-auto rounded bg-stone-100 px-2 py-1 font-mono text-xs break-all text-stone-700 dark:bg-stone-950 dark:text-stone-400"
                >
                  {line}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </li>
  )
}

const GROUP_ORDER: CheckStatus[] = ['action', 'warn', 'unknown', 'clear']

const GROUP_TITLE: Record<CheckStatus, string> = {
  action: '対応が必要',
  warn: '確認が必要',
  unknown: '判定できなかった',
  clear: '痕跡が残っていない',
}

export function ResultList({ results }: { results: CheckResult[] }) {
  return (
    <div className="space-y-8">
      {GROUP_ORDER.map((status) => {
        const items = results.filter((r) => r.status === status)
        if (!items.length) return null
        return (
          <section key={status}>
            <h2 className="mb-3 text-sm font-semibold tracking-wide text-stone-500 dark:text-stone-400">
              {GROUP_TITLE[status]}（{items.length}）
            </h2>
            <ul className="space-y-2">
              {items.map((r) => (
                <ResultCard key={r.id} result={r} />
              ))}
            </ul>
          </section>
        )
      })}
    </div>
  )
}
