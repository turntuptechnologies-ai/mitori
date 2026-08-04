import { useCallback, useEffect, useMemo, useState } from 'react'
import { ManualChecklist } from './components/ManualChecklist'
import { ResultList } from './components/ResultList'
import { ScoreRing } from './components/ScoreRing'
import { normalizeDomain, runScan, type ScanProgress } from './lib/scan'
import { download, toMarkdown } from './lib/report'
import type { CheckResult, ScanReport } from './lib/types'

const STORAGE_PREFIX = 'mitori:manual:'

function loadChecked(domain: string): Set<string> {
  try {
    const raw = localStorage.getItem(STORAGE_PREFIX + domain)
    return new Set<string>(raw ? (JSON.parse(raw) as string[]) : [])
  } catch {
    return new Set()
  }
}

export default function App() {
  const [input, setInput] = useState('')
  const [domain, setDomain] = useState<string | null>(null)
  const [scanning, setScanning] = useState(false)
  const [progress, setProgress] = useState<ScanProgress | null>(null)
  const [partial, setPartial] = useState<CheckResult[]>([])
  const [report, setReport] = useState<ScanReport | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [checked, setChecked] = useState<Set<string>>(new Set())

  useEffect(() => {
    if (domain) setChecked(loadChecked(domain))
  }, [domain])

  const toggle = useCallback(
    (id: string) => {
      setChecked((prev) => {
        const next = new Set(prev)
        if (next.has(id)) next.delete(id)
        else next.add(id)
        if (domain) {
          try {
            localStorage.setItem(STORAGE_PREFIX + domain, JSON.stringify([...next]))
          } catch {
            // localStorage が使えない環境では永続化を諦める
          }
        }
        return next
      })
    },
    [domain],
  )

  const start = useCallback(async () => {
    const normalized = normalizeDomain(input)
    if (!normalized) {
      setError('ドメイン名として解釈できませんでした')
      return
    }
    setError(null)
    setDomain(normalized)
    setReport(null)
    setPartial([])
    setScanning(true)
    try {
      const result = await runScan(
        normalized,
        (r) => setPartial((prev) => [...prev, r]),
        (p) => setProgress(p),
      )
      setReport(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : '検査に失敗しました')
    } finally {
      setScanning(false)
      setProgress(null)
    }
  }, [input])

  const shown = report?.results ?? partial
  const percent = progress ? Math.round((progress.completed / progress.total) * 100) : 0

  const exportMarkdown = useMemo(
    () => () => {
      if (!report) return
      download(`mitori-${report.domain}.md`, toMarkdown(report, checked))
    },
    [report, checked],
  )

  return (
    <div className="mx-auto max-w-3xl px-4 py-10 sm:px-6 sm:py-14">
      <header>
        <h1 className="text-3xl font-semibold tracking-tight text-stone-900 dark:text-stone-100">
          mitori<span className="ml-2 text-lg font-normal text-stone-500">看取り</span>
        </h1>
        <p className="mt-3 text-sm leading-relaxed text-stone-600 dark:text-stone-400">
          手放そうとしているドメインに、まだ何が繋がっているかを調べます。
          <br />
          DNS・証明書透明性ログ・RDAP だけを使うので、検査はすべてブラウザの中で完結します。
        </p>
      </header>

      <form
        className="mt-8"
        onSubmit={(e) => {
          e.preventDefault()
          if (!scanning) void start()
        }}
      >
        <div className="flex flex-col gap-2 sm:flex-row">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="example.com"
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
            className="min-w-0 flex-1 rounded-lg border border-stone-300 bg-white px-3.5 py-2.5 font-mono text-sm text-stone-900 outline-none placeholder:text-stone-400 focus:border-stone-500 dark:border-stone-700 dark:bg-stone-900 dark:text-stone-100"
          />
          <button
            type="submit"
            disabled={scanning}
            className="rounded-lg bg-stone-800 px-6 py-2.5 text-sm font-semibold text-stone-50 transition-colors hover:bg-stone-700 disabled:opacity-50 dark:bg-stone-200 dark:text-stone-900 dark:hover:bg-stone-100"
          >
            {scanning ? '検査中…' : '看取る'}
          </button>
        </div>
        {error && <p className="mt-2 text-sm text-rose-700 dark:text-rose-400">{error}</p>}
      </form>

      {scanning && progress && (
        <div className="mt-6">
          <div className="h-1 overflow-hidden rounded-full bg-stone-200 dark:bg-stone-800">
            <div
              className="h-full bg-stone-700 transition-[width] duration-300 dark:bg-stone-300"
              style={{ width: `${percent}%` }}
            />
          </div>
          <p className="mt-2 text-xs text-stone-500">
            {progress.completed} / {progress.total} — {progress.current}
          </p>
        </div>
      )}

      {report && (
        <div className="mt-10 rounded-lg border border-stone-200 bg-white p-5 dark:border-stone-800 dark:bg-stone-900">
          <ScoreRing score={report.score} decidable={report.decidable} />
          <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-stone-200 pt-4 dark:border-stone-800">
            <button
              type="button"
              onClick={exportMarkdown}
              className="rounded border border-stone-300 px-3 py-1.5 text-xs font-medium text-stone-700 hover:bg-stone-50 dark:border-stone-700 dark:text-stone-300 dark:hover:bg-stone-800"
            >
              看取り記録を Markdown で保存
            </button>
            <span className="text-xs text-stone-500">
              記録は、このドメイン以外の場所に残してください
            </span>
          </div>
        </div>
      )}

      {report?.notes.length ? (
        <ul className="mt-4 space-y-1">
          {report.notes.map((n) => (
            <li key={n} className="text-xs text-amber-700 dark:text-amber-500">
              {n}
            </li>
          ))}
        </ul>
      ) : null}

      {shown.length > 0 && (
        <div className="mt-10">
          <ResultList results={shown} />
        </div>
      )}

      {domain && report && (
        <div className="mt-12">
          <ManualChecklist checked={checked} onToggle={toggle} />
        </div>
      )}

      <footer className="mt-16 border-t border-stone-200 pt-6 text-xs leading-relaxed text-stone-500 dark:border-stone-800">
        <p>
          自動判定は DNS・CT ログ・RDAP
          から観測できる範囲に限られます。被リンクや印刷物のような参照、契約や届出に書かれた連絡先は検出できません。
          進捗 100% は「観測できる痕跡が無い」という意味であって、「手放してよい」という意味ではありません。
        </p>
      </footer>
    </div>
  )
}
