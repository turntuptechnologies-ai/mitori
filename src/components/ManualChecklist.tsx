import { useMemo } from 'react'
import {
  collectTasks,
  MANUAL_CATEGORY_LABEL,
  MANUAL_CATEGORY_ORDER,
  MANUAL_ITEMS,
  MANUAL_PHASE_LABEL,
  type ManualCategory,
  type ManualItem,
} from '../lib/manual'
import type { CheckResult, DerivedTask } from '../lib/types'

interface Props {
  results: CheckResult[]
  checked: Set<string>
  onToggle: (id: string) => void
}

const PHASES: ManualItem['phase'][] = [
  'judge',
  'inventory',
  'detach',
  'cooldown',
  'release',
  'after',
]

/**
 * 検査結果の重大度バッジ（塗りつぶし）と混同されないよう、分類は点で示す。
 * 色が意味を持つのは分類の識別だけで、危険度とは無関係。
 */
const CATEGORY_DOT: Record<ManualCategory, string> = {
  mail: 'bg-sky-500',
  web: 'bg-violet-500',
  service: 'bg-teal-500',
  domain: 'bg-orange-500',
  offline: 'bg-stone-400',
  record: 'bg-indigo-500',
}

function CategoryTag({ category }: { category: ManualCategory }) {
  return (
    <span className="mr-1.5 inline-flex items-center gap-1 align-middle whitespace-nowrap">
      <span className={`size-1.5 rounded-full ${CATEGORY_DOT[category]}`} aria-hidden />
      <span className="text-[11px] text-stone-500 dark:text-stone-400">
        {MANUAL_CATEGORY_LABEL[category]}
      </span>
    </span>
  )
}

function Checkbox({
  id,
  checked,
  onToggle,
}: {
  id: string
  checked: boolean
  onToggle: (id: string) => void
}) {
  return (
    <input
      type="checkbox"
      checked={checked}
      onChange={() => onToggle(id)}
      className="mt-0.5 size-4 shrink-0 accent-stone-700 dark:accent-stone-400"
    />
  )
}

function DerivedTaskRow({
  task,
  checked,
  onToggle,
}: {
  task: DerivedTask
  checked: Set<string>
  onToggle: (id: string) => void
}) {
  const done = checked.has(task.id)
  return (
    <li>
      <label className="flex cursor-pointer items-start gap-2.5">
        <Checkbox id={task.id} checked={done} onToggle={onToggle} />
        <span
          className={`text-sm ${
            done
              ? 'text-stone-400 line-through dark:text-stone-600'
              : 'text-stone-700 dark:text-stone-300'
          }`}
        >
          {task.text}
        </span>
      </label>
    </li>
  )
}

export function ManualChecklist({ results, checked, onToggle }: Props) {
  const tasks = useMemo(() => collectTasks(results), [results])
  const derived = useMemo(() => [...tasks.values()].flat(), [tasks])

  // 分類ごとの進み具合。生成タスクは親項目の分類として数える
  const byCategory = useMemo(() => {
    const counts = new Map<ManualCategory, { total: number; done: number }>()
    for (const item of MANUAL_ITEMS) {
      const c = counts.get(item.category) ?? { total: 0, done: 0 }
      for (const id of [item.id, ...(tasks.get(item.id) ?? []).map((t) => t.id)]) {
        c.total += 1
        if (checked.has(id)) c.done += 1
      }
      counts.set(item.category, c)
    }
    return counts
  }, [tasks, checked])

  const total = MANUAL_ITEMS.length + derived.length
  const done =
    MANUAL_ITEMS.filter((i) => checked.has(i.id)).length +
    derived.filter((t) => checked.has(t.id)).length

  return (
    <section>
      <div className="mb-3 flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h2 className="text-sm font-semibold tracking-wide text-stone-500 dark:text-stone-400">
          確認項目（{done} / {total}）
        </h2>
        <p className="text-xs text-stone-500 dark:text-stone-500">
          {derived.length > 0
            ? `うち ${derived.length} 件は、今回の検査で見つかったものから作られています`
            : 'DNS からは観測できないため、mitori では判定できません'}
        </p>
      </div>

      <div className="mb-4 flex flex-wrap gap-x-4 gap-y-1.5 rounded-lg border border-stone-200 bg-stone-50 px-3.5 py-2.5 dark:border-stone-800 dark:bg-stone-950">
        {MANUAL_CATEGORY_ORDER.map((category) => {
          const c = byCategory.get(category)
          if (!c) return null
          return (
            <span key={category} className="inline-flex items-center gap-1.5">
              <span className={`size-1.5 rounded-full ${CATEGORY_DOT[category]}`} aria-hidden />
              <span className="text-xs text-stone-600 dark:text-stone-400">
                {MANUAL_CATEGORY_LABEL[category]}
              </span>
              <span className="font-mono text-xs text-stone-400 dark:text-stone-600">
                {c.done}/{c.total}
              </span>
            </span>
          )
        })}
      </div>

      <div className="space-y-5">
        {PHASES.map((phase) => {
          const items = MANUAL_ITEMS.filter((i) => i.phase === phase)
          return (
            <div
              key={phase}
              className="rounded-lg border border-stone-200 bg-white p-4 dark:border-stone-800 dark:bg-stone-900"
            >
              <h3 className="mb-2 text-sm font-semibold text-stone-800 dark:text-stone-200">
                {MANUAL_PHASE_LABEL[phase]}
              </h3>
              <ul className="space-y-2">
                {items.map((item) => {
                  const found = tasks.get(item.id) ?? []
                  return (
                    <li key={item.id}>
                      <label className="flex cursor-pointer items-start gap-2.5">
                        <Checkbox id={item.id} checked={checked.has(item.id)} onToggle={onToggle} />
                        <span className="min-w-0">
                          <CategoryTag category={item.category} />
                          <span
                            className={`text-sm ${
                              checked.has(item.id)
                                ? 'text-stone-400 line-through dark:text-stone-600'
                                : 'text-stone-800 dark:text-stone-200'
                            }`}
                          >
                            {item.text}
                          </span>
                          {item.note && (
                            <span className="mt-0.5 block text-xs text-stone-500 dark:text-stone-500">
                              {item.note}
                            </span>
                          )}
                        </span>
                      </label>

                      {found.length > 0 && (
                        <div className="mt-2 ml-6.5 border-l-2 border-stone-300 pl-3 dark:border-stone-700">
                          <p className="mb-1 text-xs font-medium text-stone-500 dark:text-stone-500">
                            検査で見つかった分（{found.filter((t) => checked.has(t.id)).length} /{' '}
                            {found.length}）
                          </p>
                          <ul className="space-y-1.5">
                            {found.map((task) => (
                              <DerivedTaskRow
                                key={task.id}
                                task={task}
                                checked={checked}
                                onToggle={onToggle}
                              />
                            ))}
                          </ul>
                        </div>
                      )}
                    </li>
                  )
                })}
              </ul>
            </div>
          )
        })}
      </div>
    </section>
  )
}
