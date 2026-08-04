import { useMemo } from 'react'
import { collectTasks, MANUAL_ITEMS, MANUAL_PHASE_LABEL, type ManualItem } from '../lib/manual'
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
                        <Checkbox
                          id={item.id}
                          checked={checked.has(item.id)}
                          onToggle={onToggle}
                        />
                        <span className="min-w-0">
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
