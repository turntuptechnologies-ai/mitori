import { MANUAL_ITEMS, MANUAL_PHASE_LABEL, type ManualItem } from '../lib/manual'

interface Props {
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

export function ManualChecklist({ checked, onToggle }: Props) {
  const done = MANUAL_ITEMS.filter((i) => checked.has(i.id)).length

  return (
    <section>
      <div className="mb-3 flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h2 className="text-sm font-semibold tracking-wide text-stone-500 dark:text-stone-400">
          手動確認項目（{done} / {MANUAL_ITEMS.length}）
        </h2>
        <p className="text-xs text-stone-500 dark:text-stone-500">
          DNS からは観測できないため、mitori では判定できません
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
                {items.map((item) => (
                  <li key={item.id}>
                    <label className="flex cursor-pointer items-start gap-2.5">
                      <input
                        type="checkbox"
                        checked={checked.has(item.id)}
                        onChange={() => onToggle(item.id)}
                        className="mt-0.5 size-4 shrink-0 accent-stone-700 dark:accent-stone-400"
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
                  </li>
                ))}
              </ul>
            </div>
          )
        })}
      </div>
    </section>
  )
}
