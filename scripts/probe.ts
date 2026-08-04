/**
 * 実際の外部 API に対してスキャナを動かす手動検証スクリプト。
 *
 *   npx tsx scripts/probe.ts example.com
 *
 * ブラウザではなく Node で動かすため CORS は掛からないが、
 * CORS 許可は curl で別途確認済み。ここで見たいのはロジックと応答形式の整合。
 */
import { normalizeDomain, runScan } from '../src/lib/scan'
import { collectTasks, MANUAL_ITEMS } from '../src/lib/manual'

const input = process.argv[2] ?? 'example.com'
const domain = normalizeDomain(input)
if (!domain) {
  console.error(`ドメインとして解釈できません: ${input}`)
  process.exit(1)
}

const started = Date.now()
const report = await runScan(
  domain,
  () => {},
  (p) => process.stderr.write(`\r${p.completed}/${p.total} ${p.current}          `),
)
process.stderr.write('\n\n')

const MARK: Record<string, string> = { clear: '○', action: '●', warn: '△', unknown: '?' }

console.log(`# ${report.domain}  進捗 ${report.score}%  (判定できた項目 ${report.decidable})`)
console.log(`# 所要 ${((Date.now() - started) / 1000).toFixed(1)}s\n`)

for (const r of report.results) {
  console.log(`${MARK[r.status]} [${r.severity}] ${r.title}`)
  console.log(`    ${r.summary}`)
  for (const e of r.evidence ?? []) console.log(`      - ${e}`)
}
const tasks = collectTasks(report.results)
if (tasks.size) {
  const derived = [...tasks.values()].flat().length
  console.log(`\n## 検査から作られた具体タスク (${derived})`)
  for (const item of MANUAL_ITEMS) {
    const found = tasks.get(item.id)
    if (!found?.length) continue
    console.log(`  ${item.text}`)
    for (const t of found) console.log(`    □ ${t.text}`)
  }
}

if (report.notes.length) {
  console.log('\n## notes')
  for (const n of report.notes) console.log(`  ! ${n}`)
}
