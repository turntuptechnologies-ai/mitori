import { describe, expect, it } from 'vitest'
import { collectTasks, makeTask } from './manual'
import { makeResult, type CheckResult } from './types'

const result = (id: string, tasks: CheckResult['tasks']): CheckResult =>
  makeResult({
    id,
    phase: 'detach',
    title: id,
    severity: 'info',
    status: 'action',
    summary: '',
    tasks,
  })

describe('makeTask', () => {
  it('流し込み先と観測対象から id を組み立てる', () => {
    expect(makeTask('det-tenant', 'Slack', 'Slack を解除する')).toEqual({
      target: 'det-tenant',
      id: 'det-tenant:slack',
      text: 'Slack を解除する',
    })
  })

  it('表記ゆれがあっても同じ観測なら同じ id になる', () => {
    // id が変わるとチェック済みの状態が失われるため、空白と大小文字は吸収する
    expect(makeTask('det-tenant', ' Microsoft 365 ', 'a').id).toBe(
      makeTask('det-tenant', 'microsoft 365', 'b').id,
    )
  })

  it('文言が変わっても id は変わらない', () => {
    // 件数のように毎回変わる値を文言に含めても、チェック状態は保たれる
    expect(makeTask('det-request', 'ja.wikipedia.org', '144 ページを差し替える').id).toBe(
      makeTask('det-request', 'ja.wikipedia.org', '12 ページを差し替える').id,
    )
  })
})

describe('collectTasks', () => {
  it('流し込み先ごとにまとめる', () => {
    const tasks = collectTasks([
      result('saas-tokens', [makeTask('det-tenant', 'Slack', 'Slack を解除する')]),
      result('registry', [makeTask('rel-autorenew', 'registrar', '自動更新を確認する')]),
    ])
    expect(tasks.get('det-tenant')?.map((t) => t.text)).toEqual(['Slack を解除する'])
    expect(tasks.get('rel-autorenew')).toHaveLength(1)
  })

  it('複数の検査が同じ相手を指しても 1 件に畳む', () => {
    // Microsoft 365 は所有権トークンとグループウェア連携の両方から出てくる
    const tasks = collectTasks([
      result('saas-tokens', [makeTask('det-tenant', 'Microsoft 365', 'テナントから外す')]),
      result('ms365', [makeTask('det-tenant', 'Microsoft 365', 'テナントから外す')]),
    ])
    expect(tasks.get('det-tenant')).toHaveLength(1)
  })

  it('存在しない項目に紐づいたタスクは捨てる', () => {
    // makeTask の型で弾かれるのが本筋だが、実行時にも表示先の無いタスクを残さない。
    // 残すと、どこにも出ないまま件数の分母だけが増える
    const orphan = { target: 'no-such-item', id: 'no-such-item:a', text: 'text' }
    expect(collectTasks([result('x', [orphan])]).size).toBe(0)
  })

  it('タスクを持たない検査結果を混ぜても壊れない', () => {
    expect(collectTasks([result('x', undefined), result('y', [])]).size).toBe(0)
  })
})
