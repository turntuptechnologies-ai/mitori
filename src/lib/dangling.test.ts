import { describe, expect, it } from 'vitest'
import {
  classifyCnameTarget,
  isServiceName,
  matchTakeoverService,
  type TargetProbe,
} from './dangling'
import { RCODE_NOERROR, RCODE_NXDOMAIN } from './doh'

const probe = (over: Partial<TargetProbe> = {}): TargetProbe => ({
  rcode: RCODE_NOERROR,
  hasAddress: true,
  hasOtherRecords: false,
  ...over,
})

describe('classifyCnameTarget', () => {
  it('向き先の名前が存在しなければ dangling と断定する', () => {
    expect(classifyCnameTarget(probe({ rcode: RCODE_NXDOMAIN, hasAddress: false }))).toBe('dangling')
  })

  it('乗っ取られやすいサービスでも、名前が存在しなければ dangling を優先する', () => {
    // NXDOMAIN は確定情報なので、サービス指紋より強い
    expect(
      classifyCnameTarget(probe({ rcode: RCODE_NXDOMAIN, hasAddress: false, service: 'Amazon S3' })),
    ).toBe('dangling')
  })

  it('名前はあるがアドレスも他のレコードも無い場合は nodata', () => {
    expect(classifyCnameTarget(probe({ hasAddress: false }))).toBe('nodata')
  })

  it('TXT だけを持つ向き先は正当な委譲として ok にする', () => {
    // _acme-challenge や _domainkey の CNAME は TXT しか持たないホストを指す。
    // これを nodata にすると正常な設定が「切れている」と誤検出される
    expect(classifyCnameTarget(probe({ hasAddress: false, hasOtherRecords: true }))).toBe('ok')
  })

  it('解決するうえに乗っ取られやすい向き先なら takeover-prone', () => {
    expect(classifyCnameTarget(probe({ service: 'GitHub Pages' }))).toBe('takeover-prone')
  })

  it('解決して既知サービスでもなければ ok', () => {
    expect(classifyCnameTarget(probe())).toBe('ok')
  })

  // 実測した現実の応答をそのまま固定する。
  // NXDOMAIN を返さないゾーンが多いため、rcode だけに頼ると取りこぼす
  it.each<[string, TargetProbe, string]>([
    ['no-such.wikipedia.org 相当', probe({ rcode: RCODE_NXDOMAIN, hasAddress: false }), 'dangling'],
    ['no-such.github.com 相当（NOERROR だが応答なし）', probe({ hasAddress: false }), 'nodata'],
    [
      '解放済み S3 相当（ワイルドカードで解決する）',
      probe({ service: 'Amazon S3' }),
      'takeover-prone',
    ],
    [
      'mbo0001._domainkey.mailbox.org 相当（TXT のみ）',
      probe({ hasAddress: false, hasOtherRecords: true }),
      'ok',
    ],
  ])('%s', (_label, input, expected) => {
    expect(classifyCnameTarget(input)).toBe(expected)
  })
})

describe('isServiceName', () => {
  // 実測で誤検出したものをそのまま並べる。いずれも正常な設定
  it.each([
    '_dmarc.example.com',
    '_acme-challenge.example.com',
    'mbo0001._domainkey.example.com',
    '_25._tcp.example.com',
    '77fa5113._openpgpkey.example.com',
  ])('%s はプロトコル専用の名前として除外する', (host) => {
    expect(isServiceName(host)).toBe(true)
  })

  it.each(['www.example.com', 'blog.example.com', 'old-site.example.com'])(
    '%s は通常のホスト名として検査対象に残す',
    (host) => {
      expect(isServiceName(host)).toBe(false)
    },
  )
})

describe('matchTakeoverService', () => {
  it('末尾一致でサービスを特定する', () => {
    expect(matchTakeoverService('my-bucket.s3.amazonaws.com')).toBe('Amazon S3')
    expect(matchTakeoverService('example.github.io')).toBe('GitHub Pages')
  })

  it('末尾のドットと大文字を吸収する', () => {
    expect(matchTakeoverService('Example.GitHub.IO.')).toBe('GitHub Pages')
  })

  it('部分一致では誤検出しない', () => {
    // ドメインの途中に含まれるだけのものを拾わないこと
    expect(matchTakeoverService('github.io.example.com')).toBeUndefined()
    expect(matchTakeoverService('example.com')).toBeUndefined()
  })
})
