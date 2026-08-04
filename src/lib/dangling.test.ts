import { describe, expect, it } from 'vitest'
import { classifyCnameTarget, matchTakeoverService } from './dangling'
import { RCODE_NOERROR, RCODE_NXDOMAIN } from './doh'

describe('classifyCnameTarget', () => {
  it('向き先の名前が存在しなければ dangling と断定する', () => {
    expect(classifyCnameTarget(RCODE_NXDOMAIN, false, undefined)).toBe('dangling')
  })

  it('乗っ取られやすいサービスでも、名前が存在しなければ dangling を優先する', () => {
    // NXDOMAIN は確定情報なので、サービス指紋より強い
    expect(classifyCnameTarget(RCODE_NXDOMAIN, false, 'Amazon S3')).toBe('dangling')
  })

  it('名前はあるがアドレスを持たない場合は nodata として区別する', () => {
    expect(classifyCnameTarget(RCODE_NOERROR, false, undefined)).toBe('nodata')
  })

  it('解決するうえに乗っ取られやすい向き先なら takeover-prone', () => {
    expect(classifyCnameTarget(RCODE_NOERROR, true, 'GitHub Pages')).toBe('takeover-prone')
  })

  it('解決して既知サービスでもなければ ok', () => {
    expect(classifyCnameTarget(RCODE_NOERROR, true, undefined)).toBe('ok')
  })

  // 実測した現実の応答をそのまま固定する。
  // NXDOMAIN を返さないゾーンが多いため、rcode だけに頼ると取りこぼす
  it.each([
    ['no-such.wikipedia.org 相当', RCODE_NXDOMAIN, false, undefined, 'dangling'],
    ['no-such.github.com 相当（NOERROR だが応答なし）', RCODE_NOERROR, false, undefined, 'nodata'],
    ['解放済み S3 相当（ワイルドカードで解決する）', RCODE_NOERROR, true, 'Amazon S3', 'takeover-prone'],
    ['解放済み github.io 相当', RCODE_NOERROR, true, 'GitHub Pages', 'takeover-prone'],
  ])('%s', (_label, rcode, hasAddress, service, expected) => {
    expect(classifyCnameTarget(rcode as number, hasAddress as boolean, service as string | undefined)).toBe(
      expected,
    )
  })
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
