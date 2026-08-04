import { describe, expect, it } from 'vitest'
import { parseCaa, unquoteTxt } from './doh'

describe('parseCaa', () => {
  it('Google DoH の表示形式を読む', () => {
    expect(parseCaa('0 issue "letsencrypt.org"')).toEqual({
      flags: 0,
      tag: 'issue',
      value: 'letsencrypt.org',
    })
  })

  it('Cloudflare DoH の RFC 3597 汎用形式を復号する', () => {
    // 00 05 "issue" "digicert.com" — 実際に cloudflare-dns.com が返した値
    const raw = '\\# 19 00 05 69 73 73 75 65 64 69 67 69 63 65 72 74 2e 63 6f 6d'
    expect(parseCaa(raw)).toEqual({ flags: 0, tag: 'issue', value: 'digicert.com' })
  })

  it('発行禁止を表す issue ";" を復号できる', () => {
    // 00 05 "issue" ";"
    const raw = '\\# 8 00 05 69 73 73 75 65 3b'
    expect(parseCaa(raw)).toEqual({ flags: 0, tag: 'issue', value: ';' })
  })

  it('issuewild も読める', () => {
    expect(parseCaa('0 issuewild ";"')).toEqual({ flags: 0, tag: 'issuewild', value: ';' })
  })

  it('解釈できない値は null を返す', () => {
    expect(parseCaa('')).toBeNull()
    expect(parseCaa('\\# 3 00')).toBeNull()
  })
})

describe('unquoteTxt', () => {
  it('引用符を外す', () => {
    expect(unquoteTxt('"v=spf1 -all"')).toBe('v=spf1 -all')
  })

  it('255 バイト超で分割された文字列を結合する', () => {
    // 分割片を結合しないと SPF や DKIM の判定を誤る
    expect(unquoteTxt('"v=DKIM1; p=AAAA" "BBBB"')).toBe('v=DKIM1; p=AAAABBBB')
  })

  it('エスケープされた引用符を戻す', () => {
    expect(unquoteTxt('"a\\"b"')).toBe('a"b')
  })

  it('引用符が無ければそのまま返す', () => {
    expect(unquoteTxt('bare-value')).toBe('bare-value')
  })
})
