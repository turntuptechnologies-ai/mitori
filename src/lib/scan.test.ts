import { describe, expect, it } from 'vitest'
import { normalizeDomain } from './scan'

describe('normalizeDomain', () => {
  it('素のドメインをそのまま通す', () => {
    expect(normalizeDomain('example.com')).toBe('example.com')
  })

  it('URL からホスト名を取り出す', () => {
    expect(normalizeDomain('https://www.example.com/path?q=1')).toBe('www.example.com')
  })

  it('前後の空白と末尾のドットを落とす', () => {
    expect(normalizeDomain('  example.com.  ')).toBe('example.com')
  })

  it('大文字を小文字に揃える', () => {
    expect(normalizeDomain('EXAMPLE.COM')).toBe('example.com')
  })

  it('国際化ドメインを punycode に変換する', () => {
    expect(normalizeDomain('日本語.jp')).toBe('xn--wgv71a119e.jp')
  })

  it('ドットを含まない入力は受け付けない', () => {
    expect(normalizeDomain('localhost')).toBeNull()
    expect(normalizeDomain('')).toBeNull()
    expect(normalizeDomain('   ')).toBeNull()
  })
})
