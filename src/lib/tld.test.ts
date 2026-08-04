import { describe, expect, it } from 'vitest'
import { attributeLabelOf, classify, profileOf } from './tld'

describe('classify', () => {
  it('属性型 JP を第 2 レベルのラベルで見分ける', () => {
    expect(classify('expo2025.or.jp')).toBe('attribute-jp')
    expect(classify('city.yokohama.lg.jp')).toBe('attribute-jp')
    expect(classify('u-tokyo.ac.jp')).toBe('attribute-jp')
    expect(classify('digital.go.jp')).toBe('attribute-jp')
  })

  it('サブドメインが付いていても属性型と分かる', () => {
    expect(classify('www.expo2025.or.jp')).toBe('attribute-jp')
    expect(classify('a.b.c.example.co.jp')).toBe('attribute-jp')
  })

  it('汎用 JP を見分ける', () => {
    expect(classify('expo2025.jp')).toBe('general-jp')
    expect(classify('www.odate-city.jp')).toBe('general-jp')
  })

  it('第 2 レベルが都道府県名なら都道府県型・地域型として扱う', () => {
    expect(classify('kotoura.tottori.jp')).toBe('prefecture-jp')
    // 大館市の city.odate.akita.jp のような従来の地方公共団体ドメイン名も同じ形
    expect(classify('city.odate.akita.jp')).toBe('prefecture-jp')
  })

  it('都道府県名でない 3 ラベルの JP は汎用 JP のサブドメイン', () => {
    // example.jp の www サブドメインであって、都道府県型ではない
    expect(classify('www.example.jp')).toBe('general-jp')
  })

  it('3 文字以上のトップレベルは gTLD として扱う', () => {
    expect(classify('juniorexpo2025.com')).toBe('gtld')
    expect(classify('example.org')).toBe('gtld')
    // 地理名の gTLD も ICANN の規則に従うので gTLD
    expect(classify('example.tokyo')).toBe('gtld')
  })

  it('2 文字のトップレベルは国別コードとして判定を避ける', () => {
    // 国ごとに制度が違うため、断定せず判定不能にする
    expect(classify('example.uk')).toBe('other-cctld')
    expect(classify('example.de')).toBe('other-cctld')
  })
})

describe('attributeLabelOf', () => {
  it('属性ラベルを取り出す', () => {
    expect(attributeLabelOf('city.yokohama.lg.jp')).toBe('lg')
    expect(attributeLabelOf('expo2025.or.jp')).toBe('or')
  })

  it('属性型でなければ null', () => {
    expect(attributeLabelOf('expo2025.jp')).toBeNull()
    expect(attributeLabelOf('example.com')).toBeNull()
    // 'xx' は属性ラベルではない
    expect(attributeLabelOf('foo.xx.jp')).toBeNull()
  })
})

describe('profileOf', () => {
  it('属性型は資格審査ありとして扱う', () => {
    const p = profileOf('city.yokohama.lg.jp')
    expect(p.exposure).toBe('screened')
    expect(p.whoCanTake).toContain('地方公共団体')
  })

  it('汎用 JP は国内の誰でも取得できるとして扱う', () => {
    expect(profileOf('expo2025.jp').exposure).toBe('domestic')
  })

  it('gTLD は全世界に開かれているとして扱う', () => {
    expect(profileOf('juniorexpo2025.com').exposure).toBe('global')
  })

  it('都道府県型と地域型は区別できないので断定しない', () => {
    // 名前だけでは制度が決まらない。片方に決め打ちすると誤った猶予期間を伝えることになる
    const p = profileOf('city.odate.akita.jp')
    expect(p.exposure).toBe('unclear')
    expect(p.notes.join()).toContain('判別できません')
  })

  it('.jp 以外の国別コードは判定しない', () => {
    expect(profileOf('example.uk').exposure).toBe('unclear')
  })

  it('属性型には、組織が消えると保持できなくなることを添える', () => {
    // 「手放さない」が最も確実な対策だが、属性型では解散すると選べない
    expect(profileOf('u-tokyo.ac.jp').notes.join()).toContain('第 26 条第 2 項')
  })
})
