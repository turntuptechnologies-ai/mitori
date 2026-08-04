import { describe, expect, it } from 'vitest'
import { classifyAuthority, nextNameOf, siblingProbe, successorProbe } from './nsec'
import type { DnsAnswer } from './doh'

const rr = (type: number, name: string, data: string): DnsAnswer => ({
  name,
  type,
  TTL: 300,
  data,
})

const NSEC = 47
const NSEC3 = 50
const RRSIG = 46
const SOA = 6

describe('classifyAuthority', () => {
  // 以下の応答はすべて実測したものをそのまま固定している
  it('ルートゾーンのような素の NSEC は nsec と判定する', () => {
    const authority = [
      rr(SOA, '.', 'a.root-servers.net. nstld.verisign-grs.com. 1 1800 900 604800 86400'),
      rr(NSEC, 'zw.', '. NS RRSIG NSEC'),
      rr(NSEC, '.', 'aaa. NS SOA RRSIG NSEC DNSKEY TYPE63'),
      rr(RRSIG, '.', 'NSEC 8 0 86400 ...'),
    ]
    expect(classifyAuthority(authority, 'zzz-nonexistent-tld-mitori')).toBe('nsec')
  })

  it('NSEC3 が含まれていれば nsec3 と判定する', () => {
    const authority = [
      rr(
        NSEC3,
        'bvb2o0np2rsvrvh4gv6r6mf82p2s2en3.iana.org.',
        '1 0 0 - CDPML5AR48F7FM312T5NLVFFJAFL5TTL',
      ),
    ]
    expect(classifyAuthority(authority, 'no-such-name-mitori.iana.org')).toBe('nsec3')
  })

  it('問い合わせた名前を所有者とする NSEC はホワイトライと判定する', () => {
    // ietf.org の実応答。合成された NSEC なので次の名前を教えていない
    const authority = [
      rr(
        NSEC,
        'no-such-name-mitori.ietf.org.',
        '\\000.no-such-name-mitori.ietf.org. RRSIG NSEC TYPE128',
      ),
    ]
    expect(classifyAuthority(authority, 'no-such-name-mitori.ietf.org')).toBe('white-lies')
  })

  it('NSEC も NSEC3 も無ければ unavailable', () => {
    expect(classifyAuthority([rr(SOA, 'example.com.', '...')], 'x.example.com')).toBe('unavailable')
    expect(classifyAuthority([], 'x.example.com')).toBe('unavailable')
  })

  it('末尾ドットと大小文字の違いを吸収する', () => {
    const authority = [rr(NSEC, 'X.Example.COM.', '\\000.x.example.com. A RRSIG NSEC')]
    expect(classifyAuthority(authority, 'x.example.com')).toBe('white-lies')
  })
})

describe('nextNameOf', () => {
  it('RDATA の先頭にある次の名前を取り出す', () => {
    expect(nextNameOf('6only.nlnetlabs.nl. TXT RRSIG NSEC')).toBe('6only.nlnetlabs.nl')
  })

  it('前後の空白を無視する', () => {
    expect(nextNameOf('  aaa.  NS SOA  ')).toBe('aaa')
  })
})

describe('successorProbe', () => {
  it('最小バイトのラベルを足して直後の名前を作る', () => {
    // 正規順序ではラベルの中身が小さいほど先。\000 より小さいラベルは存在しない
    expect(successorProbe('example.com')).toBe('\\000.example.com')
  })
})

describe('siblingProbe', () => {
  // 委譲点では `\000.name` がリゾルバを子ゾーンに送ってしまい親の NSEC が返らない。
  // 最左ラベルの末尾に最小バイトを足すと、子ゾーンに入らずサブツリーを飛び越えられる
  it('最左ラベルの末尾に最小バイトを足す', () => {
    expect(siblingProbe('acme.nlnetlabs.nl')).toBe('acme\\000.nlnetlabs.nl')
  })

  it('サブドメインが深くても最左ラベルだけを変える', () => {
    expect(siblingProbe('a.b.example.com')).toBe('a\\000.b.example.com')
  })

  it('ドットが無い場合も壊れない', () => {
    expect(siblingProbe('localhost')).toBe('localhost\\000')
  })
})
