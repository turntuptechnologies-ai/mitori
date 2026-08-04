/**
 * Wayback Machine にアーカイブが残っているかを確認する。
 *
 * 件数を数えられる CDX API は CORS ヘッダを返さないため、
 * CORS 許可済みの availability API に限定する。
 * 得られるのは「最も近いスナップショット」だけだが、
 * 「消せない参照が実在する」ことの証明には足りる。
 */

export interface WaybackResult {
  ok: boolean
  archived: boolean
  /** YYYYMMDDhhmmss */
  timestamp?: string
  url?: string
  reason?: string
}

interface AvailabilityResponse {
  archived_snapshots?: {
    closest?: { available?: boolean; url?: string; timestamp?: string; status?: string }
  }
}

export async function checkWayback(domain: string): Promise<WaybackResult> {
  try {
    const res = await fetch(
      `https://archive.org/wayback/available?url=${encodeURIComponent(domain)}`,
    )
    if (!res.ok) throw new Error(`wayback ${res.status}`)
    const data = (await res.json()) as AvailabilityResponse
    const closest = data.archived_snapshots?.closest
    if (!closest?.available) return { ok: true, archived: false }
    return {
      ok: true,
      archived: true,
      timestamp: closest.timestamp,
      url: closest.url,
    }
  } catch {
    return { ok: false, archived: false, reason: 'Wayback Machine に問い合わせできませんでした' }
  }
}

export function formatWaybackTimestamp(ts: string): string {
  if (ts.length < 8) return ts
  return `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}`
}
