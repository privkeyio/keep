export interface BunkerInfo {
  mode: string
  url: string
  npub: string
  relay: string
  frost_relays: string[]
  group: string | null
  threshold: string | null
}

export interface Share {
  name: string
  group: string
  identifier: number
  threshold: number
  total_shares: number
  sign_count: number
}

export interface SigningEntry {
  timestamp_ms: number
  session: string
  operation: string
  participants: number[]
  our_index: number
}

export interface LogEvent {
  type: 'log'
  app: string
  action: string
  success: boolean
  detail: string | null
}

export interface ApprovalEvent {
  type: 'approval'
  id: number
  app: string
  method: string
  kind: number | null
  preview: string | null
}

export type ServerEvent = LogEvent | ApprovalEvent

export async function getBunker(): Promise<BunkerInfo> {
  const r = await fetch('/api/bunker')
  if (!r.ok) throw new Error(`bunker: ${r.status}`)
  return r.json()
}

export async function getShares(): Promise<Share[]> {
  const r = await fetch('/api/shares')
  if (!r.ok) throw new Error(`shares: ${r.status}`)
  return r.json()
}

export async function importShare(
  data: string,
  passphrase: string,
  name: string,
): Promise<void> {
  const r = await fetch('/api/shares/import', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ data, passphrase, name: name || null }),
  })
  if (!r.ok && r.status !== 204) {
    throw new Error((await r.text()) || `import failed: ${r.status}`)
  }
}

export async function exportShare(
  group: string,
  identifier: number,
  passphrase: string,
): Promise<string> {
  const r = await fetch('/api/shares/export', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ group, identifier, passphrase }),
  })
  if (!r.ok) throw new Error((await r.text()) || `export failed: ${r.status}`)
  return (await r.json()).export
}

export async function deleteShare(group: string, identifier: number): Promise<void> {
  const r = await fetch('/api/shares/delete', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ group, identifier }),
  })
  if (!r.ok && r.status !== 204) {
    throw new Error((await r.text()) || `delete failed: ${r.status}`)
  }
}

export async function getSigningLog(): Promise<{
  verified: boolean
  entries: SigningEntry[]
}> {
  const r = await fetch('/api/signing-log')
  if (!r.ok) throw new Error(`signing log: ${r.status}`)
  return r.json()
}

export async function getKillswitch(): Promise<boolean> {
  const r = await fetch('/api/killswitch')
  if (!r.ok) throw new Error(`killswitch: ${r.status}`)
  return (await r.json()).enabled
}

export async function setKillswitch(enabled: boolean): Promise<boolean> {
  const r = await fetch('/api/killswitch', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ enabled }),
  })
  if (!r.ok) throw new Error(`killswitch: ${r.status}`)
  return (await r.json()).enabled
}

export async function resolveApproval(id: number, approve: boolean): Promise<void> {
  const r = await fetch(`/api/approvals/${id}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ approve }),
  })
  if (!r.ok && r.status !== 204) throw new Error(`approval: ${r.status}`)
}

export function connectEvents(onEvent: (e: ServerEvent) => void): WebSocket {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  const ws = new WebSocket(`${proto}://${location.host}/api/events`)
  ws.onmessage = (m) => {
    try {
      onEvent(JSON.parse(m.data))
    } catch {
      /* ignore malformed frames */
    }
  }
  return ws
}
