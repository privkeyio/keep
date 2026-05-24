<script lang="ts">
  import { onMount } from 'svelte'
  import {
    getBunker,
    getShares,
    resolveApproval,
    connectEvents,
    type BunkerInfo,
    type Share,
    type LogEvent,
    type ApprovalEvent,
  } from './lib/api'

  let bunker = $state<BunkerInfo | null>(null)
  let shares = $state<Share[]>([])
  let error = $state<string | null>(null)

  type PendingApproval = ApprovalEvent & { resolved?: 'approved' | 'denied' }
  let approvals = $state<PendingApproval[]>([])
  let logs = $state<LogEvent[]>([])

  onMount(() => {
    getBunker()
      .then((b) => (bunker = b))
      .catch((e) => (error = String(e)))
    getShares()
      .then((s) => (shares = s))
      .catch((e) => (error = String(e)))

    const ws = connectEvents((e) => {
      if (e.type === 'approval') {
        approvals = [{ ...e }, ...approvals]
      } else {
        logs = [e, ...logs].slice(0, 100)
      }
    })
    return () => ws.close()
  })

  async function decide(a: PendingApproval, approve: boolean) {
    await resolveApproval(a.id, approve)
    approvals = approvals.map((x) =>
      x.id === a.id ? { ...x, resolved: approve ? 'approved' : 'denied' } : x,
    )
  }
</script>

<main>
  <h1>Keep — FROST Bunker</h1>

  {#if error}
    <p class="fail">{error}</p>
  {/if}

  <h2>Connection</h2>
  <div class="panel">
    {#if bunker}
      <div class="kv"><span>npub</span><code>{bunker.npub}</code></div>
      <div class="kv"><span>bunker</span><code>{bunker.url}</code></div>
      <div class="kv"><span>relay</span><code>{bunker.relay}</code></div>
    {:else}
      <p class="muted">Connecting…</p>
    {/if}
  </div>

  <h2>Shares</h2>
  <div class="panel">
    {#each shares as s (s.name)}
      <div class="share">
        <span>{s.name}</span>
        <span class="muted">
          {s.threshold}-of-{s.total_shares} · signed {s.sign_count}
        </span>
      </div>
    {:else}
      <p class="muted">No shares imported yet.</p>
    {/each}
  </div>

  <h2>Activity</h2>
  <div class="panel">
    {#each approvals as a (a.id)}
      <div class="event approval">
        <span><strong>{a.app}</strong> requests {a.method}</span>
        {#if a.resolved}
          <span class="muted">→ {a.resolved}</span>
        {:else}
          <button class="ok" onclick={() => decide(a, true)}>Approve</button>
          <button class="no" onclick={() => decide(a, false)}>Deny</button>
        {/if}
      </div>
    {/each}
    {#each logs as l, i (i)}
      <div class="event">
        <strong>{l.app}</strong>: {l.action}
        <span class:fail={!l.success}>{l.success ? '✓' : '✗'}</span>
        {#if l.detail}<span class="muted"> · {l.detail}</span>{/if}
      </div>
    {/each}
    {#if approvals.length === 0 && logs.length === 0}
      <p class="muted">Waiting for signing activity…</p>
    {/if}
  </div>
</main>
