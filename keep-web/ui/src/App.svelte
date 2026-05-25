<script lang="ts">
  import { onMount } from 'svelte'
  import {
    getBunker,
    getShares,
    importShare,
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

  let importData = $state('')
  let importPass = $state('')
  let importName = $state('')
  let importing = $state(false)
  let importMsg = $state<string | null>(null)
  let importOk = $state(false)

  // What the Connection panel shows once a share is imported and the
  // co-signer is running.
  const fieldLegend: [string, string][] = [
    ['mode', 'network FROST co-signer once running (vs. setup)'],
    ['group', 'the FROST group npub this node co-signs for'],
    ['threshold', 'signatures needed, e.g. 2-of-3'],
    ['npub', "this signer's own public key"],
    ['bunker', 'NIP-46 connection string to paste into a Nostr client'],
    ['bunker relay', 'relay where clients reach the bunker'],
    ['frost relays', 'relays used to coordinate signing rounds with your devices'],
  ]

  function refreshShares() {
    getShares()
      .then((s) => (shares = s))
      .catch((e) => (error = String(e)))
  }

  async function submitImport(e: Event) {
    e.preventDefault()
    importing = true
    importMsg = null
    try {
      await importShare(importData, importPass, importName)
      importOk = true
      importMsg = null
      importData = ''
      importPass = ''
      importName = ''
      refreshShares()
    } catch (err) {
      importOk = false
      importMsg = String(err)
    } finally {
      importing = false
    }
  }

  onMount(() => {
    getBunker()
      .then((b) => (bunker = b))
      .catch((e) => (error = String(e)))
    refreshShares()

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

  {#if bunker && bunker.mode === 'setup'}
    <div class="panel setup">
      <strong>⚙ Setup required.</strong> No FROST share is loaded yet — this node
      isn't signing.
      <h3>Tasks to finish setup</h3>
      <ol class="tasks">
        <li>Import your FROST share below (export it from the device that holds it).</li>
        <li>
          Open the <strong>Configure</strong> action and set <strong>FROST Relays</strong>
          to match the relays your other share-holders use.
        </li>
        <li><strong>Restart the service</strong> to start the co-signer.</li>
        <li>
          Copy the bunker connection string (shown here after restart) into your
          Nostr client.
        </li>
      </ol>
    </div>
  {/if}

  <h2>Connection</h2>
  <div class="panel">
    {#if bunker}
      <div class="kv">
        <span>mode</span>
        {#if bunker.mode === 'network-frost'}
          <code>network FROST co-signer</code>
        {:else if bunker.mode === 'setup'}
          <code class="warn">setup — not signing yet</code>
        {:else}
          <code class="warn">single-key (no threshold security)</code>
        {/if}
      </div>
      {#if bunker.mode === 'setup'}
        <p class="muted legend-intro">
          Once a share is imported and the service is restarted, this panel will
          show:
        </p>
        <dl class="legend">
          {#each fieldLegend as [field, desc]}
            <dt>{field}</dt>
            <dd>{desc}</dd>
          {/each}
        </dl>
      {/if}
      {#if bunker.group}
        <div class="kv"><span>group</span><code>{bunker.group}</code></div>
      {/if}
      {#if bunker.threshold}
        <div class="kv"><span>threshold</span><code>{bunker.threshold}</code></div>
      {/if}
      {#if bunker.npub}
        <div class="kv"><span>npub</span><code>{bunker.npub}</code></div>
      {/if}
      {#if bunker.url}
        <div class="kv"><span>bunker</span><code>{bunker.url}</code></div>
      {/if}
      {#if bunker.relay}
        <div class="kv"><span>bunker relay</span><code>{bunker.relay}</code></div>
      {/if}
      {#if bunker.frost_relays.length}
        <div class="kv">
          <span>frost relays</span><code>{bunker.frost_relays.join(', ')}</code>
        </div>
      {/if}
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

  <h2>Import Share</h2>
  <div class="panel">
    <p class="note">
      The FROST relay must match the one your other share-holders use, or you
      won't find each other for signing rounds. Set it with the Configure
      action; the current relays are shown above.
    </p>
    <form onsubmit={submitImport}>
      <textarea
        bind:value={importData}
        placeholder="Paste share export (kshare1… or JSON)"
        rows="3"
      ></textarea>
      <div class="row">
        <input
          type="password"
          bind:value={importPass}
          placeholder="Passphrase"
          autocomplete="off"
        />
        <input type="text" bind:value={importName} placeholder="Name (optional)" />
        <button class="ok" type="submit" disabled={importing || !importData || !importPass}>
          {importing ? 'Importing…' : 'Import'}
        </button>
      </div>
      {#if importOk}
        <div class="import-ok">
          <strong>✓ Share imported.</strong>
          <span>Now <strong>restart the service</strong> to start the co-signer.</span>
        </div>
      {:else if importMsg}
        <p class="fail">{importMsg}</p>
      {/if}
    </form>
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
