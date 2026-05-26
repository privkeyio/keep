<script lang="ts">
  import { onMount } from 'svelte'
  import {
    getBunker,
    getShares,
    importShare,
    exportShare,
    deleteShare,
    renameShare,
    getSigningLog,
    getKillswitch,
    setKillswitch,
    resolveApproval,
    connectEvents,
    hasAuthToken,
    setAuthToken,
    type BunkerInfo,
    type Share,
    type SigningEntry,
    type LogEvent,
    type ApprovalEvent,
  } from './lib/api'

  let bunker = $state<BunkerInfo | null>(null)
  let shares = $state<Share[]>([])
  let error = $state<string | null>(null)

  let authed = $state(hasAuthToken())
  let tokenInput = $state('')
  let stopStream: (() => void) | undefined

  function submitToken() {
    if (!tokenInput.trim()) return
    setAuthToken(tokenInput)
    tokenInput = ''
    error = null
    authed = true
    load()
  }

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

  // undefined = status not yet loaded (interaction disabled until known).
  let signingEnabled = $state<boolean | undefined>(undefined)
  let signingLoadError = $state<string | null>(null)
  let signingLog = $state<SigningEntry[]>([])
  let signingVerified = $state(true)
  let wsConnected = $state(false)

  // Per-share export UI state.
  let exportFor = $state<string | null>(null) // "group:id"
  let exportPass = $state('')
  let exportResult = $state('')
  let exportErr = $state<string | null>(null)

  // Per-share rename UI state.
  let renameFor = $state<string | null>(null)
  let renameVal = $state('')

  // Copy-to-clipboard feedback (which value was just copied).
  let copied = $state<string | null>(null)

  async function copy(value: string, label: string) {
    try {
      await navigator.clipboard.writeText(value)
      copied = label
      setTimeout(() => (copied === label ? (copied = null) : null), 1500)
    } catch {
      /* clipboard blocked (non-https); ignore */
    }
  }

  function fmtDate(secs: number | null): string {
    if (!secs) return 'never'
    return new Date(secs * 1000).toLocaleString()
  }

  function startRename(s: Share) {
    renameFor = `${s.group}:${s.identifier}`
    renameVal = s.name
  }

  async function doRename(s: Share) {
    try {
      await renameShare(s.group, s.identifier, renameVal.trim())
      renameFor = null
      refreshShares()
    } catch (e) {
      error = String(e)
    }
  }

  function refreshShares() {
    getShares()
      .then((s) => (shares = s))
      .catch((e) => (error = String(e)))
  }

  function refreshSigningLog() {
    getSigningLog()
      .then((r) => {
        signingLog = r.entries
        signingVerified = r.verified
      })
      .catch(() => {})
  }

  async function toggleKillswitch() {
    try {
      signingEnabled = await setKillswitch(!signingEnabled)
    } catch (e) {
      error = String(e)
    }
  }

  async function confirmDelete(s: Share) {
    if (!confirm(`Delete share "${s.name}" (${s.identifier})? This cannot be undone.`))
      return
    try {
      await deleteShare(s.group, s.identifier)
      refreshShares()
    } catch (e) {
      error = String(e)
    }
  }

  function startExport(s: Share) {
    exportFor = `${s.group}:${s.identifier}`
    exportPass = ''
    exportResult = ''
    exportErr = null
  }

  async function doExport(s: Share) {
    exportErr = null
    try {
      exportResult = await exportShare(s.group, s.identifier, exportPass)
    } catch (e) {
      exportErr = String(e)
    } finally {
      // Don't leave the passphrase sitting in client memory.
      exportPass = ''
    }
  }

  async function submitImport(e: Event) {
    e.preventDefault()
    importing = true
    importMsg = null
    importOk = false
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

  function handleUnauthorized(e: unknown): boolean {
    if (String(e).includes('401')) {
      authed = false
      stopStream?.()
      stopStream = undefined
      error = 'Authentication required. Enter the auth token.'
      return true
    }
    return false
  }

  function load() {
    getBunker()
      .then((b) => (bunker = b))
      .catch((e) => {
        if (!handleUnauthorized(e)) error = String(e)
      })
    refreshShares()
    getKillswitch()
      .then((e) => {
        signingEnabled = e
        signingLoadError = null
      })
      .catch((err) => {
        if (handleUnauthorized(err)) return
        signingEnabled = undefined
        signingLoadError = String(err)
      })
    refreshSigningLog()

    const stream = connectEvents(
      (e) => {
        if (e.type === 'approval') {
          // Cap the list so a long-running session can't grow it unbounded:
          // keep all still-pending requests, then fill up to 100 with the most
          // recent resolved ones.
          const next = [{ ...e }, ...approvals]
          const pending = next.filter((x) => !x.resolved)
          const resolved = next.filter((x) => x.resolved)
          approvals = [...pending, ...resolved].slice(0, 100)
        } else {
          logs = [e, ...logs].slice(0, 100)
          // A co-sign just happened — refresh the persistent audit log.
          if (e.app === 'frost') refreshSigningLog()
        }
      },
      (connected) => (wsConnected = connected),
    )
    stopStream = () => stream.close()
  }

  onMount(() => {
    if (authed) load()
    return () => stopStream?.()
  })

  async function decide(a: PendingApproval, approve: boolean) {
    try {
      await resolveApproval(a.id, approve)
      approvals = approvals.map((x) =>
        x.id === a.id ? { ...x, resolved: approve ? 'approved' : 'denied' } : x,
      )
    } catch (e) {
      // The request may have already timed out / been resolved on the signer.
      error = `Could not ${approve ? 'approve' : 'deny'} request: ${e}`
    }
  }
</script>

{#snippet copyField(label: string, value: string)}
  <div class="field">
    <span class="field-label">{label}</span>
    <span class="field-value" title={value}>{value}</span>
    <button class="copy-btn" onclick={() => copy(value, label + value)}>
      {copied === label + value ? '✓ Copied' : 'Copy'}
    </button>
  </div>
{/snippet}

<main>
  <h1>Keep — FROST Bunker</h1>

  {#if error}
    <p class="fail">{error}</p>
  {/if}

  {#if !authed}
    <div class="panel setup">
      <strong>🔒 Authentication required.</strong>
      <p>
        Enter the auth token. It is set via <code>KEEP_WEB_AUTH_TOKEN</code>, or, if
        unset, generated once at startup and printed to the service logs.
      </p>
      <form onsubmit={(e) => (e.preventDefault(), submitToken())}>
        <input
          type="password"
          placeholder="auth token"
          bind:value={tokenInput}
          autocomplete="off"
        />
        <button type="submit" disabled={!tokenInput.trim()}>Unlock</button>
      </form>
    </div>
  {:else}
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
      {#if bunker.threshold}
        <div class="kv"><span>threshold</span><strong>{bunker.threshold}</strong></div>
      {/if}
      {#if bunker.group}{@render copyField('group', bunker.group)}{/if}
      {#if bunker.npub}{@render copyField('npub', bunker.npub)}{/if}
      {#if bunker.url}{@render copyField('bunker', bunker.url)}{/if}
      {#if bunker.relay}{@render copyField('bunker relay', bunker.relay)}{/if}
      {#each bunker.frost_relays as r (r)}
        {@render copyField('frost relay', r)}
      {/each}
      {#if bunker.mode !== 'setup'}
        <div class="kv killswitch">
          <span>co-signing</span>
          {#if signingEnabled === undefined}
            <code class="warn">unknown{signingLoadError ? ` (${signingLoadError})` : ''}</code>
          {:else}
            <code class={signingEnabled ? '' : 'warn'}>
              {signingEnabled ? 'enabled' : 'DISABLED (kill switch)'}
            </code>
            <button class={signingEnabled ? 'no' : 'ok'} onclick={toggleKillswitch}>
              {signingEnabled ? 'Disable signing' : 'Enable signing'}
            </button>
          {/if}
        </div>
      {/if}
    {:else}
      <p class="muted">Connecting…</p>
    {/if}
  </div>

  <h2>Shares</h2>
  <div class="panel">
    {#each shares as s (s.group + ':' + s.identifier)}
      <div class="share">
        <div class="share-main">
          {#if renameFor === s.group + ':' + s.identifier}
            <div class="row">
              <input type="text" bind:value={renameVal} maxlength="64" />
              <button class="ok" onclick={() => doRename(s)} disabled={!renameVal.trim()}>
                Save
              </button>
              <button onclick={() => (renameFor = null)}>Cancel</button>
            </div>
          {:else}
            <span class="share-name">{s.name}</span>
          {/if}
          <span class="muted share-meta">
            #{s.identifier} · {s.threshold}-of-{s.total_shares} · signed {s.sign_count}
            {#if !s.did_backup}· <span class="warn-text">not backed up</span>{/if}
          </span>
          <span class="muted share-meta">
            created {fmtDate(s.created_at)} · last used {fmtDate(s.last_used)}
          </span>
        </div>
        <span class="share-actions">
          <button onclick={() => startRename(s)}>Rename</button>
          <button onclick={() => startExport(s)}>Export</button>
          <button class="no" onclick={() => confirmDelete(s)}>Delete</button>
        </span>
      </div>
      {#if exportFor === s.group + ':' + s.identifier}
        <div class="export-box">
          {#if exportResult}
            <p class="muted">Encrypted export (back this up):</p>
            <textarea readonly rows="3">{exportResult}</textarea>
          {:else}
            <div class="row">
              <input
                type="password"
                bind:value={exportPass}
                placeholder="Export passphrase"
                autocomplete="off"
              />
              <button class="ok" onclick={() => doExport(s)} disabled={!exportPass}>
                Export
              </button>
              <button onclick={() => (exportFor = null)}>Cancel</button>
            </div>
          {/if}
          {#if exportErr}<p class="fail">{exportErr}</p>{/if}
        </div>
      {/if}
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

  <h2>
    Activity
    <span class="verify {wsConnected ? 'ok' : 'fail'}">
      {wsConnected ? '● live' : '○ reconnecting…'}
    </span>
  </h2>
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

  <h2>
    Signing Log
    {#if signingLog.length}
      <span class="verify {signingVerified ? 'ok' : 'fail'}">
        {signingVerified ? '✓ chain verified' : '✗ chain INVALID'}
      </span>
    {/if}
  </h2>
  <div class="panel">
    {#each signingLog as e (e.timestamp_ms + ':' + e.session + ':' + e.operation)}
      <div class="event">
        <code>{e.session}</code>
        <span>{e.operation}</span>
        <span class="muted">
          · participants {e.participants.join(',')} · {new Date(
            e.timestamp_ms,
          ).toLocaleString()}
        </span>
      </div>
    {:else}
      <p class="muted">No signatures recorded yet.</p>
    {/each}
  </div>
  {/if}
</main>
