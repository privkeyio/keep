<script lang="ts">
  import { onMount } from 'svelte'
  import crest from './assets/keep-crest.png'
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

  let openRelays = $state<Record<string, boolean>>({})

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
  // Still-unresolved requests, surfaced in a prominent banner so they aren't
  // missed in the activity stream.
  const pendingApprovals = $derived(approvals.filter((a) => !a.resolved))
  // Repeated identical events (e.g. periodic "peer online" announcements) are
  // coalesced into one line with a count so real signal isn't buried.
  type CountedLog = LogEvent & { count: number; ts: number }
  let logs = $state<CountedLog[]>([])

  let importData = $state('')
  let importPass = $state('')
  let importName = $state('')
  let importing = $state(false)
  let importMsg = $state<string | null>(null)
  let importOk = $state(false)

  // undefined = status not yet loaded (interaction disabled until known).
  let signingEnabled = $state<boolean | undefined>(undefined)
  // Set once the active share is deleted: signing is locked off until a restart.
  let signerRetired = $state(false)
  let signingLoadError = $state<string | null>(null)
  let signingLog = $state<SigningEntry[]>([])
  let signingVerified = $state(true)
  let wsConnected = $state(false)

  // One row per signing session (the raw log has 3+ operations each). Status is
  // "signed" once a SignatureCompleted entry exists, otherwise "in progress".
  type SigningSession = {
    session: string
    participants: number[]
    completed: boolean
    latest: number
  }
  const signingSessions = $derived.by<SigningSession[]>(() => {
    const byId = new Map<string, SigningSession>()
    for (const e of signingLog) {
      const g = byId.get(e.session) ?? {
        session: e.session,
        participants: e.participants,
        completed: false,
        latest: e.timestamp_ms,
      }
      if (e.operation === 'SignatureCompleted') g.completed = true
      g.latest = Math.max(g.latest, e.timestamp_ms)
      byId.set(e.session, g)
    }
    return [...byId.values()].sort((a, b) => b.latest - a.latest)
  })

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

  function shortNpub(npub: string): string {
    return npub.length > 24 ? `${npub.slice(0, 12)}…${npub.slice(-6)}` : npub
  }

  // Ticks so relative timestamps stay current without a new event.
  let nowTick = $state(Date.now())
  $effect(() => {
    const t = setInterval(() => (nowTick = Date.now()), 30000)
    return () => clearInterval(t)
  })

  // Relative time for activity/log rows; full timestamp shown on hover.
  function relTime(ms: number): string {
    const s = Math.max(0, Math.round((nowTick - ms) / 1000))
    if (s < 5) return 'just now'
    if (s < 60) return `${s}s ago`
    const m = Math.round(s / 60)
    if (m < 60) return `${m}m ago`
    const h = Math.round(m / 60)
    if (h < 24) return `${h}h ago`
    return new Date(ms).toLocaleDateString()
  }

  // Surface pending approvals in the tab title so a backgrounded tab still
  // shows that a co-sign decision is waiting.
  $effect(() => {
    if (typeof document !== 'undefined') {
      document.title = pendingApprovals.length
        ? `(${pendingApprovals.length}) Approval needed — Keep`
        : 'Keep'
    }
  })

  // Shares grouped by their FROST group, so a vault holding more than one
  // group renders as separate sections instead of one flat pile.
  let groupedShares = $derived.by(() => {
    const m = new Map<string, Share[]>()
    for (const s of shares) {
      const list = m.get(s.group) ?? []
      list.push(s)
      m.set(s.group, list)
    }
    return [...m.entries()].map(([group, items]) => ({ group, items }))
  })

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

  // A network-level fetch failure (server briefly down, e.g. during a restart)
  // surfaces as "TypeError: Failed to fetch"; show something reassuring rather
  // than a raw error, since the WebSocket auto-reconnect will recover it.
  function friendlyError(e: unknown): string {
    return String(e).includes('Failed to fetch')
      ? 'Cannot reach the service. It may be restarting; reconnecting…'
      : String(e)
  }

  function refreshShares() {
    getShares()
      .then((s) => (shares = s))
      .catch((e) => {
        if (!handleUnauthorized(e)) error = friendlyError(e)
      })
  }

  function refreshSigningLog() {
    getSigningLog()
      .then((r) => {
        signingLog = r.entries
        signingVerified = r.verified
      })
      .catch(() => {})
  }

  function exportSigningLog() {
    const data = JSON.stringify(
      { verified: signingVerified, exported_at: new Date().toISOString(), entries: signingLog },
      null,
      2,
    )
    const url = URL.createObjectURL(new Blob([data], { type: 'application/json' }))
    const a = document.createElement('a')
    a.href = url
    a.download = `keep-signing-log-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  async function toggleKillswitch() {
    try {
      const status = await setKillswitch(!signingEnabled)
      signingEnabled = status.enabled
      signerRetired = status.retired
    } catch (e) {
      error = String(e)
    }
  }

  async function confirmDelete(s: Share) {
    if (!confirm(`Delete share "${s.name}" (${s.identifier})? This cannot be undone.`))
      return
    try {
      await deleteShare(s.group, s.identifier)
      // Clear the post-import "restart to come online" notice: it's stale once
      // the share is gone.
      importOk = false
      // Deleting the active share retires the signer; refresh the full state
      // (not just the share list) so the killswitch/retired status updates too.
      refreshState()
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
      // Export marks the share backed up server-side; refresh to clear the badge.
      refreshShares()
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
      error = 'Authentication required. Enter your Web Admin password.'
      return true
    }
    return false
  }

  // Re-fetch all the snapshot state. Safe to call repeatedly; used on first
  // load and again whenever the connection is re-established (e.g. after the
  // service restarts), so the page recovers without a manual reload.
  function refreshState() {
    getBunker()
      .then((b) => {
        bunker = b
        error = null
      })
      .catch((e) => {
        if (!handleUnauthorized(e)) error = friendlyError(e)
      })
    refreshShares()
    getKillswitch()
      .then((s) => {
        signingEnabled = s.enabled
        signerRetired = s.retired
        signingLoadError = null
      })
      .catch((err) => {
        if (handleUnauthorized(err)) return
        signingEnabled = undefined
        signingLoadError = String(err)
      })
    refreshSigningLog()
  }

  function load() {
    refreshState()

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
          const head = logs[0]
          if (
            head &&
            head.app === e.app &&
            head.action === e.action &&
            head.detail === e.detail &&
            head.success === e.success
          ) {
            logs[0] = { ...head, count: head.count + 1, ts: Date.now() }
          } else {
            logs = [{ ...e, count: 1, ts: Date.now() }, ...logs].slice(0, 100)
          }
          // A co-sign just happened: refresh the persistent audit log.
          if (e.app === 'frost') refreshSigningLog()
        }
      },
      (connected) => {
        // Connection just came back (e.g. after a restart): refresh the
        // snapshot state so the page reflects the new mode/shares.
        if (connected && !wsConnected) refreshState()
        wsConnected = connected
      },
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

{#snippet tip(text: string)}
  <span class="tip" data-tip={text} role="img" aria-label={text}>
    <svg viewBox="0 0 16 16" width="12" height="12" aria-hidden="true">
      <circle cx="8" cy="8" r="7" fill="none" stroke="currentColor" stroke-width="1.3" />
      <circle cx="8" cy="4.7" r="0.95" fill="currentColor" />
      <rect x="7.1" y="6.7" width="1.8" height="5" rx="0.9" fill="currentColor" />
    </svg>
  </span>
{/snippet}

{#snippet copyField(label: string, value: string, hint: string)}
  <div class="field">
    <span class="field-label">
      {label}{@render tip(hint)}
    </span>
    <button
      class="field-value copyable"
      title="Click to copy"
      onclick={() => copy(value, 'f' + value)}
    >
      <span class="cv-text">{value}</span>
      <span class="cv-icon" class:done={copied === 'f' + value}>
        {copied === 'f' + value ? '✓ copied' : 'copy'}
      </span>
    </button>
  </div>
{/snippet}

{#snippet relayGroup(label: string, hint: string, relays: string[], key: string)}
  {@const open = openRelays[key] ?? relays.length === 1}
  <div class="field relay-field">
    <button
      class="relay-head"
      aria-expanded={open}
      onclick={() => (openRelays[key] = !open)}
    >
      <span class="field-label">
        {label} · {relays.length}{@render tip(hint)}
      </span>
      <span class="chev" class:open>▸</span>
    </button>
    {#if open}
      <div class="relay-list">
        {#each relays as r (r)}
          <button
            class="field-value copyable relay-item"
            title="Click to copy"
            onclick={() => copy(r, 'r' + r)}
          >
            <span class="cv-text">{r}</span>
            <span class="cv-icon" class:done={copied === 'r' + r}>
              {copied === 'r' + r ? '✓ copied' : 'copy'}
            </span>
          </button>
        {/each}
      </div>
    {/if}
  </div>
{/snippet}

<header class="topbar">
  <img class="logo" src={crest} alt="Keep" />
  <div class="brand">
    <span class="brand-name">Keep</span>
    <span class="brand-sub">FROST threshold co&#8209;signer</span>
  </div>
  {#if bunker}
    <span class="mode-pill {bunker.mode === 'network-frost' ? 'on' : 'warn'}">
      {bunker.mode === 'network-frost'
        ? 'co-signer online'
        : bunker.mode === 'setup'
          ? 'setup'
          : 'single-key'}
    </span>
  {/if}
</header>

<main>
  {#if error}
    <p class="fail banner">{error}</p>
  {/if}

  {#if authed && pendingApprovals.length}
    <div class="approval-bar" role="alert" aria-live="assertive">
      {#each pendingApprovals as a (a.id)}
        <div class="approval-bar-row">
          <span class="approval-bar-text">
            <strong>{a.app}</strong> requests <strong>{a.method}</strong>{#if a.kind !== null}
              · kind {a.kind}{/if}
            {#if a.preview}<span class="muted"> · {a.preview}</span>{/if}
          </span>
          <span class="approval-bar-actions">
            <button class="ok" onclick={() => decide(a, true)}>Approve</button>
            <button class="no" onclick={() => decide(a, false)}>Deny</button>
          </span>
        </div>
      {/each}
    </div>
  {/if}

  {#if !authed}
    <div class="panel setup">
      <strong>🔒 Sign in</strong>
      <p>
        Enter your Web Admin password. Find your username and password under the <span
          class="token">Show Login Credentials</span
        > action.
      </p>
      <form onsubmit={(e) => (e.preventDefault(), submitToken())}>
        <input type="text" value="admin" readonly autocomplete="username" aria-label="Username" />
        <input
          type="password"
          placeholder="password"
          bind:value={tokenInput}
          autocomplete="current-password"
          aria-label="Password"
        />
        <button type="submit" disabled={!tokenInput.trim()}>Sign in</button>
      </form>
    </div>
  {:else}
  {#if bunker && bunker.mode === 'setup'}
    <div class="panel setup">
      {#if shares.length > 0}
        <strong>⚙ Almost done — restart to finish.</strong>
        <p>
          Your share is imported, but the co-signer hasn't started yet.
          <strong>Restart the service</strong> to bring it online (on StartOS, use the
          <strong>Restart</strong> button on this service's page). The connection details
          appear here once it's up.
        </p>
      {:else}
        <strong>⚙ Setup required.</strong> No FROST share is loaded yet; this node
        isn't signing.
        <h3>Tasks to finish setup</h3>
        <ol class="tasks">
          <li>Import your FROST share below (export it from the device that holds it).</li>
          <li>
            Open the <strong>Configure</strong> action and set <strong>FROST Relays</strong>
            to match the relays your other share-holders use.
          </li>
          <li>
            <strong>Restart the service</strong> to start the co-signer. On StartOS, use the
            <strong>Restart</strong> button on this service's page; this page then shows the
            connection details.
          </li>
          <li>
            Copy the bunker connection string (shown here after restart) into your
            Nostr client.
          </li>
        </ol>
      {/if}
    </div>
  {/if}

  {#if bunker && bunker.mode !== 'setup' && signerRetired}
    <div class="panel disabled-banner">
      <div>
        <strong>⚠ Co-signer retired.</strong>
        The active share was deleted, so this node will <strong>not sign</strong>.
        <strong>Restart the service</strong> to finalize (on StartOS, use the
        <strong>Restart</strong> button on this service's page). It then comes back using
        any remaining shares, or in setup mode if none are left.
      </div>
    </div>
  {:else if bunker && bunker.mode !== 'setup' && signingEnabled === false}
    <div class="panel disabled-banner">
      <div>
        <strong>⏸ Co-signing is disabled.</strong>
        This node is online but will <strong>not sign</strong> until you enable it.
      </div>
      <button class="ok" onclick={toggleKillswitch}>Enable signing</button>
    </div>
  {/if}

  <h2>Connection</h2>
  <div class="panel">
    {#if bunker}
      <div class="conn-status">
        {#if bunker.mode === 'setup'}
          <span class="dot warn"></span>
          {#if shares.length > 0}
            <span>Share imported. Restart the service to bring the co-signer online.</span>
          {:else}
            <span>Not signing yet. Import a share, then restart to begin.</span>
          {/if}
        {:else if signerRetired}
          <span class="dot warn"></span>
          <span>Active share deleted. <strong>Restart the service</strong> to finalize.</span>
        {:else if signingEnabled === false}
          <span class="dot warn"></span>
          <span>Online, but <strong>co-signing is off</strong>. It won't sign until you enable it.</span>
        {:else if bunker.mode === 'single-key'}
          <span class="dot warn"></span>
          <span>Single-key mode (no threshold security).</span>
        {:else}
          <span class="dot ok"></span>
          <span>Co-signer online and coordinating with your devices.</span>
        {/if}
      </div>
      {#if bunker.mode === 'setup'}
        <p class="muted setup-hint">
          Once your share is imported and the service is restarted, this card
          shows the bunker connection string, the group it co-signs for, and the
          relays it uses.
        </p>
      {/if}
      {#if bunker.threshold}
        <div class="kv">
          <span>
            threshold{@render tip(
              'Signatures required to sign, out of the total shares (e.g. 2-of-3).',
            )}
          </span>
          <strong>{bunker.threshold}</strong>
        </div>
      {/if}
      {#if bunker.group}
        {@render copyField(
          'group',
          bunker.group,
          'The FROST group this node co-signs for (its public key / npub).',
        )}
      {/if}
      {#if bunker.npub}
        {@render copyField('npub', bunker.npub, "This signer node's own public key.")}
      {/if}
      {#if bunker.url}
        {@render copyField(
          'bunker',
          bunker.url,
          'NIP-46 connection string. Paste this into a Nostr client to sign through this node.',
        )}
      {/if}
      {#if bunker.bunker_relays.length}
        {@render relayGroup(
          'Bunker relays',
          'Relays where Nostr clients reach the bunker.',
          bunker.bunker_relays,
          'bunker',
        )}
      {/if}
      {#if bunker.frost_relays.length}
        {@render relayGroup(
          'FROST relays',
          'Relays used to coordinate signing rounds with your other devices. Must match the relays they use.',
          bunker.frost_relays,
          'frost',
        )}
      {/if}
      {#if bunker.mode !== 'setup'}
        <div class="kv killswitch">
          <span>
            co-signing{@render tip(
              'When off, this node refuses to join signing rounds (a kill switch). New installs start off until you enable it.',
            )}
          </span>
          {#if signingEnabled === undefined}
            <span class="status-pill warn">unknown</span>
          {:else if signerRetired}
            <span class="status-pill off">Retired</span>
            <span class="muted">restart to finalize</span>
          {:else}
            <span class="status-pill {signingEnabled ? 'on' : 'off'}">
              {signingEnabled ? 'Enabled' : 'Disabled'}
            </span>
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
  {#each groupedShares as g (g.group)}
    <div class="panel group-panel">
      <div class="group-head">
        <span class="group-label">Group</span>
        <button
          class="group-npub copyable"
          title="Click to copy the full group npub"
          onclick={() => copy(g.group, 'g' + g.group)}
        >
          {copied === 'g' + g.group ? '✓ copied' : shortNpub(g.group)}
        </button>
        <span class="share-tag">{g.items[0].threshold}-of-{g.items[0].total_shares}</span>
        {#if bunker?.group === g.group}
          <span class="badge active-badge">active co-signer</span>
        {/if}
      </div>
      {#each g.items as s (s.identifier)}
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
              <div class="share-head">
                <span class="share-name">{s.name}</span>
                <span class="share-idx">#{s.identifier}</span>
                {#if !s.did_backup}<span
                    class="badge warn-badge"
                    title="This share hasn't been exported anywhere. Export it (below) to back it up; the badge clears once you do."
                    >not backed up</span
                  >{/if}
              </div>
            {/if}
            <dl class="meta-grid">
              <div><dt>Signatures</dt><dd>{s.sign_count}</dd></div>
              <div><dt>Created</dt><dd>{fmtDate(s.created_at)}</dd></div>
              <div>
                <dt>Last used</dt>
                <dd>
                  {#if s.last_used}{fmtDate(s.last_used)}{:else}<span class="never">never</span>{/if}
                </dd>
              </div>
            </dl>
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
              <span class="muted">Encrypted export (back this up):</span>
              <button
                class="field-value copyable export-value"
                title="Click to copy"
                onclick={() => copy(exportResult, 'export')}
              >
                <span class="cv-text">{exportResult}</span>
                <span class="cv-icon" class:done={copied === 'export'}>
                  {copied === 'export' ? '✓ copied' : 'copy'}
                </span>
              </button>
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
      {/each}
    </div>
  {:else}
    <div class="panel"><p class="muted">No shares imported yet.</p></div>
  {/each}

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
          {#if bunker?.mode === 'setup'}
            <span>
              The co-signer isn't running yet. <strong>Restart the service</strong> to bring
              it online (on StartOS, use the <strong>Restart</strong> button on this service's
              page). The connection details appear here once it's up.
            </span>
          {:else}
            <span>It's saved to the vault. The running co-signer is unaffected.</span>
          {/if}
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
    {#each approvals.filter((a) => a.resolved) as a (a.id)}
      <div class="event approval">
        <span><strong>{a.app}</strong> requested {a.method}</span>
        <span class="muted">→ {a.resolved}</span>
      </div>
    {/each}
    {#each logs as l, i (i)}
      <div class="event">
        <strong>{l.app}</strong>: {l.action}
        <span class:fail={!l.success}>{l.success ? '✓' : '✗'}</span>
        {#if l.count > 1}<span class="count-badge">×{l.count}</span>{/if}
        {#if l.detail}<span class="muted"> · {l.detail}</span>{/if}
        <span class="muted row-time" title={new Date(l.ts).toLocaleString()}>
          · {relTime(l.ts)}
        </span>
      </div>
    {/each}
    {#if approvals.every((a) => !a.resolved) && logs.length === 0}
      <p class="muted">Waiting for signing activity…</p>
    {/if}
  </div>

  <h2>
    Signing Log
    {#if signingLog.length}
      <span class="verify {signingVerified ? 'ok' : 'fail'}">
        {signingVerified ? '✓ chain verified' : '✗ chain INVALID'}
      </span>
      <button class="link-btn" onclick={exportSigningLog}>Export</button>
    {/if}
  </h2>
  <div class="panel">
    {#each signingSessions as s (s.session)}
      <div class="event">
        <span class="token">{s.session}</span>
        <span class="verify {s.completed ? 'ok' : 'warn'}">
          {s.completed ? '✓ signed' : '… in progress'}
        </span>
        <span class="muted" title={new Date(s.latest).toLocaleString()}>
          · participants {s.participants.join(',')} · {relTime(s.latest)}
        </span>
      </div>
    {:else}
      <p class="muted">No signatures recorded yet.</p>
    {/each}
  </div>
  {/if}
</main>
