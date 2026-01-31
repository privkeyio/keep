# Security Review: Warden Policy Integration

**Date:** 2026-01-31  
**Branch:** feat/warden-policy-mobile  
**Reviewer:** Claude Opus 4.5 (automated security agent)  
**Scope:** keep-mobile policy enforcement, warden core/api integration

## Executive Summary

The Warden policy enforcement integration introduces a client-side policy engine in keep-mobile that evaluates transaction rules before allowing signatures. While the implementation demonstrates good security practices in several areas (signature verification with constant-time comparison, proper input validation, forbid(unsafe_code)), several critical issues were identified that could allow policy bypass.

## Files Reviewed

### keep-mobile (changed files)
- `/home/kyle/Documents/GitHub/keep/keep-mobile/src/policy.rs` - Policy bundle parsing, signature verification, rule evaluation
- `/home/kyle/Documents/GitHub/keep/keep-mobile/src/velocity.rs` - Transaction rate limiting
- `/home/kyle/Documents/GitHub/keep/keep-mobile/src/lib.rs` - Main integration, policy evaluator initialization
- `/home/kyle/Documents/GitHub/keep/keep-mobile/src/error.rs` - Error types

### warden (supporting context)
- `/home/kyle/Documents/GitHub/warden/warden-core/src/bundle.rs` - Server-side bundle verification
- `/home/kyle/Documents/GitHub/warden/warden-core/src/evaluator.rs` - Server-side policy evaluation
- `/home/kyle/Documents/GitHub/warden/warden-core/src/policy.rs` - Policy data structures
- `/home/kyle/Documents/GitHub/warden/warden-api/src/auth.rs` - JWT authentication with replay protection
- `/home/kyle/Documents/GitHub/warden/warden-core/src/ssrf.rs` - SSRF protection for webhook URLs
- `/home/kyle/Documents/GitHub/warden/warden-core/src/secrets.rs` - Secret management with SSRF validation

---

## Critical Findings

### 1. Policy Not Persisted - DoS/Bypass Risk
**File:** `/home/kyle/Documents/GitHub/keep/keep-mobile/src/lib.rs:113-114`  
**Beads Issue:** keep-7ko

The PolicyEvaluator and VelocityTracker are stored only in memory:
```rust
policy: Arc<std::sync::RwLock<PolicyEvaluator>>,
velocity: Arc<std::sync::Mutex<VelocityTracker>>,
```

**Risk:** Application restart clears all policies and velocity tracking. An attacker who can trigger app termination (crash, force-quit, battery drain) can:
1. Bypass policy enforcement entirely (no policy = allow all)
2. Reset daily/weekly spending limits

**Fix:** Persist policy bundles and velocity data to `SecureStorage`. Load on initialization.

### 2. Missing Warden Public Key Pinning
**File:** `/home/kyle/Documents/GitHub/keep/keep-mobile/src/policy.rs:196-217`  
**Beads Issue:** keep-v4n

Policy signature verification extracts the public key from the bundle itself:
```rust
pub fn verify_signature(&self) -> Result<(), KeepMobileError> {
    let verifying_key = VerifyingKey::from_bytes(&self.warden_pubkey).map_err(...)?;
    // ... verifies signature using this key
}
```

**Risk:** An attacker who can deliver a rogue policy bundle can sign it with their own key. The signature will verify successfully because the verification uses the attacker's public key embedded in the bundle.

**Fix:** Add a trusted warden public key registry to the app. During `import_policy()`, verify that `bundle.warden_pubkey` matches one of the trusted keys before accepting.

### 3. Address Comparison Case Sensitivity
**File:** `/home/kyle/Documents/GitHub/keep/keep-mobile/src/policy.rs:411-428`  
**Beads Issue:** keep-0ly

Whitelist/blacklist checks use case-sensitive string comparison:
```rust
if !whitelist.contains(dest) {
    return Ok(PolicyDecision::Deny { ... });
}
```

**Risk:** Bitcoin Bech32 addresses are case-insensitive. An attacker could bypass a blocklist entry for `bc1qmalicious...` by sending to `bc1Qmalicious...` or `BC1QMALICIOUS...`.

**Fix:** Normalize addresses to lowercase before comparison:
```rust
if !whitelist.iter().any(|w| w.to_lowercase() == dest.to_lowercase()) {
```

---

## High Findings

### 4. Velocity Tracker Not Persisted
**File:** `/home/kyle/Documents/GitHub/keep/keep-mobile/src/velocity.rs`  
**Beads Issue:** keep-kg2

Same as policy persistence issue. Daily/weekly limits are tracked in memory only.

**Risk:** Limit bypass via app restart.

---

## Medium Findings

### 5. No Policy Rollback Protection
**File:** `/home/kyle/Documents/GitHub/keep/keep-mobile/src/policy.rs`  
**Beads Issue:** keep-1uo

Unlike warden's `BundleLoader` which implements `is_version_newer()`, keep-mobile accepts any valid policy regardless of version.

**Risk:** An attacker could replay an older, more permissive policy bundle.

**Fix:** Store the last accepted policy version and reject bundles with equal or lower versions.

### 6. Policy Timestamp Not Validated
**File:** `/home/kyle/Documents/GitHub/keep/keep-mobile/src/policy.rs:141-150`  
**Beads Issue:** keep-8u7

The `created_at` field is parsed but never validated:
```rust
let created_at = u64::from_le_bytes([...]);
```

**Risk:** Replay attacks with old policies, or policies dated in the future.

**Fix:** Validate that `created_at` is within a reasonable window (e.g., not older than current policy, not in the future).

### 7. Denial Reasons May Leak Policy Details
**File:** `/home/kyle/Documents/GitHub/keep/keep-mobile/src/policy.rs:312-428`  
**Beads Issue:** keep-bc2

Denial messages reveal specific policy configuration:
```rust
reason: format!(
    "Amount {} sats exceeds maximum {} sats",
    ctx.amount_sats, max_amount
),
```

**Risk:** Information disclosure helps attackers understand policy structure and craft evasion strategies.

**Fix:** Return generic denial messages to external callers; log detailed reasons internally.

### 8. Potential Panic in DKG Module
**File:** `/home/kyle/Documents/GitHub/keep/keep-mobile/src/dkg.rs:394-395`  
**Beads Issue:** keep-jxb

```rust
33 => vk_bytes[1..33].try_into().unwrap(),
32 => vk_bytes.try_into().unwrap(),
```

**Risk:** DoS via malformed DKG package.

**Fix:** Use fallible conversion with error handling.

---

## Positive Observations

The codebase demonstrates several security best practices:

1. **Forbid Unsafe Code:** All modules use `#![forbid(unsafe_code)]`

2. **Constant-Time Comparison:** Hash verification uses `subtle::ConstantTimeEq`:
   ```rust
   if !bool::from(computed.ct_eq(&self.policy_hash)) {
   ```

3. **Input Size Limits:** Policy parsing enforces maximum sizes:
   ```rust
   pub const POLICY_MAX_RULES_LEN: usize = 2048;
   ```

4. **Saturating Arithmetic:** Velocity tracking avoids overflow:
   ```rust
   .fold(0u64, |acc, amt| acc.saturating_add(amt))
   ```

5. **SSRF Protection (warden):** Comprehensive validation of webhook URLs with blocklisted hostnames and IP ranges

6. **JWT Replay Protection (warden):** JTI cache prevents token replay attacks

7. **Secret Redaction (warden):** SecretValue type prevents accidental logging

8. **DoS Protection:** Evaluation limits prevent rule explosion attacks:
   ```rust
   const MAX_RULES_PER_EVALUATION: usize = 256;
   const MAX_NESTING_DEPTH: usize = 10;
   ```

---

## Recommendations Summary

| Priority | Issue | Action |
| --- | --- | --- |
| Critical | Policy not persisted | Add persistence to SecureStorage |
| Critical | No pubkey pinning | Add trusted warden key registry |
| Critical | Case-sensitive addresses | Normalize to lowercase |
| High | Velocity not persisted | Add persistence to SecureStorage |
| Medium | No rollback protection | Track and enforce policy versions |
| Medium | Timestamp not validated | Add time bounds validation |
| Medium | Verbose denial messages | Use generic external messages |
| Low | Potential panic in DKG | Use fallible conversion |

---

## Dependency Notes

`cargo audit` was not available. Recommend running:
```bash
cargo install cargo-audit
cargo audit
```

---

## Beads Issues Created

- keep-7ko: Policy not persisted (P0)
- keep-kg2: Velocity tracker not persisted (P0)
- keep-v4n: Missing warden pubkey pinning (P0)
- keep-0ly: Address comparison case sensitivity (P0)
- keep-8u7: Policy timestamp not validated (P2)
- keep-bc2: Denial reason info disclosure (P2)
- keep-1uo: Policy rollback protection (P2)
- keep-jxb: Potential panic in DKG (P2)
