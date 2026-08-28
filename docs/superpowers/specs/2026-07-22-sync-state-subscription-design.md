# Sync State Subscription Design

NEVER ADD/PUSH TO GIT

**Status:** Proposed for final review

**Date:** 2026-07-22

## Summary

Replace wallet-side stdout parsing with a node-owned finite-state machine that exposes the current synchronization phase and its progress. The node provides both a unary snapshot and a change-only subscription. A process-wide state holder uses three atomics: one `AtomicU8` for the phase and two `AtomicU64`s for progress.

The FSM has a single visible critical-path phase. The outer IBD flow owns normal transitions. Synchronous consensus-reset boundaries may transfer ownership to one of two distinct UTXO-index rebuild phases. Inner processors receive generation-scoped tokens and can update progress, but cannot select a phase or overwrite a later generation.

## Motivation

`wallet/core/src/utxo/sync.rs` currently derives detailed sync state by matching log lines with regular expressions. This is explicitly marked temporary and has several shortcomings:

- log messages are not an API contract;
- progress disappears when the wallet cannot observe local node stdout;
- independently emitted log lines have no common transition or overlap policy;
- a subscriber cannot obtain an authoritative initial snapshot;
- new phases, including SMT import, require coordinated log and regex changes.

[PR #244](https://github.com/kaspanet/rusty-kaspa/pull/244) implemented direct `SyncStateChanged` notifications from each inner subsystem. That proves the required RPC plumbing, but it lets unrelated publishers replace one another without centralized ownership, does not provide a unary detailed snapshot, and predates the current SMT and readiness logic.

[PR #654](https://github.com/kaspanet/rusty-kaspa/pull/654) established the process-wide injection pattern used by `ProcessingCounters` and separated mining permission from the stricter node-sync predicate. This design follows the same injection pattern while reporting synchronization work independently of mining-rule decisions.

## Goals

- Represent node synchronization as an authoritative FSM.
- Report pruning-proof, trusted-block, header, SMT, UTXO-set, UTXO-index, body, and post-processing work.
- Distinguish remote pruning-point UTXO-set synchronization from local UTXO-index rebuilding.
- Distinguish the UTXO-index rebuild performed during staging-consensus commit from the rebuild performed after replacing the pruning-point UTXO set.
- Keep state reads cheap and coherent using three atomics.
- Prevent delayed or parallel inner work from moving progress into a newer phase.
- Preserve the existing `GetSyncStatus` boolean helper while adding a detailed snapshot.
- Provide a change-only subscription with immediate phase events and coalesced progress events.
- Support race-free subscription bootstrap.
- Remove stdout regex observation after wallet/client integration is complete.

## Non-goals

- Persist sync state or progress across process restarts.
- Return phase history or timing estimates.
- Expose more than one simultaneous visible phase.
- Estimate totals that the protocol cannot determine cheaply and authoritatively.
- Report background consensus work that does not gate completion of the current sync operation.
- Change the mining-rule engine or its mining-permission semantics.
- Add a durable failure-reason API. Existing errors and logs remain authoritative for failures.

## Public state model

The public model is typed; callers do not consume raw atomic values.

```rust
pub struct SyncProgress {
    pub current: u64,
    pub total: Option<NonZeroU64>,
}

pub enum SyncState {
    NotSynced,
    Negotiating,
    PruningProof(SyncProgress),
    TrustedBlocks(SyncProgress),
    Headers(SyncProgress),
    CommittingConsensus,
    StagingUtxoIndexResync(SyncProgress),
    ApplyingPruningPoint,
    SmtState(SyncProgress),
    UtxoSetSync(SyncProgress),
    PruningPointUtxoIndexResync(SyncProgress),
    BlockBodies(SyncProgress),
    RevalidatingOrphans(SyncProgress),
    Synced,
}

impl SyncState {
    pub fn is_synced(&self) -> bool {
        matches!(self, Self::Synced)
    }
}
```

Only `Synced` is synced. Every active phase, including both UTXO-index rebuild phases, returns `false` from `is_synced()`.

The two index states have deliberately different meanings:

- `StagingUtxoIndexResync` rebuilds the optional index after a staging consensus becomes active during headers-proof IBD.
- `PruningPointUtxoIndexResync` rebuilds it after the downloaded pruning-point UTXO set replaces the current set.

Clients must not compare enum discriminants to infer progress. The valid phase order depends on the selected IBD branch. Monotonicity is represented by phase generation and notification sequence, and each resync occurrence has a unique state.

## Three-atomic representation

```rust
pub struct AtomicSyncState {
    phase: AtomicU8,
    current: AtomicU64,
    total: AtomicU64,
}
```

### Phase word

`phase` stores an internal `#[repr(u8)]` phase value. `255` is reserved for the private `Transitioning` marker and is never exposed through RPC.

Normal phase changes have one primary writer: the IBD orchestration path. A synchronous reset-handler call site may take ownership at the exact point where the outer operation invokes the handler. Those transfers are synchronous and awaited.

### Packed progress words

Both progress words use the same layout:

```text
63                         40 39                          0
+----------------------------+-----------------------------+
| 24-bit phase generation    | 40-bit progress value       |
+----------------------------+-----------------------------+
```

The 40-bit value range is sufficient for DAA spans, block counts, UTXO counts, and SMT lane counts. Reporting code clamps larger values to the maximum representable value; observability must never fail IBD.

The low 40 bits of `total` use zero as the unknown-total sentinel. A phase with zero work is skipped rather than entered, making zero unambiguous. The typed snapshot converts zero to `None` and a non-zero value to `Some(NonZeroU64)`.

### Entering a phase

Entering a phase requires the caller to name the expected predecessor phase. It performs these operations:

1. Claim writer ownership with `phase.compare_exchange(expected, Transitioning, AcqRel, Acquire)`.
2. Increment the 24-bit generation, skipping zero after wrap.
3. Store the new generation and initial current value in `current`.
4. Store the same generation and total-or-zero value in `total`.
5. Store the new phase with release ordering.
6. Return `SyncProgressToken { phase, generation }` for measured phases.

Only the successful claimant writes either progress word or the final phase. A failed claim returns the observed phase without changing state. This serializes the otherwise independent IBD owner, terminal-readiness worker, and synchronous reset boundaries while keeping the representation to three atomics.

The IBD path normally supplies its immediately preceding phase as `expected`. The terminal-readiness worker may claim only `Synced` or `NotSynced`; it cannot replace an active phase. If its terminal refresh wins just as a new IBD attempt starts, the IBD owner reloads the terminal phase and retries its initial transition. A reset boundary requires its exact expected predecessor (`CommittingConsensus` for the staging rebuild and `UtxoSetSync` for the pruning-point rebuild). A rejected instrumentation transition is logged and IBD continues without a progress token; observability must never fail synchronization or overwrite a newer owner.

Direct re-entry into the same phase is safe because it receives a new generation. The two body searches at the end of IBD share one `BlockBodies` phase and one aggregate token rather than entering `BlockBodies` twice.

### Reading a snapshot

A reader:

1. loads `phase` with acquire ordering;
2. retries if it is `Transitioning`;
3. loads `current` and `total`;
4. loads `phase` again with acquire ordering;
5. accepts the snapshot only if both phase reads match and both packed generations match.

Progress updates change only `current`; `total` is immutable for a phase generation. Therefore an accepted snapshot is coherent without a mutex or a fourth state atomic.

### Progress tokens

A token contains only the expected phase and generation. A progress update verifies both and uses compare-and-swap on the packed `current` word while preserving its generation bits. It returns `false` without writing when the phase or generation no longer matches.

This prevents:

- a delayed callback from a completed phase updating the next phase;
- an earlier instance of a repeated operation updating a later generation;
- concurrent inner workers replacing the phase;
- a synchronous reset handler overwriting a phase that has already advanced.

Inner workers may call `advance(delta)` or `set_current(value)`. Aggregation belongs to the phase owner; inner code does not select the next phase.

## FSM paths

Question marks below mean the phase is skipped when the corresponding data is already stable. An asterisk means the phase exists only when `--utxoindex` is enabled.

### Headers-proof IBD

```text
NotSynced
  -> Negotiating
  -> PruningProof
  -> TrustedBlocks
  -> Headers
  -> CommittingConsensus
  -> StagingUtxoIndexResync*
  -> SmtState
  -> UtxoSetSync
  -> PruningPointUtxoIndexResync*
  -> BlockBodies
  -> RevalidatingOrphans
  -> Synced | NotSynced
```

`StagingConsensus::commit()` currently invokes consensus-reset handlers synchronously. Installing the downloaded pruning-point UTXO set invokes them again later. The distinct states above preserve a forward-only observable path rather than emitting the same resync state twice or restoring an earlier phase.

### Resume or ordinary IBD

```text
NotSynced
  -> Negotiating
  -> TrustedBlocks?
  -> SmtState?
  -> UtxoSetSync?
  -> PruningPointUtxoIndexResync?*
  -> Headers
  -> BlockBodies
  -> RevalidatingOrphans
  -> Synced | NotSynced
```

### Pruning catch-up

```text
NotSynced
  -> Negotiating
  -> Headers
  -> ApplyingPruningPoint
  -> TrustedBlocks
  -> SmtState
  -> UtxoSetSync
  -> PruningPointUtxoIndexResync*
  -> BlockBodies
  -> RevalidatingOrphans
  -> Synced | NotSynced
```

### Terminal refresh

After an IBD attempt, the outer flow evaluates the same readiness conditions currently used by `GetSyncStatus`: recent sink, sufficient peer connectivity, and no transitional consensus state. Success selects `Synced` only when all conditions hold; otherwise it selects `NotSynced`.

While the FSM is terminal, a lightweight status worker re-evaluates readiness every two seconds. It may transition `Synced <-> NotSynced` as connectivity or sink recency changes. It never overwrites an active phase.

“Immediate” terminal publication means immediately after this worker detects the readiness change; its detection latency is bounded by the two-second refresh interval.

## Progress semantics

| State | `current` | `total` |
|---|---|---|
| `PruningProof` | Completed proof levels | Number of proof levels |
| `TrustedBlocks` | Processed trusted blocks or trusted bodies | Exact work-set size |
| `Headers` | Covered DAA-score span from the shared header | Fixed target DAA-score span |
| `StagingUtxoIndexResync` | Indexed UTXOs | Unknown unless a cheap authoritative total exists |
| `SmtState` | Imported SMT lanes | Metadata `active_lanes_count` |
| `UtxoSetSync` | Received and imported UTXOs | Unknown because the wire protocol supplies no upfront count |
| `PruningPointUtxoIndexResync` | Indexed UTXOs | Unknown unless a cheap authoritative total exists |
| `BlockBodies` | Processed bodies across both final body searches | Exact aggregate requested count |
| `RevalidatingOrphans` | Completed orphan-processing tasks | Number of queued tasks |

`Negotiating`, `CommittingConsensus`, and `ApplyingPruningPoint` have no numeric progress and therefore expose no `SyncProgress`.

SMT progress measures lanes completed by the importer, not merely downloaded from the peer. `consensus/smt-store/src/streaming_import/mod.rs` already has the correct two-second import reporting boundary and will forward the imported-lane count through the token.

## Reset-handler context

The reset-handler API gains an explicit reason:

```rust
pub enum ConsensusResetReason {
    StagingConsensusCommitted,
    PruningPointUtxoSetReplaced,
}

pub trait ConsensusResetHandler: Send + Sync {
    fn handle_consensus_reset(&self, reason: ConsensusResetReason, progress: Option<SyncProgressToken>);
}
```

Immediately before synchronous handler invocation, the owning call path enters the corresponding index phase and passes its token:

- staging commit uses `StagingConsensusCommitted` and `StagingUtxoIndexResync`;
- pruning-point UTXO replacement uses `PruningPointUtxoSetReplaced` and `PruningPointUtxoIndexResync`.

The UTXO-index handler maps the supplied reason to its expected phase for validation, reports progress through the supplied token, and never inspects other FSM phases to infer why it was called. When no UTXO index is registered, the call site skips the index phase.

## Components and ownership

### `AtomicSyncState`

Lives in `consensus/core/src/api/sync_state.rs`. It defines the internal phase representation, packed-word helpers, tokens, transition methods, and typed snapshot conversion. It has no RPC or notification dependencies.

### `SyncStateCoordinator`

Lives with consensus notification infrastructure. It wraps the atomic state and owns delivery-only metadata under a small mutex:

- latest typed snapshot and its monotonically increasing external sequence;
- last emitted sequence.

All public phase changes use `SyncStateCoordinator::transition(expected, next, progress)`. The coordinator first performs the atomic transition and then publishes the accepted phase immediately. Inner progress updates still go directly through atomic tokens and do not take this mutex.

The mutex is not used by sync processing or ordinary atomic state reads. It only orders unary snapshots against notification publication. A unary sample may discover a new typed snapshot and assign its sequence, but it never marks that sequence emitted. The publication path emits whenever the latest sequence is greater than `last_emitted`, even if a unary call discovered the snapshot first. Therefore an unrelated unary caller cannot consume a change intended for subscribers.

### IBD flow

`protocol/flows/src/ibd/flow.rs` owns the branch transitions and passes tokens into measured work. `ProgressReporter` reports header DAA coverage through its token. Body searches are aggregated into one visible phase.

### Consensus and SMT internals

Pruning-proof validation receives the proof token so each completed level advances progress. SMT streaming import receives its token and reports completed imported lanes at its existing progress boundary.

### UTXO index

The synchronous reset handler receives a reason and token. Its resync loop advances the appropriate index state without knowing the surrounding IBD branch.

### Readiness and RPC service

A status worker refreshes terminal readiness and asks the coordinator to publish coalesced progress. The unary RPC samples through the same coordinator so it can assign a sequence consistent with notifications.

### Daemon wiring

`kaspad/src/daemon.rs` creates one process-wide `Arc<AtomicSyncState>` and coordinator, following the `ProcessingCounters` injection pattern. Test constructors receive a default `NotSynced` instance.

## Unary RPC contract

The existing operation remains `GetSyncStatus`. Its response retains `is_synced` and adds the detailed state and sequence:

```rust
pub struct GetSyncStatusResponse {
    pub is_synced: bool,
    pub sync_state: Option<SyncState>,
    pub sequence: u64,
}
```

The server always returns `Some(sync_state)`. The field is optional at transport boundaries so a new client can recognize a server that predates this API revision. `is_synced` is always computed as `sync_state.is_synced()` on a new server.

The existing convenience method `get_sync_status() -> RpcResult<bool>` remains source-compatible. A new detailed helper returns the full response. The RPC API revision increases from `0` to `1`; the API version remains `1`.

Protobuf adds fields without changing the existing `isSynced = 1` tag. JSON clients tolerate the added fields. Borsh clients continue to follow the repository convention that peers use matching RPC schemas/revisions.

## Subscription contract

Add the `SyncStateChanged` event, scope, subscription command, and notification across consensus notify, RPC core, gRPC, wRPC, WASM, and client routing.

```rust
pub struct SyncStateChangedNotification {
    pub sync_state: SyncState,
    pub sequence: u64,
}
```

The boolean is not duplicated because clients derive it with `sync_state.is_synced()`.

Publication rules:

- phase transitions publish immediately;
- terminal readiness transitions publish immediately;
- progress atomics may update at processing granularity, but notifications are sampled at most once every two seconds;
- typed snapshots equal to the coordinator's latest versioned snapshot do not advance the sequence;
- unary sampling can version a new snapshot but cannot suppress its later notification;
- already emitted sequences are never emitted again;
- notification delivery failure is logged and does not affect IBD.

Subscriptions emit changes only; they do not synthesize an initial event.

### Race-free bootstrap

A client performs:

1. Start the `SyncStateChanged` subscription and buffer notifications.
2. Call `GetSyncStatus`.
3. Install the unary result as its baseline.
4. Apply buffered and future notifications with `sequence` greater than the unary sequence.
5. Discard notifications with an equal or lower sequence.

The coordinator samples and assigns sequences for both paths, so no state change can be lost between subscription activation and the unary baseline.

## Wallet and CLI migration

For servers at RPC API revision 1 or later, the wallet sync monitor uses the subscription bootstrap above and maps RPC `SyncState` directly into wallet events. Its local `is_synced` atomic is updated from `SyncState::is_synced()`.

For older servers, the wallet retains boolean polling through the existing unary method but cannot show detailed phases.

After the new path is active:

- remove `StateObserver` and all sync-state regular expressions from `wallet/core/src/utxo/sync.rs`;
- remove `SyncMonitor::handle_stdout`;
- stop forwarding node stdout to the wallet sync monitor from `cli/src/modules/node.rs`;
- retain CLI rendering by mapping the new typed states and normalized progress.

## Failure and cancellation behavior

- An expected IBD error transitions immediately to `NotSynced` after logging the underlying error.
- The IBD ownership guard resets to `NotSynced` on cancellation or unwinding when no explicit terminal transition occurred.
- A stale token is a non-error no-op.
- Progress overflow saturates and never fails synchronization.
- A closed notification path is logged and never fails synchronization.
- There is no `Failed` state; the FSM describes current work/readiness rather than retaining error history.
- Restart initializes the state to `NotSynced`; progress is reconstructed by new work.

## Concurrency analysis

Current production flow already enforces one top-level IBD through `FlowContext::try_set_ibd_running`. The major steps in `IbdFlow::ibd` are awaited sequentially. Header validation, body processing, SMT download/import, and orphan processing may pipeline work internally, but that work belongs to one visible phase token.

The phase compare-and-exchange is the final protection against independent writers. It prevents a terminal readiness refresh from overwriting newly started IBD, prevents an IBD start from trampling a refresh already being committed, and prevents a reset callback from publishing against an unexpected predecessor. The single top-level IBD guard remains the policy-level exclusion; phase ownership makes the state holder correct even at its asynchronous boundaries.

Consensus-reset handlers are synchronous by design. Their explicit reason and token create a deterministic ownership transfer rather than an overlap. The outer caller resumes only after handlers return and then advances to the next phase.

If future code truly overlaps two gating phases, the visible state remains the phase that most recently received ownership. An older phase can continue computation, but its generation token cannot update the newer snapshot. Supporting simultaneous public phases would require a different API and is outside this design.

## Testing strategy

### Atomic state unit tests

- default snapshot is `NotSynced`;
- known and unknown totals convert correctly;
- transition resets progress and increments generation;
- same-phase re-entry invalidates the previous token;
- stale tokens cannot update current progress;
- concurrent `advance` calls preserve generation and saturate the current value;
- readers never accept `Transitioning`, mismatched phases, or mismatched generations;
- competing transition writers have exactly one winner and only that winner initializes progress;
- `is_synced()` is true only for `Synced`;
- values above the 40-bit range clamp without panicking.

### Coordinator tests

- phase changes publish immediately;
- progress changes coalesce to a maximum rate of one event per two seconds;
- identical typed snapshots do not advance sequence;
- unary sampling and notifications share a monotonic sequence;
- unary discovery of a new snapshot does not suppress its pending notification;
- subscribe-then-unary bootstrap neither loses nor reorders a change;
- delivery failure does not affect atomic state.

### FSM and integration tests

- headers-proof IBD follows the complete path, including both distinct index rebuild states when enabled;
- ordinary/resume IBD skips stable phases and uses only `PruningPointUtxoIndexResync`;
- pruning catch-up reports `ApplyingPruningPoint` and the final index rebuild;
- both body searches aggregate under one `BlockBodies` generation;
- disabling the UTXO index removes both index phases;
- an IBD error and cancellation end in `NotSynced`;
- peer loss changes terminal `Synced` to `NotSynced` without overwriting active work;
- a readiness refresh racing an IBD start cannot overwrite the active IBD phase;
- an index-reset transition with an unexpected predecessor is ignored without failing IBD;

### Serialization and transport tests

- every state round-trips through workflow serialization, Borsh, JSON, protobuf, and WASM conversion;
- unknown totals remain absent rather than becoming zero totals;
- `GetSyncStatus` retains field tag and helper compatibility;
- gRPC and wRPC clients can subscribe, bootstrap, and receive only changes;
- an older-server response without `sync_state` activates boolean polling fallback.

### Wallet and CLI tests

- RPC states map to wallet events and CLI output;
- subscription events update wallet `is_synced` immediately;
- old-server fallback polls only the boolean;
- no detailed state depends on stdout contents after migration.

## Acceptance criteria

- A unary request returns the current typed state, progress, derived boolean, and sequence.
- A subscription emits each phase/readiness change immediately and progress changes no more than once every two seconds.
- A client can combine subscription and unary response without a missed-update window.
- No stale inner operation can update a later phase generation.
- Headers-proof IBD exposes two distinct, forward-only UTXO-index rebuild states.
- Optional-index nodes skip both index phases when the feature is disabled.
- Existing boolean-only callers continue to compile and work.
- Wallet and CLI detailed progress no longer parse node stdout.
