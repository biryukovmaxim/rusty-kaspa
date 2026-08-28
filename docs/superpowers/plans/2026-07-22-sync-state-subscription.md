# Sync State Subscription Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace wallet stdout parsing with an authoritative, three-atomic node sync FSM exposed through a detailed unary RPC and a change-only subscription.

**Architecture:** `AtomicSyncState` in consensus core stores one phase plus generation-tagged current/total progress. `SyncStateCoordinator` owns external sequencing and publication through the consensus notification root, while the IBD orchestration path owns phase transitions and gives generation-scoped tokens to inner processors. RPC transports expose the same typed state, and wallets use subscribe-then-unary bootstrap with revision-gated boolean polling fallback.

**Tech Stack:** Rust atomics and Tokio, Kaspa consensus/notify infrastructure, workflow serialization and Borsh/Serde, protobuf/gRPC, wRPC/WASM, wallet core and CLI.

## Global Constraints

- The in-process state representation is exactly one `AtomicU8` and two `AtomicU64`s; delivery sequencing may use a separate mutex.
- `phase = 255` is the private `Transitioning` sentinel and is never serialized.
- Both progress words pack a 24-bit non-zero generation in bits 40–63 and a 40-bit value in bits 0–39.
- A packed total value of zero means unknown; the typed API exposes `Option<NonZeroU64>`.
- Only `SyncState::Synced` returns `true` from `is_synced()`.
- `StagingUtxoIndexResync` and `PruningPointUtxoIndexResync` remain distinct forward-only states.
- Phase and readiness changes publish as soon as accepted; progress notifications publish no more than once per two seconds.
- Unary snapshots and notifications use one monotonically increasing sequence, and unary sampling never consumes a pending notification.
- Observability failures and stale tokens never fail IBD.
- The existing `get_sync_status() -> RpcResult<bool>` helper and protobuf `isSynced = 1` field remain compatible.
- RPC API version remains `1`; RPC API revision changes from `0` to `1`.
- There is no persistent state, ETA, simultaneous public phase list, or `Failed` state.
- Do not run `git add`, `git commit`, or `git push`; leave every implementation change in the working tree for user-managed review and integration.

## File Map

### New files

- `consensus/core/src/api/sync_state.rs` — public state/progress types, packed atomic storage, transition ownership, and progress tokens.
- `consensus/notify/src/sync_state.rs` — versioned snapshots, notification publication, and delivery sequencing.
- `protocol/flows/src/sync_state.rs` — IBD phase-session helper and terminal readiness monitor.

### Existing files with central changes

- `consensus/core/src/api/mod.rs` — exports sync types and carries proof/SMT progress tokens through consensus APIs.
- `consensus/src/consensus/mod.rs` and `consensus/src/processes/pruning_proof/validate.rs` — proof and SMT importer instrumentation.
- `consensus/smt-store/src/streaming_import/mod.rs` — imported-lane progress.
- `components/consensusmanager/src/lib.rs` and `components/consensusmanager/src/session.rs` — reasoned reset contexts and SMT token forwarding.
- `indexes/utxoindex/src/index.rs` — reset-reason validation and indexed-UTXO progress.
- `protocol/flows/src/flow_context.rs`, `protocol/flows/src/ibd/flow.rs`, and `protocol/flows/src/ibd/progress.rs` — FSM ownership, branch transitions, aggregate progress, cancellation, and readiness.
- `kaspad/src/daemon.rs` — creates and injects the process-wide coordinator.
- `notify/src/events.rs` and `notify/src/scope.rs` — subscription event and fieldless scope.
- `consensus/notify/src/notification.rs` — internal sync-state notification.
- `rpc/core/src/api/{notifications,ops,rpc}.rs`, `rpc/core/src/model/message.rs`, and `rpc/core/src/convert/{notification,scope}.rs` — public RPC contract.
- `rpc/service/src/service.rs` — detailed unary response.
- `rpc/grpc/core/proto/{messages,rpc}.proto`, `rpc/grpc/core/src/convert/{message,notification,kaspad}.rs`, `rpc/grpc/core/src/ext/kaspad.rs`, and `rpc/grpc/server/src/request_handler/factory.rs` — gRPC wire support.
- `rpc/wrpc/client/src/client.rs`, `rpc/wrpc/wasm/src/{client,notify}.rs`, and `rpc/core/src/wasm/message.rs` — wRPC/WASM exposure.
- `wallet/core/src/{events,utxo/sync,utxo/processor,wasm/notify}.rs`, `wallet/core/Cargo.toml`, `cli/src/{cli,modules/node}.rs` — subscription bootstrap, compatibility fallback, rendering, and regex removal.

---

### Task 1: Three-atomic sync-state core

**Files:**
- Create: `consensus/core/src/api/sync_state.rs`
- Modify: `consensus/core/src/api/mod.rs:27-32`
- Test: `consensus/core/src/api/sync_state.rs` (`#[cfg(test)]` module)

**Interfaces:**
- Consumes: only standard atomics plus existing Serde, Borsh, and workflow serializer dependencies.
- Produces: `SyncPhase`, `SyncProgress`, `SyncState`, `AtomicSyncState`, and `SyncProgressToken`.

- [ ] **Step 1: Write failing public-model and atomic tests**

Add tests covering the exact contract:

```rust
#[test]
fn default_and_known_progress_snapshot() {
    let state = Arc::new(AtomicSyncState::default());
    assert_eq!(state.snapshot(), SyncState::NotSynced);

    let token = state
        .transition(SyncPhase::NotSynced, SyncPhase::Headers, NonZeroU64::new(100))
        .unwrap()
        .unwrap();
    assert!(token.advance(7));
    assert_eq!(
        state.snapshot(),
        SyncState::Headers(SyncProgress { current: 7, total: NonZeroU64::new(100) })
    );
}

#[test]
fn same_phase_reentry_rejects_old_token() {
    let state = Arc::new(AtomicSyncState::default());
    let old = state
        .transition(SyncPhase::NotSynced, SyncPhase::Headers, NonZeroU64::new(10))
        .unwrap()
        .unwrap();
    let new = state
        .transition(SyncPhase::Headers, SyncPhase::Headers, NonZeroU64::new(20))
        .unwrap()
        .unwrap();
    assert!(!old.advance(1));
    assert!(new.advance(2));
}

#[test]
fn competing_writers_have_one_winner() {
    let state = Arc::new(AtomicSyncState::default());
    let barrier = Arc::new(Barrier::new(3));
    let writers = [SyncPhase::Negotiating, SyncPhase::Synced].map(|next| {
        let state = state.clone();
        let barrier = barrier.clone();
        thread::spawn(move || {
            barrier.wait();
            state.transition(SyncPhase::NotSynced, next, None).is_ok()
        })
    });
    barrier.wait();
    assert_eq!(writers.into_iter().filter(|h| h.join().unwrap()).count(), 1);
}
```

Also add focused tests named `unknown_total_roundtrip`, `reader_retries_during_transition`, `reader_rejects_mismatched_generations`, `concurrent_advances_preserve_generation`, `progress_clamps_to_40_bits`, `advance_saturates_at_total`, `generation_wrap_skips_zero`, and `is_synced_only_for_terminal_synced`.

- [ ] **Step 2: Run the focused tests and confirm the module is missing**

Run: `cargo test -p kaspa-consensus-core api::sync_state -- --nocapture`

Expected: FAIL because `api::sync_state` and its exported types do not exist.

- [ ] **Step 3: Implement the public and internal phase models**

Create these exact public shapes and derive `Clone`, `Debug`, `PartialEq`, `Eq`, Serde, and Borsh traits:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum SyncPhase {
    NotSynced = 0,
    Negotiating = 1,
    PruningProof = 2,
    TrustedBlocks = 3,
    Headers = 4,
    CommittingConsensus = 5,
    StagingUtxoIndexResync = 6,
    ApplyingPruningPoint = 7,
    SmtState = 8,
    UtxoSetSync = 9,
    PruningPointUtxoIndexResync = 10,
    BlockBodies = 11,
    RevalidatingOrphans = 12,
    Synced = 13,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SyncProgress {
    pub current: u64,
    pub total: Option<NonZeroU64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "kebab-case", tag = "type", content = "data")]
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
```

Implement `SyncPhase::has_progress()`, `SyncState::phase()`, `SyncState::from_parts(phase, current, total)`, and `SyncState::is_synced()`. Implement workflow `Serializer`/`Deserializer` with format version `1`, an explicit phase byte, current, and optional total so every transport sees the same model.

- [ ] **Step 4: Implement packed transitions and tokens**

Use these constants and signatures:

```rust
const TRANSITIONING: u8 = 255;
const VALUE_BITS: u32 = 40;
const VALUE_MASK: u64 = (1u64 << VALUE_BITS) - 1;
const GENERATION_MASK: u64 = (1u64 << 24) - 1;

pub struct AtomicSyncState {
    phase: AtomicU8,
    current: AtomicU64,
    total: AtomicU64,
}

impl AtomicSyncState {
    pub fn transition(
        self: &Arc<Self>,
        expected: SyncPhase,
        next: SyncPhase,
        total: Option<NonZeroU64>,
    ) -> Result<Option<SyncProgressToken>, SyncPhase>;

    pub fn snapshot(&self) -> SyncState;
    pub fn phase(&self) -> SyncPhase;
}

#[derive(Clone)]
pub struct SyncProgressToken {
    state: Arc<AtomicSyncState>,
    phase: SyncPhase,
    generation: u32,
}

impl SyncProgressToken {
    pub fn phase(&self) -> SyncPhase;
    pub fn advance(&self, delta: u64) -> bool;
    pub fn set_current(&self, value: u64) -> bool;
}
```

The transition must claim `expected -> TRANSITIONING` with `compare_exchange(..., Ordering::AcqRel, Ordering::Acquire)`, initialize both packed words with one new non-zero generation, then release-store `next`. Snapshot must double-read the phase and retry on the sentinel, phase changes, or generation mismatch. Token updates must CAS only `current`, preserve generation bits, clamp to the 40-bit range, and saturate at known total.

- [ ] **Step 5: Run atomic and serialization tests**

Run: `cargo test -p kaspa-consensus-core api::sync_state -- --nocapture`

Expected: all sync-state tests PASS, including the competing-writer test.

- [ ] **Step 6: Review the atomic-core change set**

Run: `git diff -- consensus/core/src/api/sync_state.rs consensus/core/src/api/mod.rs`

Expected: only the atomic model, its exports, and its tests are present; leave them unstaged.

---

### Task 2: Coordinator, sequence, and internal notification

**Files:**
- Create: `consensus/notify/src/sync_state.rs`
- Modify: `consensus/notify/src/lib.rs:1-12`
- Modify: `consensus/notify/src/notification.rs:20-45,170-180`
- Modify: `notify/src/events.rs:30-70`
- Modify: `notify/src/scope.rs:30-55` and append `SyncStateChangedScope`
- Test: `consensus/notify/src/sync_state.rs` (`#[cfg(test)]` module)

**Interfaces:**
- Consumes: `Arc<AtomicSyncState>`, `ConsensusNotificationRoot`, and the fieldless overall subscription machinery.
- Produces: `SyncStateCoordinator`, `VersionedSyncState`, and `SyncStateChangedNotification`.

- [ ] **Step 1: Write coordinator race and coalescing tests**

```rust
#[tokio::test]
async fn unary_discovery_does_not_consume_notification() {
    let (sender, receiver) = async_channel::unbounded();
    let root = Arc::new(ConsensusNotificationRoot::new(sender));
    let coordinator = SyncStateCoordinator::new(Arc::new(AtomicSyncState::default()), root);

    let token = coordinator
        .transition(SyncPhase::NotSynced, SyncPhase::Headers, NonZeroU64::new(10))
        .unwrap()
        .unwrap();
    let _phase_event = receiver.recv().await.unwrap();
    assert!(token.advance(1));
    let unary = coordinator.snapshot();
    coordinator.publish_if_changed();

    let Notification::SyncStateChanged(event) = receiver.recv().await.unwrap() else { panic!() };
    assert_eq!(event.sequence, unary.sequence);
    assert_eq!(event.sync_state, unary.sync_state);
}

#[test]
fn terminal_refresh_cannot_replace_active_phase() {
    let coordinator = test_coordinator();
    coordinator.transition(SyncPhase::NotSynced, SyncPhase::Negotiating, None).unwrap();
    assert!(!coordinator.refresh_terminal(true));
    assert_eq!(coordinator.atomic().phase(), SyncPhase::Negotiating);
}
```

Add `identical_snapshot_keeps_sequence`, `phase_transition_publishes_once`, `progress_publication_waits_for_explicit_sample`, and `closed_root_does_not_change_atomic_result`.

- [ ] **Step 2: Run the coordinator test target and verify failure**

Run: `cargo test -p kaspa-consensus-notify sync_state -- --nocapture`

Expected: FAIL because the coordinator and notification variant are absent.

- [ ] **Step 3: Append the generic subscription event without renumbering existing events**

Append `SyncStateChanged` after `NewBlockTemplate`, change `EVENT_COUNT` from `9` to `10`, add the string `sync-state-changed`, add `SyncStateChanged` to `Scope`, and define:

```rust
#[derive(Clone, Display, Debug, Default, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SyncStateChangedScope {}
```

The existing `OverallSubscription` handles the new fieldless scope.

- [ ] **Step 4: Add the consensus notification payload**

```rust
#[derive(Debug, Clone)]
pub struct SyncStateChangedNotification {
    pub sync_state: SyncState,
    pub sequence: u64,
}
```

Append `SyncStateChanged(SyncStateChangedNotification)` to `consensus_notify::Notification` with a concise display string. Do not place it in the consensus-to-index conversion path.

- [ ] **Step 5: Implement delivery sequencing**

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionedSyncState {
    pub sync_state: SyncState,
    pub sequence: u64,
}

struct DeliveryState {
    latest: SyncState,
    sequence: u64,
    last_emitted: u64,
}

pub struct SyncStateCoordinator {
    atomic: Arc<AtomicSyncState>,
    root: Arc<ConsensusNotificationRoot>,
    delivery: Mutex<DeliveryState>,
}
```

Implement:

```rust
pub fn atomic(&self) -> &Arc<AtomicSyncState>;
pub fn snapshot(&self) -> VersionedSyncState;
pub fn transition(
    &self,
    expected: SyncPhase,
    next: SyncPhase,
    total: Option<NonZeroU64>,
) -> Result<Option<SyncProgressToken>, SyncPhase>;
pub fn publish_if_changed(&self) -> bool;
pub fn refresh_terminal(&self, synced: bool) -> bool;
pub fn abort_active(&self) -> bool;
```

`snapshot()` acquires the delivery mutex first and samples atomics while holding it; that lock acquisition is the linearization point that prevents an older pre-lock sample from replacing a newer versioned snapshot. It increments sequence only when the typed value differs and never changes `last_emitted`. `publish_if_changed()` uses the same lock-then-sample order, emits when `sequence > last_emitted`, marks that sequence once, releases the mutex, and then calls the notification root. `transition()` publishes immediately only after a successful atomic claim. `refresh_terminal()` accepts only `Synced` or `NotSynced`; `abort_active()` CASes the observed nonterminal phase to `NotSynced` and cannot replace a terminal phase. Direct `AtomicSyncState::snapshot()` reads and token progress writes remain lock-free.

Log notification-root errors after releasing the delivery mutex. Never return them through `transition`, `refresh_terminal`, `abort_active`, or progress sampling.

- [ ] **Step 6: Run notification and coordinator tests**

Run: `cargo test -p kaspa-consensus-notify sync_state -- --nocapture`

Expected: all coordinator tests PASS.

- [ ] **Step 7: Review coordinator and event groundwork**

Run: `git diff -- consensus/notify/src notify/src/events.rs notify/src/scope.rs`

Expected: only coordinator, notification, event, scope, and test changes are present; leave them unstaged.

---

### Task 3: Daemon wiring, IBD ownership guard, and readiness refresh

**Files:**
- Create: `protocol/flows/src/sync_state.rs`
- Modify: `protocol/flows/src/lib.rs`
- Modify: `protocol/flows/src/flow_context.rs:263-420,650-675`
- Modify: `protocol/flows/src/ibd/flow.rs:94-245`
- Modify: `kaspad/src/daemon.rs:570-705`
- Test: `protocol/flows/src/sync_state.rs` (`#[cfg(test)]` module)

**Interfaces:**
- Consumes: `Arc<SyncStateCoordinator>`, the existing IBD `AtomicBool` guard, consensus readiness queries, and `TickService`.
- Produces: `IbdSyncSession`, cancellation-safe FSM ownership, and the two-second terminal/progress sampler.

- [ ] **Step 1: Write phase-session and guard tests**

```rust
#[test]
fn dropped_active_session_returns_to_not_synced() {
    let coordinator = test_coordinator();
    {
        let mut session = IbdSyncSession::begin(coordinator.clone()).unwrap();
        session.enter(SyncPhase::Headers, NonZeroU64::new(10)).unwrap();
    }
    assert_eq!(coordinator.atomic().phase(), SyncPhase::NotSynced);
}

#[test]
fn completed_session_is_not_reset_by_drop() {
    let coordinator = test_coordinator();
    let mut session = IbdSyncSession::begin(coordinator.clone()).unwrap();
    session.finish(true);
    drop(session);
    assert_eq!(coordinator.atomic().phase(), SyncPhase::Synced);
}
```

Add a test that adopts a phase entered synchronously by a reset boundary and then advances from that exact predecessor.

Add `readiness_refresh_racing_ibd_begin_never_replaces_active_phase` with a barrier around the two writers. Add a Tokio time-controlled monitor test that performs several token updates inside two seconds and asserts one coalesced event, then advances two seconds and asserts the next event.

- [ ] **Step 2: Run the flow test target and verify failure**

Run: `cargo test -p kaspa-p2p-flows sync_state -- --nocapture`

Expected: FAIL because `IbdSyncSession` does not exist.

- [ ] **Step 3: Implement the orchestration-only session helper**

```rust
pub struct IbdSyncSession {
    coordinator: Arc<SyncStateCoordinator>,
    phase: SyncPhase,
    terminal: bool,
}

impl IbdSyncSession {
    pub fn begin(coordinator: Arc<SyncStateCoordinator>) -> Result<Self, SyncPhase>;
    pub fn enter(
        &mut self,
        next: SyncPhase,
        total: Option<NonZeroU64>,
    ) -> Result<Option<SyncProgressToken>, SyncPhase>;
    pub fn adopt(&mut self, phase: SyncPhase);
    pub fn phase(&self) -> SyncPhase;
    pub fn finish(&mut self, synced: bool);
}
```

`begin()` transitions the currently observed terminal phase to `Negotiating`, retrying if a terminal refresh won the first claim. `Drop` calls `abort_active()` unless `finish()` selected a terminal state. `enter()` always uses the session's current phase as the expected predecessor. `adopt()` is used only after a synchronous reset boundary already changed the atomic owner.

- [ ] **Step 4: Inject one coordinator through the daemon and flow context**

In `kaspad/src/daemon.rs`, create the atomic and coordinator directly after `notification_root`:

```rust
let atomic_sync_state = Arc::new(AtomicSyncState::default());
let sync_state = Arc::new(SyncStateCoordinator::new(atomic_sync_state, notification_root.clone()));
```

Add `sync_state: Arc<SyncStateCoordinator>` to `FlowContextInner`, add it to `FlowContext::new`, and expose `pub fn sync_state(&self) -> &Arc<SyncStateCoordinator>`. Pass the daemon instance into the constructor. Update test constructors with a root-backed default coordinator.

- [ ] **Step 5: Add readiness and sampling worker**

Add `FlowContext::is_sync_ready()` using exactly the current unary predicate:

```rust
pub async fn is_sync_ready(&self) -> bool {
    let session = self.consensus().unguarded_session();
    let sink = session.async_get_sink_daa_score_timestamp().await;
    self.mining_rule_engine.is_sink_recent_and_connected(sink)
        && !session.async_is_consensus_in_transitional_ibd_state().await
}
```

From `start_async_services()`, spawn a loop that waits `Duration::from_secs(2)` through `TickService`, calls `refresh_terminal(ready)`, and calls `publish_if_changed()` for coalesced progress. It exits on `TickReason::Shutdown`. `refresh_terminal` itself prevents overwriting active IBD.

- [ ] **Step 6: Put the IBD session around every attempt**

In `IbdFlow::start_impl`, create `IbdSyncSession` immediately after acquiring `IbdRunningGuard`. Pass `&mut IbdSyncSession` into `ibd`. On success, evaluate `ctx.is_sync_ready().await` and call `finish`; on error, call `finish(false)` before returning the protocol error. The drop guard covers cancellation and panic unwinding.

- [ ] **Step 7: Run focused flow tests and check affected crates**

Run: `cargo test -p kaspa-p2p-flows sync_state -- --nocapture`

Expected: phase-session tests PASS.

Run: `cargo check -p kaspad -p kaspa-p2p-flows`

Expected: both packages compile.

- [ ] **Step 8: Review wiring and ownership**

Run: `git diff -- protocol/flows/src/sync_state.rs protocol/flows/src/lib.rs protocol/flows/src/flow_context.rs protocol/flows/src/ibd/flow.rs kaspad/src/daemon.rs`

Expected: only process-wide wiring, readiness, and IBD ownership changes are present; leave them unstaged.

---

### Task 4: Reasoned consensus resets and two monotonic index states

**Files:**
- Modify: `components/consensusmanager/src/lib.rs:70-85,175-225`
- Modify: `indexes/utxoindex/src/index.rs:35-50,139-185,205-220`
- Modify: `protocol/flows/src/ibd/flow.rs:130-225,774-785`
- Test: `components/consensusmanager/src/lib.rs` and `indexes/utxoindex/src/index.rs`

**Interfaces:**
- Consumes: `SyncProgressToken` and `IbdSyncSession`.
- Produces: `ConsensusResetReason`, `ConsensusResetContext`, and progress-aware synchronous reset handlers.

- [ ] **Step 1: Write reset-reason and index-progress tests**

Add a consensus-manager test with a recording handler and assert it receives each exact reason. Extend the UTXO-index test so `resync(Some(&token))` ends with `current == resync_utxo_collection_size` and an unknown total.

```rust
#[derive(Default)]
struct RecordingResetHandler(Mutex<Vec<ConsensusResetReason>>);

impl ConsensusResetHandler for RecordingResetHandler {
    fn handle_consensus_reset(&self, context: &ConsensusResetContext) {
        self.0.lock().push(context.reason);
    }
}
```

- [ ] **Step 2: Run focused tests and verify signature failures**

Run: `cargo test -p kaspa-consensusmanager consensus_reset -- --nocapture`

Run: `cargo test -p kaspa-utxoindex test_utxoindex -- --nocapture`

Expected: FAIL until reset contexts and progress-aware resync exist.

- [ ] **Step 3: Replace the context-free reset trait**

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsensusResetReason {
    StagingConsensusCommitted,
    PruningPointUtxoSetReplaced,
}

pub struct ConsensusResetContext {
    pub reason: ConsensusResetReason,
    pub progress: Option<SyncProgressToken>,
}

pub trait ConsensusResetHandler: Send + Sync {
    fn handle_consensus_reset(&self, context: &ConsensusResetContext);
}
```

Change `invoke_consensus_reset_handlers` to accept one context by value and pass `&context` to every synchronous handler. Change `StagingConsensus::commit` to accept a `FnOnce() -> ConsensusResetContext`, invoke it after activating staging consensus and immediately before handlers, then invoke handlers with that context.

- [ ] **Step 4: Instrument UTXO-index resync without changing failure semantics**

Change `resync` to `fn resync(&mut self, progress: Option<&SyncProgressToken>)`. After each successful `update_utxo_state`, call `token.advance(current_chunk_size as u64)` when present. Startup recovery calls `resync(None)`. The handler asserts that the token phase matches the reason mapping and calls resync even when instrumentation supplied no token:

```rust
let expected = match context.reason {
    ConsensusResetReason::StagingConsensusCommitted => SyncPhase::StagingUtxoIndexResync,
    ConsensusResetReason::PruningPointUtxoSetReplaced => SyncPhase::PruningPointUtxoIndexResync,
};
debug_assert!(context.progress.as_ref().is_none_or(|token| token.phase() == expected));
utxoindex.write().resync(context.progress.as_ref()).unwrap();
```

- [ ] **Step 5: Enter the two index phases at their exact reset boundaries**

For staging commit, enter `CommittingConsensus`, then pass a closure into `commit` that transitions to `StagingUtxoIndexResync` when `config.utxoindex` is true and returns `ConsensusResetContext { reason: StagingConsensusCommitted, progress }`. Adopt the resulting phase after the blocking call.

For pruning-point replacement, finish UTXO import, transition `UtxoSetSync -> PruningPointUtxoIndexResync` when enabled, invoke handlers with `PruningPointUtxoSetReplaced`, and adopt that phase. When the index is disabled, invoke handlers with no token and keep the prior phase. A rejected transition logs a warning, passes `None`, and does not fail IBD.

- [ ] **Step 6: Run reset and index tests**

Run: `cargo test -p kaspa-consensusmanager consensus_reset -- --nocapture`

Run: `cargo test -p kaspa-utxoindex test_utxoindex -- --nocapture`

Expected: both test sets PASS.

- [ ] **Step 7: Review reset semantics**

Run: `git diff -- components/consensusmanager/src/lib.rs indexes/utxoindex/src/index.rs protocol/flows/src/ibd/flow.rs`

Expected: only reasoned reset and index-progress changes are present; leave them unstaged.

---

### Task 5: Instrument IBD phases and aggregate progress

**Files:**
- Modify: `protocol/flows/src/ibd/flow.rs:112-1140`
- Modify: `protocol/flows/src/ibd/progress.rs:1-75`
- Modify: `consensus/core/src/api/mod.rs:295-310`
- Modify: `consensus/src/consensus/mod.rs:1110-1135`
- Modify: `consensus/src/processes/pruning_proof/validate.rs:175-205,314-350`
- Test: `protocol/flows/src/ibd/flow.rs` and `consensus/src/processes/pruning_proof/validate.rs`

**Interfaces:**
- Consumes: `&mut IbdSyncSession` and optional generation-scoped progress tokens.
- Produces: every non-SMT phase and progress value in the approved FSM.

- [ ] **Step 1: Add branch-path tests before changing orchestration**

Extract a pure test helper that records transitions for branch decisions and assert these exact vectors:

```rust
assert_eq!(
    headers_proof_path(true),
    vec![
        Negotiating, PruningProof, TrustedBlocks, Headers, CommittingConsensus,
        StagingUtxoIndexResync, SmtState, UtxoSetSync,
        PruningPointUtxoIndexResync, BlockBodies, RevalidatingOrphans,
    ]
);
assert_eq!(
    pruning_catchup_path(false),
    vec![Negotiating, Headers, ApplyingPruningPoint, TrustedBlocks, SmtState,
         UtxoSetSync, BlockBodies, RevalidatingOrphans]
);
```

Add tests for skipped stable SMT/UTXO work, disabled index states, one aggregate `BlockBodies` generation, and zero-work phase skipping.

- [ ] **Step 2: Run path tests and verify they fail**

Run: `cargo test -p kaspa-p2p-flows ibd::flow::tests::sync_state -- --nocapture`

Expected: FAIL because branch transition recording is not implemented.

- [ ] **Step 3: Thread the session through all IBD branches**

Change `ibd`, `ibd_with_headers_proof`, `sync_and_validate_pruning_proof`, `sync_headers`, `sync_new_utxo_set`, `sync_pruning_point_utxoset`, trusted-body helpers, body helpers, and orphan post-processing to accept either `&mut IbdSyncSession` or the specific `SyncProgressToken` they need.

Use these transitions:

- Header-proof: `PruningProof -> TrustedBlocks -> Headers -> CommittingConsensus -> StagingUtxoIndexResync? -> SmtState -> UtxoSetSync -> PruningPointUtxoIndexResync? -> BlockBodies -> RevalidatingOrphans`.
- Resume: `TrustedBlocks? -> SmtState? -> UtxoSetSync? -> PruningPointUtxoIndexResync? -> Headers -> BlockBodies -> RevalidatingOrphans`.
- Catch-up: `Headers -> ApplyingPruningPoint -> TrustedBlocks -> SmtState -> UtxoSetSync -> PruningPointUtxoIndexResync? -> BlockBodies -> RevalidatingOrphans`.

Skip any measured phase whose exact work count is zero.

- [ ] **Step 4: Report pruning-proof and trusted-block progress**

Add `progress: Option<SyncProgressToken>` to `ConsensusApi::validate_pruning_proof` and its implementation. In the proof level loop, advance once after a level validates successfully. The initial validation receives a token with `total = proof.len()`; local sanity fallback validation receives `None` so it cannot double-count.

After `trusted_set` is built, enter `TrustedBlocks` with its exact length and advance after each awaited trusted block. For missing trusted bodies, enter the same phase with the missing-hash count and advance only after each batch's validation futures succeed.

- [ ] **Step 5: Extend `ProgressReporter` with a token**

Keep log behavior and add `token: Option<SyncProgressToken>`. On each report, compute `current_daa_score.saturating_sub(low_daa_score)` and call `set_current`; completion sets the fixed DAA-span total. Header phases create the token with `relay_daa_score.saturating_sub(shared_daa_score).max(1)`.

- [ ] **Step 6: Report UTXO-set progress by imported entries**

Enter `UtxoSetSync` with unknown total. In `sync_pruning_point_utxoset`, save `chunk.len()` before moving the chunk into `spawn_blocking`, then advance only after `append_imported_pruning_point_utxos` returns. Do not use chunk count as public progress.

- [ ] **Step 7: Aggregate both final body searches under one token**

Split the current method into:

```rust
async fn missing_body_hashes(&self, consensus: &ConsensusProxy, high: Hash) -> Result<Vec<Hash>, ProtocolError>;
async fn sync_block_body_hashes(
    &mut self,
    consensus: &ConsensusProxy,
    hashes: &[Hash],
    progress: &SyncProgressToken,
) -> Result<(), ProtocolError>;
```

Collect both searches before entering `BlockBodies`, preserve first-seen order while deduplicating hashes, set the exact unique count as total, and use one token for all completed batches. This preserves one observable generation even when the relay antipast adds work.

- [ ] **Step 8: Report orphan task completion**

Call `revalidate_orphans` to obtain queued hashes/tasks. If non-empty, enter `RevalidatingOrphans` with the queued task count and advance after each joined result, including failed validations because the task itself completed. Keep validation warnings and peer attribution behavior unchanged.

- [ ] **Step 9: Run consensus and flow tests**

Run: `cargo test -p kaspa-p2p-flows ibd -- --nocapture`

Run: `cargo test -p kaspa-consensus pruning_proof -- --nocapture`

Expected: all targeted tests PASS.

- [ ] **Step 10: Review IBD instrumentation**

Run: `git diff -- protocol/flows/src/ibd consensus/core/src/api/mod.rs consensus/src/consensus/mod.rs consensus/src/processes/pruning_proof/validate.rs`

Expected: only IBD transitions, progress plumbing, and tests are present; leave them unstaged.

---

### Task 6: SMT imported-lane progress

**Files:**
- Modify: `consensus/core/src/api/mod.rs:330-350`
- Modify: `components/consensusmanager/src/session.rs:510-535`
- Modify: `consensus/src/consensus/mod.rs:1150-1190`
- Modify: `consensus/smt-store/src/streaming_import/mod.rs:30-165`
- Modify: `consensus/smt-store/tests/integration.rs` (all `streaming_import` calls)
- Modify: `consensus/smt-store/examples/bench_streaming_import.rs`
- Modify: `protocol/flows/src/ibd/flow.rs:697-773`
- Test: `consensus/smt-store/tests/integration.rs`

**Interfaces:**
- Consumes: a `SyncProgressToken` for `SyncPhase::SmtState`.
- Produces: importer-confirmed current lanes with metadata `active_lanes_count` as total.

- [ ] **Step 1: Write a streaming-import token test**

Add an integration test that constructs an `AtomicSyncState`, enters `SmtState` with the fixture lane count, runs `streaming_import(..., Some(token))`, and asserts current equals total only after import succeeds.

- [ ] **Step 2: Run the test and verify the missing parameter failure**

Run: `cargo test -p kaspa-smt-store streaming_import_reports_sync_progress -- --nocapture`

Expected: FAIL because `streaming_import` has no progress-token parameter.

- [ ] **Step 3: Carry the token down to the importer**

Append `progress: Option<SyncProgressToken>` to `ConsensusApi::import_pruning_point_smt`, `ConsensusSession::import_pruning_point_smt`, the consensus implementation, and `streaming_import`. Update existing tests and the benchmark with `None`.

After a non-empty chunk has passed proof checks, builder feed, and lane-version staging, call both the existing logger and `token.advance(chunk.len() as u64)`. Completion calls `set_current(total_count)` only after `builder.finish()` and all database flushes succeed.

- [ ] **Step 4: Enter SMT state from verified metadata**

In `sync_new_smt_state`, skip the phase entirely before Toccata activation. After metadata verification supplies `active_lanes_count`, enter `SmtState` with that exact non-zero total and pass the token into the blocking importer. A zero-lane import is skipped and proceeds to the next phase.

- [ ] **Step 5: Run SMT and protocol tests**

Run: `cargo test -p kaspa-smt-store streaming_import -- --nocapture`

Run: `cargo test -p kaspa-p2p-flows ibd -- --nocapture`

Expected: all targeted tests PASS.

- [ ] **Step 6: Review SMT progress**

Run: `git diff -- consensus/core/src/api/mod.rs components/consensusmanager/src/session.rs consensus/src/consensus/mod.rs consensus/smt-store protocol/flows/src/ibd/flow.rs`

Expected: only SMT token forwarding, imported-lane updates, call-site changes, and tests are present; leave them unstaged.

---

### Task 7: RPC core contract and detailed unary service

**Files:**
- Modify: `rpc/core/src/model/message.rs:2435-2480,2980-3660`
- Modify: `rpc/core/src/api/notifications.rs:20-210`
- Modify: `rpc/core/src/api/ops.rs:10-190`
- Modify: `rpc/core/src/api/rpc.rs:90-110`
- Modify: `rpc/core/src/convert/notification.rs:1-120`
- Modify: `rpc/core/src/convert/scope.rs:1-80`
- Modify: `rpc/core/src/model/tests.rs:1500-1580`
- Modify: `rpc/service/src/service.rs:130-225,1325-1350`
- Test: `rpc/core/src/model/tests.rs` and `rpc/service/src/service.rs`

**Interfaces:**
- Consumes: consensus `SyncStateChangedNotification` and `FlowContext::sync_state()`.
- Produces: backward-compatible detailed `GetSyncStatusResponse` and RPC `SyncStateChangedNotification`.

- [ ] **Step 1: Write RPC model round-trip tests**

Generate one instance of every `SyncState` variant and assert workflow serialization, Borsh, and JSON round trips. Add a response test asserting `is_synced == sync_state.is_synced()` and a notification test preserving sequence.

- [ ] **Step 2: Run RPC core tests and verify failure**

Run: `cargo test -p kaspa-rpc-core sync_state -- --nocapture`

Expected: FAIL because detailed fields and notification types are absent.

- [ ] **Step 3: Extend the unary model compatibly**

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetSyncStatusResponse {
    pub is_synced: bool,
    pub sync_state: Option<SyncState>,
    pub sequence: u64,
}
```

Serialize response format version `2`; deserialize version `1` as `{ is_synced, sync_state: None, sequence: 0 }` and version `2` with all fields. Keep `get_sync_status() -> RpcResult<bool>` and add:

```rust
async fn get_sync_status_detailed(&self) -> RpcResult<GetSyncStatusResponse> {
    self.get_sync_status_call(None, GetSyncStatusRequest {}).await
}
```

- [ ] **Step 4: Add the RPC notification and stable operation values**

Append `NotifySyncStateChanged = 19`, `SyncStateChangedNotification = 69`, and their exhaustive conversions without changing existing discriminants. Add request/response structs following `NotifyNewBlockTemplate`:

```rust
pub struct NotifySyncStateChangedRequest {
    pub command: Command,
}

pub struct NotifySyncStateChangedResponse {}

pub struct SyncStateChangedNotification {
    pub sync_state: SyncState,
    pub sequence: u64,
}
```

Use notification workflow variant index `9`. Add notification/scope conversions and include `SyncStateChanged` in `Notification::to_value`.

- [ ] **Step 5: Serve the coordinator snapshot**

In `RpcCoreService::get_sync_status_call`:

```rust
let versioned = self.flow_context.sync_state().snapshot();
let is_synced = versioned.sync_state.is_synced();
Ok(GetSyncStatusResponse {
    is_synced,
    sync_state: Some(versioned.sync_state),
    sequence: versioned.sequence,
})
```

Remove the duplicated consensus/mining predicate from this method. Change `RPC_API_REVISION` to `1`.

- [ ] **Step 6: Run core and service checks**

Run: `cargo test -p kaspa-rpc-core sync_state -- --nocapture`

Run: `cargo check -p kaspa-rpc-service`

Expected: tests PASS and RPC service compiles.

- [ ] **Step 7: Review the RPC core contract**

Run: `git diff -- rpc/core rpc/service/src/service.rs`

Expected: only RPC types, conversion, unary service, revision, and mock updates are present; leave them unstaged.

---

### Task 8: gRPC protobuf and routing

**Files:**
- Modify: `rpc/grpc/core/proto/messages.proto:1-145`
- Modify: `rpc/grpc/core/proto/rpc.proto:500-670,895-920`
- Modify: `rpc/grpc/core/src/convert/message.rs:520-590,1075-1140`
- Modify: `rpc/grpc/core/src/convert/notification.rs`
- Modify: `rpc/grpc/core/src/convert/kaspad.rs`
- Modify: `rpc/grpc/core/src/ext/kaspad.rs`
- Modify: `rpc/grpc/core/src/ops.rs`
- Modify: `rpc/grpc/server/src/request_handler/factory.rs:65-115`
- Test: `rpc/grpc/server/src/tests/client_server.rs`

**Interfaces:**
- Consumes: RPC core detailed response and notification.
- Produces: protobuf wire fields and gRPC subscribe/unsubscribe routing.

- [ ] **Step 1: Add a gRPC conversion round-trip test**

Construct `GetSyncStatusResponse` and `SyncStateChangedNotification` with a known-total phase, convert to protowire and back, and assert exact equality. Add an unknown-total case.

- [ ] **Step 2: Run gRPC tests and verify failure**

Run: `cargo test -p kaspa-grpc-core sync_state -- --nocapture`

Expected: FAIL because protobuf messages and conversions do not exist.

- [ ] **Step 3: Add protobuf types with fixed new IDs**

Use request oneof ID `1120`, subscription response ID `1121`, and notification ID `1122`. Preserve `GetSyncStatusResponseMessage.isSynced = 1` and add `SyncStateMessage syncState = 2` plus `uint64 sequence = 3`.

Define `SyncPhaseMessage` values `UNSPECIFIED = 0`, then the fourteen public phases in the exact `SyncPhase` order plus one. Define:

```proto
message SyncProgressMessage {
  uint64 current = 1;
  optional uint64 total = 2;
}

message SyncStateMessage {
  SyncPhaseMessage phase = 1;
  optional SyncProgressMessage progress = 2;
}

message NotifySyncStateChangedRequestMessage { NotifyCommand command = 1; }
message NotifySyncStateChangedResponseMessage { RPCError error = 1000; }
message SyncStateChangedNotificationMessage {
  SyncStateMessage syncState = 1;
  uint64 sequence = 2;
}
```

- [ ] **Step 4: Implement strict conversions**

Map all phases explicitly. Reject `UNSPECIFIED`, progress on progressless phases, and missing progress on measured phases with `ConversionError`. Convert total zero to absent and reject an explicit zero total. Add notification conversion in both directions and extend response `is_notification()`.

- [ ] **Step 5: Route the subscription**

Add the request to `KaspadPayloadOps`, `from_notification_type`, `is_subscription`, request/response adapters, and the factory's generated method list. The fieldless scope uses the normal overall subscription command path.

- [ ] **Step 6: Run gRPC tests**

Run: `cargo test -p kaspa-grpc-core sync_state -- --nocapture`

Run: `cargo test -p kaspa-grpc-server client_server -- --nocapture`

Expected: conversion and client/server tests PASS.

- [ ] **Step 7: Review gRPC support**

Run: `git diff -- rpc/grpc/core rpc/grpc/server/src/request_handler/factory.rs`

Expected: only protobuf, conversion, routing, and transport-test changes are present; leave them unstaged.

---

### Task 9: wRPC and WASM exposure

**Files:**
- Modify: `rpc/wrpc/client/src/client.rs:65-100`
- Modify: `rpc/wrpc/wasm/src/client.rs:760-930`
- Modify: `rpc/wrpc/wasm/src/notify.rs:10-260`
- Modify: `rpc/core/src/wasm/message.rs:510-545`
- Test: existing wRPC macro/interface tests plus WASM compile check

**Interfaces:**
- Consumes: `RpcApiOps::SyncStateChangedNotification`, fieldless scope, and detailed response.
- Produces: native wRPC routing and JavaScript event/subscription types.

- [ ] **Step 1: Add `SyncStateChangedNotification` to the wRPC client interface list**

Append the operation to the notification array registered in `KaspaRpcClient::new`. This is required for both Borsh and JSON encodings.

- [ ] **Step 2: Expose the WASM event and methods**

Add `SyncStateChanged = "sync-state-changed"` to `RpcEventType`, `ISyncStateChanged` to `RpcEventData`, and the event-map entry. Define the shared state/progress interfaces once in `rpc/core/src/wasm/message.rs`:

```typescript
export interface ISyncProgress { current: bigint; total?: bigint; }
export interface ISyncState { type: string; data?: ISyncProgress; }
```

Define only the notification wrapper in `rpc/wrpc/wasm/src/notify.rs`:

```typescript
export interface ISyncStateChanged { syncState: ISyncState; sequence: bigint; }
```

Add `SyncStateChanged` to `build_wrpc_wasm_bindgen_subscriptions!` so `subscribeSyncStateChanged()` and `unsubscribeSyncStateChanged()` are generated.

- [ ] **Step 3: Extend the detailed unary TypeScript response**

Change `IGetSyncStatusResponse` to:

```typescript
export interface IGetSyncStatusResponse {
    isSynced: boolean;
    syncState?: ISyncState;
    sequence: bigint;
}
```

Continue using Serde conversion so kebab-case tagged state values match notifications.

- [ ] **Step 4: Run native and WASM checks**

Run: `cargo test -p kaspa-wrpc-client --lib`

Run: `cargo check -p kaspa-wrpc-wasm --target wasm32-unknown-unknown`

Expected: native tests PASS and the WASM target compiles.

- [ ] **Step 5: Review wRPC/WASM support**

Run: `git diff -- rpc/wrpc/client/src/client.rs rpc/wrpc/wasm/src rpc/core/src/wasm/message.rs`

Expected: only notification registration, WASM methods, and TypeScript declarations are present; leave them unstaged.

---

### Task 10: Wallet bootstrap, legacy fallback, and CLI migration

**Files:**
- Modify: `wallet/core/src/events.rs:10-60`
- Modify: `wallet/core/src/utxo/sync.rs:1-275`
- Modify: `wallet/core/src/utxo/processor.rs:490-665`
- Modify: `wallet/core/src/wasm/notify.rs:250-280`
- Modify: `wallet/core/src/tests/rpc_core_mock.rs`
- Modify: `wallet/core/Cargo.toml`
- Modify: `cli/src/cli.rs:745-805`
- Modify: `cli/src/modules/node.rs:70-90,245-260`
- Test: `wallet/core/src/utxo/sync.rs` and `wallet/core/src/tests/rpc_core_mock.rs`

**Interfaces:**
- Consumes: API revision `1`, detailed unary snapshots, and ordered sync-state notifications.
- Produces: wallet events from typed RPC state; old servers retain boolean polling.

- [ ] **Step 1: Write sequence/bootstrap and legacy-mode tests**

```rust
#[tokio::test]
async fn baseline_discards_older_buffered_notifications() {
    let monitor = test_monitor();
    monitor.install_baseline(headers(20, 100), 9).await.unwrap();
    monitor.apply_notification(SyncState::Negotiating, 8).await.unwrap();
    assert_eq!(monitor.last_sequence(), 9);
    assert_eq!(monitor.current_state(), headers(20, 100));
}

#[tokio::test]
async fn detailed_state_drives_synced_boolean() {
    let monitor = test_monitor();
    monitor.install_baseline(SyncState::Synced, 1).await.unwrap();
    assert!(monitor.is_synced());
    monitor.apply_notification(SyncState::PruningPointUtxoIndexResync(progress(5, None)), 2).await.unwrap();
    assert!(!monitor.is_synced());
}
```

Add a test that revision `0` does not subscribe and starts five-second boolean polling, while revision `1` subscribes before requesting the detailed baseline.

- [ ] **Step 2: Run wallet tests and verify failure**

Run: `cargo test -p kaspa-wallet-core sync_monitor -- --nocapture`

Expected: FAIL because sequence-aware methods and typed RPC notification handling are absent.

- [ ] **Step 3: Reuse the consensus-core state in wallet events**

Remove the wallet-local `SyncState` enum and publicly re-export `kaspa_consensus_core::api::sync_state::SyncState`. Remove the wallet-local TypeScript `ISyncState` declaration and make `ISyncStateEvent.syncState` reference the shared RPC-core `ISyncState`, whose representation is `{ type, data?: { current, total? } }`.

- [ ] **Step 4: Replace regex state with versioned application**

Remove `StateObserver`, every regex, `handle_stdout`, and the `regex` dependency. Add `last_sequence: AtomicU64`, `has_baseline: AtomicBool`, `detailed: AtomicBool`, and a mutex-protected current typed state.

Implement `install_baseline(sync_state, sequence)` and `apply_notification(sync_state, sequence)`. Baseline installation records the unary sequence before notification draining begins. Notification application uses compare-and-swap on `last_sequence`, rejects equal/lower sequences, updates `is_synced` from the state method, stores the state, and broadcasts `Events::SyncState`. Keep `track(bool)` and the existing five-second task only for legacy servers.

- [ ] **Step 5: Implement subscribe-then-unary connection bootstrap**

After `GetServerInfo` validates version/network/index:

1. Register the notification listener.
2. Always subscribe to `VirtualDaaScoreChanged`.
3. If `rpc_api_revision >= 1`, subscribe to `SyncStateChanged`, then call `get_sync_status_detailed`, install its `Some(sync_state)` baseline, and process only buffered notifications with higher sequence.
4. If revision is `0`, call `track(server_info.is_synced)` and use boolean polling.

If a revision-1 response unexpectedly has `sync_state: None`, unsubscribe from `SyncStateChanged`, install the response boolean through `track`, and use legacy polling. Handle `Notification::SyncStateChanged` by calling `apply_notification`. In the `UtxosChanged` arm, infer sync completion only in legacy mode; detailed mode is controlled exclusively by the FSM.

- [ ] **Step 6: Update CLI rendering for every state**

Map all fourteen states exhaustively. For measured phases, render `current/total` and percentage when total is present; render only `current` for unknown totals. Label the two index states separately as `UTXO INDEX (STAGING)` and `UTXO INDEX (PRUNING POINT)`. `Synced` renders no sync badge; `NotSynced` and `Negotiating` render waiting/negotiation badges.

- [ ] **Step 7: Remove stdout coupling**

Delete the `sync_proc().handle_stdout(&text)` call from `cli/src/modules/node.rs`. Restore the configured mute value in `create_config`, since progress no longer depends on daemon output.

- [ ] **Step 8: Run wallet and CLI tests/checks**

Run: `cargo test -p kaspa-wallet-core sync_monitor -- --nocapture`

Run: `cargo check -p kaspa-wallet-core -p kaspa-cli`

Expected: tests PASS and both packages compile.

Run: `rg -n "StateObserver|handle_stdout|Validating level \(\\d\+\)|SMT import \(\\d\+\)" wallet/core/src cli/src`

Expected: no matches.

- [ ] **Step 9: Review wallet and CLI migration**

Run: `git diff -- wallet/core cli/src Cargo.lock`

Expected: only subscription bootstrap, fallback, rendering, dependency, and regex-removal changes are present; leave them unstaged.

---

### Task 11: Cross-transport integration and final verification

**Files:**
- Modify: `testing/integration/src/rpc_tests.rs`
- Modify: `testing/integration/src/common/client_notify.rs`
- Test: all affected packages and integration RPC tests

**Interfaces:**
- Consumes: the completed node, RPC transports, and wallet client path.
- Produces: end-to-end evidence for unary/subscription ordering and compatibility.

- [ ] **Step 1: Add an end-to-end subscribe-then-unary test**

Register a sync-state listener, start the subscription, obtain `GetSyncStatus`, and assert every received notification has a strictly increasing sequence. Buffer before unary and apply only `sequence > baseline.sequence`; assert the reconstructed client state equals a final unary snapshot.

- [ ] **Step 2: Add terminal and index-path assertions**

For a test node with UTXO index enabled, assert neither index state reports synced and that an observed staging rebuild can only precede an observed pruning-point rebuild. For a node without the index, assert neither index state is emitted.

- [ ] **Step 3: Run formatting**

Run: `cargo fmt --all -- --check`

Expected: exit code `0`. If it reports differences, run `cargo fmt --all`, inspect the diff, then rerun the check.

- [ ] **Step 4: Run all targeted package tests**

Run:

```bash
cargo test -p kaspa-consensus-core -p kaspa-consensus-notify -p kaspa-consensusmanager -p kaspa-utxoindex -p kaspa-smt-store -p kaspa-p2p-flows -p kaspa-rpc-core -p kaspa-grpc-core -p kaspa-grpc-server -p kaspa-wrpc-client -p kaspa-wallet-core
```

Expected: all packages report `test result: ok` with zero failures.

- [ ] **Step 5: Run integration RPC tests**

Run: `cargo test -p kaspa-testing-integration rpc_tests -- --nocapture`

Expected: RPC integration tests PASS, including ordered bootstrap.

- [ ] **Step 6: Check all production packages touched by wiring**

Run:

```bash
cargo check -p kaspad -p kaspa-rpc-service -p kaspa-grpc-server -p kaspa-wrpc-client -p kaspa-wallet-core -p kaspa-cli
```

Expected: exit code `0` with no compile errors.

- [ ] **Step 7: Verify compatibility and removal requirements directly**

Run: `rg -n "pub const RPC_API_VERSION: u16 = 1|pub const RPC_API_REVISION: u16 = 1" rpc/core/src/api/ops.rs`

Expected: exactly the version and revision declarations.

Run: `rg -n "StateObserver|handle_stdout|sync-state regular expressions" wallet/core/src cli/src`

Expected: no matches.

Run: `git diff --check`

Expected: no whitespace errors.

- [ ] **Step 8: Review integration coverage and final mechanical fixes**

Run: `git diff -- testing/integration Cargo.lock`

Expected: only integration coverage and dependency-lock changes caused by this implementation are present; leave them unstaged.

- [ ] **Step 9: Review the complete unstaged implementation against the design**

Run: `git diff --stat`

Expected: every changed production/test file is accounted for by a task above, with no unrelated changes and no staged or committed action taken by the implementer.

Compare the implementation to `docs/superpowers/specs/2026-07-22-sync-state-subscription-design.md` and explicitly verify all acceptance criteria before handing the unstaged working tree back to the user.
