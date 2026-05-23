use crate::{
    consensus::test_consensus::TestConsensus,
    model::{services::reachability::ReachabilityService, stores::ghostdag::GhostdagStoreReader},
};
use kaspa_consensus_core::{
    BlockHashSet,
    api::ConsensusApi,
    block::{Block, BlockTemplate, MutableBlock, TemplateBuildMode, TemplateTransactionSelector},
    blockhash,
    blockstatus::BlockStatus,
    coinbase::MinerData,
    config::{
        ConfigBuilder,
        params::{ForkActivation, MAINNET_PARAMS},
    },
    constants::{BLOCK_VERSION, TOCCATA_BLOCK_VERSION},
    tx::{ScriptPublicKey, ScriptVec, Transaction},
};
use kaspa_hashes::Hash;
use std::{collections::VecDeque, thread::JoinHandle};

struct OnetimeTxSelector {
    txs: Option<Vec<Transaction>>,
}

impl OnetimeTxSelector {
    fn new(txs: Vec<Transaction>) -> Self {
        Self { txs: Some(txs) }
    }
}

impl TemplateTransactionSelector for OnetimeTxSelector {
    fn select_transactions(&mut self) -> Vec<Transaction> {
        self.txs.take().unwrap()
    }

    fn reject_selection(&mut self, _tx_id: kaspa_consensus_core::tx::TransactionId) {
        unimplemented!()
    }

    fn is_successful(&self) -> bool {
        true
    }
}

struct TestContext {
    consensus: TestConsensus,
    join_handles: Vec<JoinHandle<()>>,
    miner_data: MinerData,
    simulated_time: u64,
    current_templates: VecDeque<BlockTemplate>,
    current_tips: BlockHashSet,
}

impl Drop for TestContext {
    fn drop(&mut self) {
        self.consensus.shutdown(std::mem::take(&mut self.join_handles));
    }
}

impl TestContext {
    fn new(consensus: TestConsensus) -> Self {
        let join_handles = consensus.init();
        let genesis_hash = consensus.params().genesis.hash;
        let simulated_time = consensus.params().genesis.timestamp;
        Self {
            consensus,
            join_handles,
            miner_data: new_miner_data(),
            simulated_time,
            current_templates: Default::default(),
            current_tips: BlockHashSet::from_iter([genesis_hash]),
        }
    }

    pub fn build_block_template_row(&mut self, nonces: impl Iterator<Item = usize>) -> &mut Self {
        for nonce in nonces {
            self.simulated_time += self.consensus.params().target_time_per_block();
            self.current_templates.push_back(self.build_block_template(nonce as u64, self.simulated_time));
        }
        self
    }

    pub fn assert_row_parents(&mut self) -> &mut Self {
        for t in self.current_templates.iter() {
            assert_eq!(self.current_tips, BlockHashSet::from_iter(t.block.header.direct_parents().iter().copied()));
        }
        self
    }

    pub async fn validate_and_insert_row(&mut self) -> &mut Self {
        self.current_tips.clear();
        while let Some(t) = self.current_templates.pop_front() {
            self.current_tips.insert(t.block.header.hash);
            self.validate_and_insert_block(t.block.to_immutable()).await;
        }
        self
    }

    pub async fn build_and_insert_disqualified_chain(&mut self, mut parents: Vec<Hash>, len: usize) -> Hash {
        // The chain will be disqualified since build_block_with_parents builds utxo-invalid blocks
        for _ in 0..len {
            self.simulated_time += self.consensus.params().target_time_per_block();
            let b = self.build_block_with_parents(parents, 0, self.simulated_time);
            parents = vec![b.header.hash];
            self.validate_and_insert_block(b.to_immutable()).await;
        }
        parents[0]
    }

    pub fn build_block_template(&self, nonce: u64, timestamp: u64) -> BlockTemplate {
        let mut t = self
            .consensus
            .build_block_template(
                self.miner_data.clone(),
                Box::new(OnetimeTxSelector::new(Default::default())),
                TemplateBuildMode::Standard,
            )
            .unwrap();
        t.block.header.timestamp = timestamp;
        t.block.header.nonce = nonce;
        t.block.header.finalize();
        t
    }

    pub fn build_block_with_parents(&self, parents: Vec<Hash>, nonce: u64, timestamp: u64) -> MutableBlock {
        let mut b = self.consensus.build_block_with_parents_and_transactions(blockhash::NONE, parents, Default::default());
        b.header.timestamp = timestamp;
        b.header.nonce = nonce;
        b.header.finalize(); // This overrides the NONE hash we passed earlier with the actual hash
        b
    }

    pub async fn validate_and_insert_block(&mut self, block: Block) -> &mut Self {
        let status = self.consensus.validate_and_insert_block(block).virtual_state_task.await.unwrap();
        assert!(status.has_block_body());
        self
    }

    pub fn assert_tips(&mut self) -> &mut Self {
        assert_eq!(BlockHashSet::from_iter(self.consensus.get_tips().into_iter()), self.current_tips);
        self
    }

    pub fn assert_tips_num(&mut self, expected_num: usize) -> &mut Self {
        assert_eq!(BlockHashSet::from_iter(self.consensus.get_tips().into_iter()).len(), expected_num);
        self
    }

    pub fn assert_virtual_parents_subset(&mut self) -> &mut Self {
        assert!(self.consensus.get_virtual_parents().is_subset(&self.current_tips));
        self
    }

    pub fn assert_valid_utxo_tip(&mut self) -> &mut Self {
        // Assert that at least one body tip was resolved with valid UTXO
        assert!(self.consensus.body_tips().iter().copied().any(|h| self.consensus.block_status(h) == BlockStatus::StatusUTXOValid));
        self
    }
}

#[tokio::test]
async fn template_mining_sanity_test() {
    let config = ConfigBuilder::new(MAINNET_PARAMS).skip_proof_of_work().build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let rounds = 10;
    let width = 3;
    for _ in 0..rounds {
        ctx.build_block_template_row(0..width)
            .assert_row_parents()
            .validate_and_insert_row()
            .await
            .assert_tips()
            .assert_virtual_parents_subset()
            .assert_valid_utxo_tip();
    }
}

#[tokio::test]
async fn block_template_version_changes_to_v2_upon_activation() {
    let activation = MAINNET_PARAMS.genesis.daa_score + 10;
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| p.toccata_activation = ForkActivation::new(activation))
        .build();
    let consensus = TestConsensus::new(&config);
    let join_handles = consensus.init();
    let miner_data = new_miner_data();

    let mut saw_pre_activation_template = false;
    loop {
        let template = consensus
            .build_block_template(
                miner_data.clone(),
                Box::new(OnetimeTxSelector::new(Default::default())),
                TemplateBuildMode::Standard,
            )
            .unwrap();
        if template.block.header.daa_score >= activation {
            assert!(saw_pre_activation_template);
            assert_eq!(template.block.header.version, TOCCATA_BLOCK_VERSION);
            break;
        }

        saw_pre_activation_template = true;
        assert_eq!(template.block.header.version, BLOCK_VERSION);
        let status = consensus.validate_and_insert_block(template.block.to_immutable()).virtual_state_task.await.unwrap();
        assert!(status.has_block_body());
    }

    consensus.shutdown(join_handles);
}

#[tokio::test]
async fn antichain_merge_test() {
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
        })
        .build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // Build a large 32-wide antichain
    ctx.build_block_template_row(0..32)
        .validate_and_insert_row()
        .await
        .assert_tips()
        .assert_virtual_parents_subset()
        .assert_valid_utxo_tip();

    // Mine a long enough chain s.t. the antichain is fully merged
    for _ in 0..32 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }
    ctx.assert_tips_num(1);
}

#[tokio::test]
async fn basic_utxo_disqualified_test() {
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
        })
        .build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // Mine a valid chain
    for _ in 0..10 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }

    // Get current sink
    let sink = ctx.consensus.get_sink();

    // Mine a longer disqualified chain
    let disqualified_tip = ctx.build_and_insert_disqualified_chain(vec![config.genesis.hash], 20).await;

    assert_ne!(sink, disqualified_tip);
    assert_eq!(sink, ctx.consensus.get_sink());
    assert_eq!(BlockHashSet::from_iter([sink, disqualified_tip]), BlockHashSet::from_iter(ctx.consensus.get_tips().into_iter()));
    assert!(!ctx.consensus.get_virtual_parents().contains(&disqualified_tip));
}

#[tokio::test]
async fn double_search_disqualified_test() {
    // TODO: add non-coinbase transactions and concurrency in order to complicate the test

    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            p.min_difficulty_window_size = p.difficulty_window_size;
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // Mine 3 valid blocks over genesis
    ctx.build_block_template_row(0..3)
        .validate_and_insert_row()
        .await
        .assert_tips()
        .assert_virtual_parents_subset()
        .assert_valid_utxo_tip();

    // Mark the one expected to remain on virtual chain
    let original_sink = ctx.consensus.get_sink();

    // Find the roots to be used for the disqualified chains
    let mut virtual_parents = ctx.consensus.get_virtual_parents();
    assert!(virtual_parents.remove(&original_sink));
    let mut iter = virtual_parents.into_iter();
    let root_1 = iter.next().unwrap();
    let root_2 = iter.next().unwrap();
    assert_eq!(iter.next(), None);

    // Mine a valid chain
    for _ in 0..10 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }

    // Get current sink
    let sink = ctx.consensus.get_sink();

    assert!(ctx.consensus.reachability_service().is_chain_ancestor_of(original_sink, sink));

    // Mine a long disqualified chain
    let disqualified_tip_1 = ctx.build_and_insert_disqualified_chain(vec![root_1], 30).await;

    // And another shorter disqualified chain
    let disqualified_tip_2 = ctx.build_and_insert_disqualified_chain(vec![root_2], 20).await;

    assert_eq!(ctx.consensus.get_block_status(root_1), Some(BlockStatus::StatusUTXOValid));
    assert_eq!(ctx.consensus.get_block_status(root_2), Some(BlockStatus::StatusUTXOValid));

    assert_ne!(sink, disqualified_tip_1);
    assert_ne!(sink, disqualified_tip_2);
    assert_eq!(sink, ctx.consensus.get_sink());
    assert_eq!(
        BlockHashSet::from_iter([sink, disqualified_tip_1, disqualified_tip_2]),
        BlockHashSet::from_iter(ctx.consensus.get_tips().into_iter())
    );
    assert!(!ctx.consensus.get_virtual_parents().contains(&disqualified_tip_1));
    assert!(!ctx.consensus.get_virtual_parents().contains(&disqualified_tip_2));

    // Mine a long enough valid chain s.t. both disqualified chains are fully merged
    for _ in 0..30 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }
    ctx.assert_tips_num(1);
}

fn new_miner_data() -> MinerData {
    let secp = secp256k1::Secp256k1::new();
    let mut rng = rand::thread_rng();
    let (_sk, pk) = secp.generate_keypair(&mut rng);
    let script = ScriptVec::from_slice(&pk.serialize());
    MinerData::new(ScriptPublicKey::new(0, script), vec![])
}

// ---------------------------------------------------------------------------
// KIP-21: compute_finality_anchor - edge-case tests.
//
// Activity window is `[current_bs - activity_threshold, current_bs]`. The
// anchor is the `accepted_id_merkle_root` of the highest chain block at
// `bs <= current_bs - activity_threshold - 1` (the block "just out of" the
// window). All tests below run with `finality_depth = 4`, so
// `activity_threshold = 2`.
// ---------------------------------------------------------------------------

fn finality_anchor_config() -> kaspa_consensus_core::config::Config {
    ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            // activity_threshold = finality_depth / 2 = 2
            p.finality_depth = 4;
            p.toccata_activation = ForkActivation::always();
        })
        .build()
}

/// **ZERO branch** - `current_bs <= activity_threshold` returns `ZERO_HASH`.
///
/// There is no chain block "out of the window" yet: the entire chain is still
/// inside the activity window from `current`'s POV. Runtime processing hits
/// the same early-return at line 1 of `compute_finality_anchor`, so the
/// recorded anchor in `SmtBlockMetadata` matches what the function would
/// return for any caller (runtime or recomputed).
///
/// ```text
///   bs:   0     1     2
///   G ── B1 ── B2
///         ↑     ↑
///         bs=1  bs=2          activity_threshold = 2
///         AT branch: bs <= AT  →  anchor = ZERO_HASH
/// ```
#[tokio::test]
async fn finality_anchor_is_zero_within_activity_threshold() {
    let config = finality_anchor_config();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let activity_threshold = config.activity_threshold();
    assert_eq!(activity_threshold, 2);

    // Mine B1, B2 - both have bs ∈ {1, 2} ≤ activity_threshold.
    let mut chain = vec![config.genesis.hash];
    for _ in 0..2 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
        chain.push(ctx.consensus.get_sink());
    }

    for hash in chain.iter().copied().skip(1) {
        let header = ctx.consensus.get_header(hash).unwrap();
        assert!(header.blue_score <= activity_threshold);
        let meta = ctx.consensus.smt_block_metadata(hash);
        assert_eq!(meta.finality_anchor, kaspa_hashes::ZERO_HASH, "bs={}", header.blue_score);
    }
}

/// **1a branch** - runtime-processed blocks resolve through the coinbase
/// lane SMT lookup with a real `block_hash`, so the anchor is exactly the
/// `accepted_id_merkle_root` of the chain block at `target_bs`.
///
/// Every block updates the coinbase lane via its selected parent's coinbase
/// tx, so for a runtime chain the lane carries one entry per chain block
/// with the real (non-`ZERO_HASH`) block hash. The SMT lookup at
/// `target_bs` therefore returns that exact block - no IBD sentinel, no
/// segment walk, no PP fallback.
///
/// ```text
///   bs:   0     1     2     3     4     5     6
///   G ── B1 ── B2 ── B3 ── B4 ── B5 ── B6
///                     ↑                 ↑
///                     anchor(B6)        current = B6  (bs=6)
///                     target_bs = 6 - 2 - 1 = 3
///                     → chain block at bs≤3 → B3
///
///   coinbase lane    (bs=1, B1)
///   entries          (bs=2, B2)
///   (real hashes,    (bs=3, B3) ← lookup target
///    not ZERO_HASH)  (bs=4, B4)
///                    (bs=5, B5)
///                    (bs=6, B6)
/// ```
#[tokio::test]
async fn finality_anchor_runtime_resolves_via_coinbase_lane() {
    let config = finality_anchor_config();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let activity_threshold = config.activity_threshold();

    // Mine a single-tip chain of length 6: B1..B6 with bs = 1..6.
    let mut chain = Vec::new();
    for _ in 0..6 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
        chain.push(ctx.consensus.get_sink());
    }

    let tip = *chain.last().unwrap();
    let tip_header = ctx.consensus.get_header(tip).unwrap();
    assert_eq!(tip_header.blue_score, 6);
    let target_bs = tip_header.blue_score - activity_threshold - 1; // = 3

    // Locate the chain block at bs == target_bs in our mined chain.
    let expected_block = *chain.iter().find(|h| ctx.consensus.get_header(**h).unwrap().blue_score == target_bs).unwrap();
    let expected_anchor = ctx.consensus.get_header(expected_block).unwrap().accepted_id_merkle_root;

    let recorded = ctx.consensus.smt_block_metadata(tip).finality_anchor;
    assert_eq!(recorded, expected_anchor);
}

/// The SMT coinbase-lane lookup can miss `target_bs` for two reasons:
/// the lane carries only one tip per lane_key, and IBD ships only the
/// active tip per lane in `[pp.bs - F/2, pp.bs]`. In either case the
/// fallback must produce the same anchor as the 1a (real `block_hash`)
/// path on the originating node.
///
/// `BlockDepthManager::calc_block_at_blue_score` is the deterministic
/// fallback: it walks `depth_store.finality_point(sp)` forward to the
/// chain block at the highest `blue_score <= target_bs`, using only
/// consensus state shared by syncer and syncee.
///
/// ```text
///   activity_threshold = 2  (finality_depth = 4)
///
///   bs:  0     1     2     3     4     5     6
///   G    B1    B2    B3    B4    B5    B6
///                     ^                 ^
///                     anchor target     current block (B6)
///                     target_bs = 3     selected_parent = B5
///
///   Fallback walk from sp = B5:
///     finality_point(B5) -> some chain block at bs <= 5 - F = 1
///     forward iterator yields B1, B2, B3, B4, B5
///     advance while bs <= 3:  B1 ok, B2 ok, B3 ok, B4 > 3 break
///     result = B3
///     return header(B3).accepted_id_merkle_root
///
///   Equals header(B3).seq_commit, which 1a also returns from the lane lookup.
/// ```
#[tokio::test]
async fn finality_anchor_fallback_matches_mining_time_for_genesis_hpp() {
    let config = finality_anchor_config();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    for _ in 0..6 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    let b6 = ctx.consensus.get_sink();
    let b6_header = ctx.consensus.get_header(b6).unwrap();
    assert_eq!(b6_header.blue_score, 6);
    assert_eq!(b6_header.pruning_point, config.genesis.hash);

    let mut walker = b6;
    let b3 = loop {
        let header = ctx.consensus.get_header(walker).unwrap();
        if header.blue_score == 3 {
            break walker;
        }
        walker = header.direct_parents()[0];
    };
    let expected_anchor = ctx.consensus.get_header(b3).unwrap().accepted_id_merkle_root;

    assert_eq!(ctx.consensus.smt_block_metadata(b6).finality_anchor, expected_anchor, "1a recorded anchor");

    let b6_ghostdag = ctx.consensus.ghostdag_store().get_data(b6).unwrap();
    let vp = ctx.consensus.virtual_processor();
    let chain_block = vp.depth_manager.calc_block_at_blue_score(&b6_ghostdag, 3);
    let walked_anchor = ctx.consensus.get_header(chain_block).unwrap().accepted_id_merkle_root;
    assert_eq!(walked_anchor, expected_anchor);
}

/// **1c branch (default)** - `target_bs` is below every entry in the
/// coinbase lane and `header_pruning_point` has no stored
/// `SmtBlockMetadata` (the chain is too young for PP to have advanced past
/// genesis). The function falls through 1a → 1b → 1c and returns
/// `ZERO_HASH` via the `unwrap_or` default.
///
/// This is *not* the same code path as the `current_bs <= activity_threshold`
/// early return - the SMT lookup actually runs, returns `None`, and the
/// metadata lookup on genesis also returns `Err`. The observable result is
/// `ZERO_HASH`, which matches runtime behavior because at this chain depth
/// no anchor block exists yet.
///
/// ```text
///   bs:   0     1     2     3
///   G ── B1 ── B2 ── B3
///                     ↑
///                     current = B3       (bs=3)
///                     target_bs = 3 - 2 - 1 = 0
///
///   coinbase lane entries: (bs=1, B1) (bs=2, B2) (bs=3, B3)
///   lookup with bounds(target=0, min=0):
///     scans bs<=0 → no entries (lane never touched at bs=0; genesis
///                  is not processed through the lane path)
///     → None  →  1c
///
///   1c: smt_metadata_store.get(genesis) → Err
///       → unwrap_or(ZERO_HASH)  →  ZERO_HASH
/// ```
#[tokio::test]
async fn finality_anchor_falls_through_to_pp_metadata_when_lane_lookup_misses() {
    let config = finality_anchor_config();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let activity_threshold = config.activity_threshold();

    // Mine exactly activity_threshold + 1 blocks so the tip's target_bs == 0
    // (below the lowest lane entry, which is at bs = 1).
    for _ in 0..(activity_threshold + 1) {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    let tip = ctx.consensus.get_sink();
    let tip_header = ctx.consensus.get_header(tip).unwrap();
    assert_eq!(tip_header.blue_score, activity_threshold + 1);

    // PP is still genesis (PP advancement hasn't kicked in yet for such a
    // short chain), and genesis has no SmtBlockMetadata → ZERO_HASH.
    assert_eq!(tip_header.pruning_point, config.genesis.hash);
    let recorded = ctx.consensus.smt_block_metadata(tip).finality_anchor;
    assert_eq!(recorded, kaspa_hashes::ZERO_HASH);
}
