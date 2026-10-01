//! The LEZ multisig's types on LEZ v0.3.0: its state, its proposals, its instructions, the
//! effects its plan emits, and the PDAs it owns. Shared by the program (plan/apply) and by
//! anyone who builds its transactions or reads its accounts.
//!
//! The design is muster's `docs/design/lez-multisig-v03.md`. In short, LEZ v0.3 programs
//! are `run_program(plan, apply)`: plan sees account ids and authorization but no data,
//! and emits one effect per shard; apply sees one shard's data and checks or changes it.
//! A check that spans accounts is an effect on each shard, carrying the claim that shard
//! must check.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{account::AccountId, program::PdaSeed};
use sha2::{Digest as _, Sha256};

/// A member: a public account id (32 bytes, derived from the member's key).
pub type Member = [u8; 32];

/// At most this many members (as in v0.2.4).
pub const MAX_MEMBERS: usize = 10;

// ---------------------------------------------------------------------------
// PDAs: SPEL's seeds, as v0.2.4 derived them, under LEZ's public-PDA formula
// ---------------------------------------------------------------------------

/// A string seed: its bytes, zero-padded to 32 (SPEL's `seed_from_str`).
#[must_use]
pub fn seed_from_str(s: &str) -> [u8; 32] {
    assert!(s.len() <= 32, "a seed string is at most 32 bytes");
    let mut out = [0_u8; 32];
    out[..s.len()].copy_from_slice(s.as_bytes());
    out
}

/// An integer seed: its little-endian bytes, zero-padded to 32.
#[must_use]
pub fn seed_u64(x: u64) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out[..8].copy_from_slice(&x.to_le_bytes());
    out
}

/// Several seeds as one: used as is when there is one, else SHA-256 of their concatenation.
#[must_use]
pub fn combine_seeds(seeds: &[[u8; 32]]) -> [u8; 32] {
    assert!(!seeds.is_empty(), "a PDA needs at least one seed");
    if seeds.len() == 1 {
        return seeds[0];
    }
    let mut h = Sha256::new();
    for s in seeds {
        h.update(s);
    }
    h.finalize().into()
}

#[must_use]
pub fn state_seed(create_key: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[*create_key])
}

#[must_use]
pub fn proposal_seed(create_key: &[u8; 32], index: u64) -> [u8; 32] {
    combine_seeds(&[seed_from_str("multisig_prop___"), *create_key, seed_u64(index)])
}

#[must_use]
pub fn vault_seed(create_key: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[seed_from_str("multisig_vault__"), *create_key])
}

/// The PDA `program` owns under `seed`: SHA-256("/LEE/v0.2/AccountId/PDA/" ‖ program ‖ seed).
#[must_use]
pub fn pda(program: &AccountId, seed: [u8; 32]) -> AccountId {
    AccountId::for_public_pda(program, &PdaSeed::new(seed))
}

#[must_use]
pub fn state_pda(program: &AccountId, create_key: &[u8; 32]) -> AccountId {
    pda(program, state_seed(create_key))
}

#[must_use]
pub fn proposal_pda(program: &AccountId, create_key: &[u8; 32], index: u64) -> AccountId {
    pda(program, proposal_seed(create_key, index))
}

#[must_use]
pub fn vault_pda(program: &AccountId, create_key: &[u8; 32]) -> AccountId {
    pda(program, vault_seed(create_key))
}

// ---------------------------------------------------------------------------
// What a proposal commits to
// ---------------------------------------------------------------------------

/// The call a proposal makes when it executes, in LEZ v0.3's shape: the program by its
/// account id, every row it touches (account and which program's shard), the instruction
/// as the callee's borsh bytes, and the PDA seeds that authorize the callee to move this
/// multisig's accounts (its vault). The rows name every account, so a recipient is
/// committed by construction.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TargetCall {
    pub program_account_id: [u8; 32],
    pub shard_selectors: Vec<([u8; 32], [u8; 32])>,
    pub instruction_data: Vec<u8>,
    pub pda_seeds: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ConfigAction {
    AddMember { new_member: Member },
    RemoveMember { member: Member },
    ChangeThreshold { new_threshold: u8 },
}

/// What Execute and ExecuteConfig carry, and what the proposal's apply checks it against.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Commitment {
    Call(TargetCall),
    Config(ConfigAction),
}

const COMMITMENT_PREFIX: &[u8; 32] = b"/lez-multisig/v0.3/Commitment/\x00\x00";

impl Commitment {
    /// SHA-256(prefix ‖ borsh(self)): what an Execute names and a proposal is held to.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(COMMITMENT_PREFIX);
        h.update(borsh::to_vec(self).expect("borsh serialization is infallible"));
        h.finalize().into()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ProposalStatus {
    Active,
    Executed,
}

/// A proposal, in its own PDA's shard.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Proposal {
    pub index: u64,
    pub proposer: Member,
    pub multisig_create_key: [u8; 32],
    pub commitment: Commitment,
    pub approved: Vec<Member>,
    pub rejected: Vec<Member>,
    pub status: ProposalStatus,
}

/// The multisig, in its state PDA's shard. The same borsh layout as v0.2.4's.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MultisigState {
    pub create_key: [u8; 32],
    pub threshold: u8,
    pub member_count: u8,
    pub members: Vec<Member>,
    /// The last proposal's index (proposals count from 1).
    pub transaction_index: u64,
}

// ---------------------------------------------------------------------------
// Instructions: what a transaction asks for
// ---------------------------------------------------------------------------

/// Rows, in order, for every instruction: the state PDA, then (but for CreateMultisig) the
/// proposal PDA, then (for Propose, ProposeConfig, Approve and Reject) the signing member.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Create a multisig: `threshold` of `members`. Rows: [state].
    CreateMultisig { create_key: [u8; 32], threshold: u8, members: Vec<Member> },
    /// A member proposes a call, as proposal `index` (the next one). Rows: [state, proposal, proposer].
    Propose { create_key: [u8; 32], index: u64, target: TargetCall },
    /// A member proposes a change of members or threshold. Rows: [state, proposal, proposer].
    ProposeConfig { create_key: [u8; 32], index: u64, action: ConfigAction },
    /// A member approves. Rows: [state, proposal, voter].
    Approve { create_key: [u8; 32], index: u64 },
    /// A member rejects. Rows: [state, proposal, voter].
    Reject { create_key: [u8; 32], index: u64 },
    /// Run the proposal's call, naming the approvers counted. Rows: [state, proposal]. The
    /// call's own rows follow in the chained call, not here.
    Execute { create_key: [u8; 32], index: u64, approvers: Vec<Member>, call: TargetCall },
    /// Apply the proposal's config change, naming the approvers counted. Rows: [state, proposal].
    ExecuteConfig { create_key: [u8; 32], index: u64, approvers: Vec<Member>, action: ConfigAction },
}

// ---------------------------------------------------------------------------
// Effects: what plan asks of each shard
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Effect {
    /// State: the shard is empty; write this.
    Init(MultisigState),
    /// State: `proposer` is a member and `index` is the next proposal; take it.
    TakeIndex { proposer: Member, index: u64 },
    /// State: `voter` is a member (a guard; the state does not change).
    Member { voter: Member },
    /// State: the approvers are distinct current members, at least threshold of them (a guard).
    Quorum { approvers: Vec<Member> },
    /// State: the quorum above, then apply the config action.
    QuorumThenApply { approvers: Vec<Member>, action: ConfigAction },
    /// Proposal: the shard is empty; write this.
    Open(Proposal),
    /// Proposal: still active; record the vote.
    Vote { voter: Member, approve: bool },
    /// Proposal: still active, every approver approved it, and it commits to `commitment`;
    /// then it is executed.
    Close { approvers: Vec<Member>, commitment: [u8; 32] },
}
