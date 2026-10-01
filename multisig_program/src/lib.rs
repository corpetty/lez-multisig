//! The LEZ multisig on LEZ v0.3.0's plan/apply ABI (muster's
//! `docs/design/lez-multisig-v03.md`).
//!
//! `plan` sees the instruction and each row's id, authorization and shard; it checks what
//! it can without data and emits one effect per shard. `apply` sees one shard's data and
//! checks or changes it. Both applies of a transaction must pass, so a check that spans the
//! state and a proposal is an effect on each.

use borsh::BorshDeserialize;
use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{AccountMeta, ChainedCall, PdaSeed, Plan, PlanInput},
};
use multisig_core::{
    Commitment, ConfigAction, Effect, Instruction, MAX_MEMBERS, Member, MultisigState, Proposal,
    ProposalStatus, TargetCall, proposal_pda, state_pda, vault_seed,
};

fn own(input: &PlanInput, row: &AccountMeta, expected: AccountId, what: &str) {
    assert_eq!(row.account_id, expected, "the {what} row is not this multisig's {what}");
    assert_eq!(
        row.program_account_id, input.self_account_id,
        "the {what} row names another program's shard"
    );
}

fn signer(row: &AccountMeta, what: &str) -> Member {
    assert!(row.is_authorized, "the {what} did not sign");
    *row.account_id.value()
}

fn check_target(create_key: &[u8; 32], target: &TargetCall) {
    // The seeds authorize the callee to move PDAs of this program. Only this multisig's own
    // vault: another multisig's vault derives from the same program, and naming its seed
    // would let this multisig's quorum move it.
    let vault = vault_seed(create_key);
    assert!(
        target.pda_seeds.iter().all(|s| *s == vault),
        "a proposal may authorize only its own multisig's vault"
    );
}

fn check_config(action: &ConfigAction) {
    if let ConfigAction::ChangeThreshold { new_threshold } = action {
        assert!(*new_threshold >= 1, "a threshold is at least 1");
    }
}

fn chained(call: &TargetCall) -> ChainedCall {
    ChainedCall {
        program_account_id: AccountId::new(call.program_account_id),
        shard_selectors: call
            .shard_selectors
            .iter()
            .map(|(a, p)| ProgramShardSelector { account_id: AccountId::new(*a), program_account_id: AccountId::new(*p) })
            .collect(),
        instruction_data: call.instruction_data.clone(),
        pda_seeds: call.pda_seeds.iter().map(|s| PdaSeed::new(*s)).collect(),
    }
}

/// What the instruction asks of each shard, checked as far as no data allows.
#[must_use]
pub fn plan(input: &PlanInput, instruction: Instruction) -> Plan {
    let me = input.self_account_id;
    let rows = &input.accounts;
    let mut plan = Plan::new(input);
    match instruction {
        Instruction::CreateMultisig { create_key, threshold, members } => {
            assert_eq!(rows.len(), 1, "CreateMultisig takes one row, the state");
            own(input, &rows[0], state_pda(&me, &create_key), "state");
            assert!(!members.is_empty() && members.len() <= MAX_MEMBERS, "1 to {MAX_MEMBERS} members");
            for (i, m) in members.iter().enumerate() {
                assert!(!members[..i].contains(m), "a member appears twice");
            }
            assert!(threshold >= 1 && usize::from(threshold) <= members.len(), "1 ≤ threshold ≤ members");
            let member_count = u8::try_from(members.len()).expect("at most 10 members");
            plan.effect(
                &rows[0],
                &Effect::Init(MultisigState { create_key, threshold, member_count, members, transaction_index: 0 }),
            );
        }
        Instruction::Propose { create_key, index, target } => {
            check_target(&create_key, &target);
            propose(&mut plan, input, create_key, index, Commitment::Call(target));
        }
        Instruction::ProposeConfig { create_key, index, action } => {
            check_config(&action);
            propose(&mut plan, input, create_key, index, Commitment::Config(action));
        }
        Instruction::Approve { create_key, index } => vote(&mut plan, input, create_key, index, true),
        Instruction::Reject { create_key, index } => vote(&mut plan, input, create_key, index, false),
        Instruction::Execute { create_key, index, approvers, call } => {
            assert_eq!(rows.len(), 2, "Execute takes two rows, the state and the proposal");
            own(input, &rows[0], state_pda(&me, &create_key), "state");
            own(input, &rows[1], proposal_pda(&me, &create_key, index), "proposal");
            check_target(&create_key, &call);
            let commitment = Commitment::Call(call.clone()).hash();
            plan.effect(&rows[0], &Effect::Quorum { approvers: approvers.clone() });
            plan.effect(&rows[1], &Effect::Close { approvers, commitment });
            plan.call(chained(&call));
        }
        Instruction::ExecuteConfig { create_key, index, approvers, action } => {
            assert_eq!(rows.len(), 2, "ExecuteConfig takes two rows, the state and the proposal");
            own(input, &rows[0], state_pda(&me, &create_key), "state");
            own(input, &rows[1], proposal_pda(&me, &create_key, index), "proposal");
            let commitment = Commitment::Config(action.clone()).hash();
            plan.effect(&rows[0], &Effect::QuorumThenApply { approvers: approvers.clone(), action });
            plan.effect(&rows[1], &Effect::Close { approvers, commitment });
        }
    }
    plan
}

fn propose(plan: &mut Plan, input: &PlanInput, create_key: [u8; 32], index: u64, commitment: Commitment) {
    let rows = &input.accounts;
    let me = input.self_account_id;
    assert_eq!(rows.len(), 3, "a proposal takes three rows: the state, the proposal, the proposer");
    own(input, &rows[0], state_pda(&me, &create_key), "state");
    own(input, &rows[1], proposal_pda(&me, &create_key, index), "proposal");
    let proposer = signer(&rows[2], "proposer");
    plan.effect(&rows[0], &Effect::TakeIndex { proposer, index });
    plan.effect(
        &rows[1],
        &Effect::Open(Proposal {
            index,
            proposer,
            multisig_create_key: create_key,
            commitment,
            approved: vec![proposer],
            rejected: vec![],
            status: ProposalStatus::Active,
        }),
    );
}

fn vote(plan: &mut Plan, input: &PlanInput, create_key: [u8; 32], index: u64, approve: bool) {
    let rows = &input.accounts;
    let me = input.self_account_id;
    assert_eq!(rows.len(), 3, "a vote takes three rows: the state, the proposal, the voter");
    own(input, &rows[0], state_pda(&me, &create_key), "state");
    own(input, &rows[1], proposal_pda(&me, &create_key, index), "proposal");
    let voter = signer(&rows[2], "voter");
    plan.effect(&rows[0], &Effect::Member { voter });
    plan.effect(&rows[1], &Effect::Vote { voter, approve });
}

fn state_of(pre: &[u8]) -> MultisigState {
    assert!(!pre.is_empty(), "no multisig here");
    MultisigState::try_from_slice(pre).expect("not a multisig state")
}

fn proposal_of(pre: &[u8]) -> Proposal {
    assert!(!pre.is_empty(), "no proposal here");
    Proposal::try_from_slice(pre).expect("not a proposal")
}

fn quorum(state: &MultisigState, approvers: &[Member]) {
    for (i, a) in approvers.iter().enumerate() {
        assert!(!approvers[..i].contains(a), "an approver is named twice");
        assert!(state.members.contains(a), "an approver is not a current member");
    }
    assert!(approvers.len() >= usize::from(state.threshold), "fewer approvers than the threshold");
}

fn enc<T: borsh::BorshSerialize>(v: &T) -> Option<Vec<u8>> {
    Some(borsh::to_vec(v).expect("borsh serialization is infallible"))
}

/// One shard's part: check it, and return its new data (None keeps it).
#[must_use]
pub fn apply(effect: Effect, pre: &[u8]) -> Option<Vec<u8>> {
    match effect {
        Effect::Init(state) => {
            assert!(pre.is_empty(), "a multisig already exists here");
            enc(&state)
        }
        Effect::TakeIndex { proposer, index } => {
            let mut state = state_of(pre);
            assert!(state.members.contains(&proposer), "the proposer is not a member");
            assert_eq!(index, state.transaction_index + 1, "not the next proposal index");
            state.transaction_index = index;
            enc(&state)
        }
        Effect::Member { voter } => {
            assert!(state_of(pre).members.contains(&voter), "the voter is not a member");
            None
        }
        Effect::Quorum { approvers } => {
            quorum(&state_of(pre), &approvers);
            None
        }
        Effect::QuorumThenApply { approvers, action } => {
            let mut state = state_of(pre);
            quorum(&state, &approvers);
            match action {
                ConfigAction::AddMember { new_member } => {
                    assert!(!state.members.contains(&new_member), "already a member");
                    assert!(state.members.len() < MAX_MEMBERS, "at most {MAX_MEMBERS} members");
                    state.members.push(new_member);
                }
                ConfigAction::RemoveMember { member } => {
                    assert!(state.members.contains(&member), "not a member");
                    assert!(
                        state.members.len() > usize::from(state.threshold),
                        "removing a member would leave fewer members than the threshold"
                    );
                    state.members.retain(|m| *m != member);
                }
                ConfigAction::ChangeThreshold { new_threshold } => {
                    assert!(
                        new_threshold >= 1 && usize::from(new_threshold) <= state.members.len(),
                        "1 ≤ threshold ≤ members"
                    );
                    state.threshold = new_threshold;
                }
            }
            state.member_count = u8::try_from(state.members.len()).expect("at most 10 members");
            enc(&state)
        }
        Effect::Open(proposal) => {
            assert!(pre.is_empty(), "a proposal already exists here");
            enc(&proposal)
        }
        Effect::Vote { voter, approve } => {
            let mut p = proposal_of(pre);
            assert_eq!(p.status, ProposalStatus::Active, "the proposal is no longer active");
            if approve {
                assert!(!p.approved.contains(&voter), "already approved");
                p.rejected.retain(|r| *r != voter);
                p.approved.push(voter);
            } else {
                assert!(!p.rejected.contains(&voter), "already rejected");
                p.approved.retain(|a| *a != voter);
                p.rejected.push(voter);
            }
            enc(&p)
        }
        Effect::Close { approvers, commitment } => {
            let mut p = proposal_of(pre);
            assert_eq!(p.status, ProposalStatus::Active, "the proposal is no longer active");
            assert_eq!(p.commitment.hash(), commitment, "not the call this proposal commits to");
            for a in &approvers {
                assert!(p.approved.contains(a), "a named approver did not approve this proposal");
            }
            p.status = ProposalStatus::Executed;
            enc(&p)
        }
    }
}

#[cfg(test)]
mod tests;
