//! The program in process: each transaction is plan, then every effect's apply against an
//! in-memory set of shards, all or nothing — what the chain does, without the zkVM.

use std::{collections::HashMap, panic};

use borsh::BorshDeserialize;
use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{AccountMeta, PlanInput},
};
use multisig_core::*;

use crate::{apply, plan};

type Shards = HashMap<(AccountId, AccountId), Vec<u8>>;

const P: [u8; 32] = [7; 32];
const CK: [u8; 32] = [9; 32];
const A: Member = [1; 32];
const B: Member = [2; 32];
const C: Member = [3; 32];
const OUTSIDER: Member = [4; 32];

fn program() -> AccountId {
    AccountId::new(P)
}

fn row(id: AccountId, authorized: bool) -> AccountMeta {
    AccountMeta::new(id, authorized, program())
}

fn signer_row(m: Member, signed: bool) -> AccountMeta {
    // a member passed for authorization only: no effect lands on its row
    AccountMeta::new(AccountId::new(m), signed, program())
}

/// Plan, then every apply; the shards change only if every apply passes. Err(the first
/// panic's message) otherwise. Ok(the chained calls) on success.
fn tx(shards: &mut Shards, accounts: Vec<AccountMeta>, ins: Instruction) -> Result<Vec<lee_core::program::ChainedCall>, String> {
    let input = PlanInput {
        self_account_id: program(),
        caller_account_id: None,
        accounts,
        instruction_data: borsh::to_vec(&ins).unwrap(),
    };
    let before = shards.clone();
    let out = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let p = plan(&input, ins);
        let output = p.output().clone();
        let mut next = shards.clone();
        for e in &output.effects {
            let sel: &ProgramShardSelector = &e.selector;
            let key = (sel.account_id, sel.program_account_id);
            let pre = next.get(&key).cloned().unwrap_or_default();
            let effect = Effect::try_from_slice(&e.data).unwrap();
            if let Some(post) = apply(effect, &pre) {
                next.insert(key, post);
            }
        }
        (next, output.chained_calls)
    }));
    match out {
        Ok((next, calls)) => {
            *shards = next;
            Ok(calls)
        }
        Err(e) => {
            *shards = before;
            Err(e.downcast_ref::<String>().cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                .unwrap_or_default())
        }
    }
}

fn refused(r: Result<Vec<lee_core::program::ChainedCall>, String>, why: &str) {
    match r {
        Ok(_) => panic!("expected a refusal naming '{why}', it passed"),
        Err(m) => assert!(m.contains(why), "expected '{why}', got '{m}'"),
    }
}

fn state(shards: &Shards) -> MultisigState {
    MultisigState::try_from_slice(&shards[&(state_pda(&program(), &CK), program())]).unwrap()
}

fn proposal(shards: &Shards, i: u64) -> Proposal {
    Proposal::try_from_slice(&shards[&(proposal_pda(&program(), &CK, i), program())]).unwrap()
}

fn st() -> AccountMeta {
    row(state_pda(&program(), &CK), false)
}

fn pr(i: u64) -> AccountMeta {
    row(proposal_pda(&program(), &CK, i), false)
}

/// A native transfer of `amount` out of the vault to `to`.
fn transfer_out(to: [u8; 32], amount: u128) -> TargetCall {
    let native = [0_u8; 32];
    let mut ins = vec![0_u8];
    ins.extend_from_slice(&amount.to_le_bytes());
    TargetCall {
        program_account_id: native,
        shard_selectors: vec![(*vault_pda(&program(), &CK).value(), native), (to, native)],
        instruction_data: ins,
        pda_seeds: vec![vault_seed(&CK)],
    }
}

fn two_of_three() -> Shards {
    let mut s = Shards::new();
    tx(&mut s, vec![st()], Instruction::CreateMultisig { create_key: CK, threshold: 2, members: vec![A, B, C] }).unwrap();
    s
}

#[test]
fn create() {
    let s = two_of_three();
    let m = state(&s);
    assert_eq!((m.threshold, m.member_count, m.members.clone(), m.transaction_index), (2, 3, vec![A, B, C], 0));
    let mut s = s;
    refused(tx(&mut s, vec![st()], Instruction::CreateMultisig { create_key: CK, threshold: 1, members: vec![A] }), "already exists");
    let mut e = Shards::new();
    refused(tx(&mut e, vec![st()], Instruction::CreateMultisig { create_key: CK, threshold: 3, members: vec![A, B] }), "threshold");
    refused(tx(&mut e, vec![st()], Instruction::CreateMultisig { create_key: CK, threshold: 1, members: vec![A, A] }), "twice");
    // another program's shard, or another account, is not this multisig's state
    let wrong = AccountMeta::new(state_pda(&program(), &CK), false, AccountId::new([5; 32]));
    refused(tx(&mut e, vec![wrong], Instruction::CreateMultisig { create_key: CK, threshold: 1, members: vec![A] }), "another program");
}

#[test]
fn propose_and_vote() {
    let mut s = two_of_three();
    let call = transfer_out([8; 32], 100);
    tx(&mut s, vec![st(), pr(1), signer_row(A, true)], Instruction::Propose { create_key: CK, index: 1, target: call.clone() }).unwrap();
    assert_eq!(state(&s).transaction_index, 1);
    let p = proposal(&s, 1);
    assert_eq!((p.proposer, p.approved.clone(), p.status), (A, vec![A], ProposalStatus::Active));
    // not the next index; not a member; not signed
    refused(tx(&mut s, vec![st(), pr(3), signer_row(B, true)], Instruction::Propose { create_key: CK, index: 3, target: call.clone() }), "next proposal");
    refused(tx(&mut s, vec![st(), pr(2), signer_row(OUTSIDER, true)], Instruction::Propose { create_key: CK, index: 2, target: call.clone() }), "not a member");
    refused(tx(&mut s, vec![st(), pr(2), signer_row(B, false)], Instruction::Propose { create_key: CK, index: 2, target: call.clone() }), "did not sign");
    // votes
    tx(&mut s, vec![st(), pr(1), signer_row(C, true)], Instruction::Reject { create_key: CK, index: 1 }).unwrap();
    tx(&mut s, vec![st(), pr(1), signer_row(C, true)], Instruction::Approve { create_key: CK, index: 1 }).unwrap();
    let p = proposal(&s, 1);
    assert_eq!((p.approved.clone(), p.rejected.clone()), (vec![A, C], vec![]));
    refused(tx(&mut s, vec![st(), pr(1), signer_row(C, true)], Instruction::Approve { create_key: CK, index: 1 }), "already approved");
    refused(tx(&mut s, vec![st(), pr(1), signer_row(OUTSIDER, true)], Instruction::Approve { create_key: CK, index: 1 }), "not a member");
}

#[test]
fn execute() {
    let mut s = two_of_three();
    let call = transfer_out([8; 32], 100);
    tx(&mut s, vec![st(), pr(1), signer_row(A, true)], Instruction::Propose { create_key: CK, index: 1, target: call.clone() }).unwrap();
    // one approval is short of the threshold
    refused(tx(&mut s, vec![st(), pr(1)], Instruction::Execute { create_key: CK, index: 1, approvers: vec![A], call: call.clone() }), "threshold");
    // naming someone who did not approve does not help
    refused(tx(&mut s, vec![st(), pr(1)], Instruction::Execute { create_key: CK, index: 1, approvers: vec![A, B], call: call.clone() }), "did not approve");
    tx(&mut s, vec![st(), pr(1), signer_row(B, true)], Instruction::Approve { create_key: CK, index: 1 }).unwrap();
    // a substituted call (another recipient) is not the one committed
    refused(tx(&mut s, vec![st(), pr(1)], Instruction::Execute { create_key: CK, index: 1, approvers: vec![A, B], call: transfer_out([6; 32], 100) }), "commits to");
    let calls = tx(&mut s, vec![st(), pr(1)], Instruction::Execute { create_key: CK, index: 1, approvers: vec![A, B], call: call.clone() }).unwrap();
    assert_eq!(proposal(&s, 1).status, ProposalStatus::Executed);
    assert_eq!(calls.len(), 1);
    let c = &calls[0];
    assert_eq!(*c.program_account_id.value(), [0; 32], "the native token program");
    assert_eq!(*c.shard_selectors[1].account_id.value(), [8; 32], "the committed recipient");
    assert_eq!(c.instruction_data, call.instruction_data);
    assert_eq!(*c.pda_seeds[0].as_bytes(), vault_seed(&CK), "authorizes the vault");
    // once only
    refused(tx(&mut s, vec![st(), pr(1)], Instruction::Execute { create_key: CK, index: 1, approvers: vec![A, B], call }), "no longer active");
}

#[test]
fn only_its_own_vault() {
    // another multisig's vault derives from the same program; naming its seed would let
    // this multisig's quorum move it
    let mut s = two_of_three();
    let mut call = transfer_out([8; 32], 100);
    call.pda_seeds = vec![vault_seed(&[10; 32])];
    refused(tx(&mut s, vec![st(), pr(1), signer_row(A, true)], Instruction::Propose { create_key: CK, index: 1, target: call.clone() }), "its own multisig's vault");
    refused(tx(&mut s, vec![st(), pr(1)], Instruction::Execute { create_key: CK, index: 1, approvers: vec![A, B], call }), "its own multisig's vault");
}

#[test]
fn config_and_current_members() {
    let mut s = two_of_three();
    let call = transfer_out([8; 32], 100);
    tx(&mut s, vec![st(), pr(1), signer_row(A, true)], Instruction::Propose { create_key: CK, index: 1, target: call.clone() }).unwrap();
    tx(&mut s, vec![st(), pr(1), signer_row(C, true)], Instruction::Approve { create_key: CK, index: 1 }).unwrap();
    // remove C (A and B agree)
    let remove = ConfigAction::RemoveMember { member: C };
    tx(&mut s, vec![st(), pr(2), signer_row(A, true)], Instruction::ProposeConfig { create_key: CK, index: 2, action: remove.clone() }).unwrap();
    tx(&mut s, vec![st(), pr(2), signer_row(B, true)], Instruction::Approve { create_key: CK, index: 2 }).unwrap();
    tx(&mut s, vec![st(), pr(2)], Instruction::ExecuteConfig { create_key: CK, index: 2, approvers: vec![A, B], action: remove }).unwrap();
    assert_eq!((state(&s).members.clone(), state(&s).member_count), (vec![A, B], 2));
    // C's approval of #1 no longer counts: C is not a current member
    refused(tx(&mut s, vec![st(), pr(1)], Instruction::Execute { create_key: CK, index: 1, approvers: vec![A, C], call: call.clone() }), "not a current member");
    // the threshold can change, within the members
    let t = ConfigAction::ChangeThreshold { new_threshold: 1 };
    tx(&mut s, vec![st(), pr(3), signer_row(A, true)], Instruction::ProposeConfig { create_key: CK, index: 3, action: t.clone() }).unwrap();
    tx(&mut s, vec![st(), pr(3), signer_row(B, true)], Instruction::Approve { create_key: CK, index: 3 }).unwrap();
    tx(&mut s, vec![st(), pr(3)], Instruction::ExecuteConfig { create_key: CK, index: 3, approvers: vec![A, B], action: t }).unwrap();
    assert_eq!(state(&s).threshold, 1);
    // now A alone executes #1
    tx(&mut s, vec![st(), pr(1)], Instruction::Execute { create_key: CK, index: 1, approvers: vec![A], call }).unwrap();
    // a config action is held to what was proposed, too
    let add = ConfigAction::AddMember { new_member: OUTSIDER };
    tx(&mut s, vec![st(), pr(4), signer_row(A, true)], Instruction::ProposeConfig { create_key: CK, index: 4, action: add }).unwrap();
    refused(tx(&mut s, vec![st(), pr(4)], Instruction::ExecuteConfig { create_key: CK, index: 4, approvers: vec![A], action: ConfigAction::AddMember { new_member: [5; 32] } }), "commits to");
}

#[test]
fn pdas_are_v024s() {
    // the seeds and formula muster derives (lez/multisig.nim, psLee02): one seed as is,
    // several hashed together, strings zero-padded, integers little-endian
    assert_eq!(state_seed(&CK), CK);
    assert_eq!(&seed_from_str("multisig_prop___")[..16], b"multisig_prop___");
    assert_eq!(seed_u64(258)[..2], [2, 1]);
    assert_ne!(proposal_seed(&CK, 1), proposal_seed(&CK, 2));
    assert_ne!(vault_pda(&program(), &CK), state_pda(&program(), &CK));
}
