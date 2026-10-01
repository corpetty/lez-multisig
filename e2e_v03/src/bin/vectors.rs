//! Vectors for clients of the v0.3 multisig (muster's `module/tests/vectors/lez-multisig-v030`):
//! the borsh bytes of a state, a call proposal, a config proposal and every instruction, and
//! the PDAs, all from `multisig_core` itself. Printed as one JSON object.

use borsh::BorshSerialize;
use lee_core::account::AccountId;
use multisig_core::*;
use serde_json::{Value, json};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn bor<T: BorshSerialize>(v: &T) -> String {
    hex(&borsh::to_vec(v).unwrap())
}

fn main() {
    let program = AccountId::new([0x11; 32]);
    let create_key = [0x22; 32];
    let (a, b, c, r) = ([0x01; 32], [0x02; 32], [0x03; 32], [0x0e; 32]);
    let vault = vault_pda(&program, &create_key);
    let call = TargetCall {
        program_account_id: [0; 32],
        shard_selectors: vec![(*vault.value(), [0; 32]), (r, [0; 32])],
        instruction_data: borsh::to_vec(&lee_core::native_token::Instruction::Transfer { amount: 100 }).unwrap(),
        pda_seeds: vec![vault_seed(&create_key)],
    };
    let action = ConfigAction::ChangeThreshold { new_threshold: 3 };
    let state = MultisigState { create_key, threshold: 2, member_count: 3, members: vec![a, b, c], transaction_index: 1 };
    let call_proposal = Proposal {
        index: 1, proposer: a, multisig_create_key: create_key, commitment: Commitment::Call(call.clone()),
        approved: vec![a, b], rejected: vec![c], status: ProposalStatus::Active,
    };
    let config_proposal = Proposal {
        index: 2, proposer: b, multisig_create_key: create_key, commitment: Commitment::Config(action.clone()),
        approved: vec![b], rejected: vec![], status: ProposalStatus::Executed,
    };
    let instructions: Vec<(&str, Instruction)> = vec![
        ("create", Instruction::CreateMultisig { create_key, threshold: 2, members: vec![a, b, c] }),
        ("propose", Instruction::Propose { create_key, index: 1, target: call.clone() }),
        ("propose-config", Instruction::ProposeConfig { create_key, index: 2, action: action.clone() }),
        ("propose-config-add", Instruction::ProposeConfig { create_key, index: 3, action: ConfigAction::AddMember { new_member: r } }),
        ("propose-config-remove", Instruction::ProposeConfig { create_key, index: 4, action: ConfigAction::RemoveMember { member: c } }),
        ("approve", Instruction::Approve { create_key, index: 1 }),
        ("reject", Instruction::Reject { create_key, index: 1 }),
        ("execute", Instruction::Execute { create_key, index: 1, approvers: vec![a, b], call: call.clone() }),
        ("execute-config", Instruction::ExecuteConfig { create_key, index: 2, approvers: vec![a, b], action }),
    ];
    let ins: serde_json::Map<String, Value> =
        instructions.iter().map(|(k, i)| ((*k).to_string(), json!(bor(i)))).collect();
    let out = json!({
        "source": "lez-multisig v0.3 port, multisig_core (branch feat/lee-v0.3.0)",
        "program": hex(program.value()),
        "create_key": hex(&create_key),
        "members": [hex(&a), hex(&b), hex(&c)],
        "recipient": hex(&r),
        "vault_seed": hex(&vault_seed(&create_key)),
        "pdas": {
            "state": hex(state_pda(&program, &create_key).value()),
            "proposal1": hex(proposal_pda(&program, &create_key, 1).value()),
            "proposal2": hex(proposal_pda(&program, &create_key, 2).value()),
            "vault": hex(vault.value()),
        },
        "transfer_instruction": hex(&call.instruction_data),
        "state": bor(&state),
        "call_proposal": bor(&call_proposal),
        "config_proposal": bor(&config_proposal),
        "call_commitment_hash": hex(&Commitment::Call(call).hash()),
        "instructions": ins,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
