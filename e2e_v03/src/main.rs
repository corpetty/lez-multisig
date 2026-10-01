//! The multisig on a running LEZ v0.3.0 sequencer.
//!
//!   e2e_v03 <sequencer url> <program account (base58)> <fund command>
//!
//! `<fund command>` is run as `<fund command> <account hex> <amount>` to send native LEZ to
//! an account (e.g. muster's `infra/lez/localnet.sh fund`, whose genesis funder stands in
//! for anyone holding native LEZ: v0.3 has no faucet). Every member pays its own fee.
//!
//!   1. a 2-of-3 is created; its vault is funded by transfer;
//!   2. A proposes a native transfer of 100 out of the vault to R; B approves;
//!   3. an outsider's vote, a substituted recipient and a second multisig naming this
//!      vault's seed are refused, and nothing moves;
//!   4. Execute, naming A and B: R holds 100, the vault 100 less, the proposal is executed;
//!   5. Execute again is refused.
//!
//! On v0.3 a transaction whose program refuses is still INCLUDED: it reverts, keeps its fee
//! and burns its signers' nonces (`lez/chain_state/src/apply.rs`, "a failed action is
//! ordinary execution semantics"), and the RPC reports no outcome. So inclusion says nothing
//! about whether a call took effect: every step here is judged by the state it reads back.
//! A refused call is charged its whole gas limit (`ValidatedStateDiff::
//! from_public_transaction_metered`: any failure but a clean non-zero exit bills the budget);
//! one that succeeds pays for the cycles it ran.

use std::{process::Command, thread::sleep, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use borsh::BorshSerialize;
use common::transaction::LeeTransaction;
use lee::{
    FeeDeclaration, PrivateKey, PublicKey, PublicTransaction,
    public_transaction::{Message, WitnessSet},
};
use lee_core::account::{AccountId, Nonce, ProgramShardSelector};
use multisig_core::*;
use serde_json::{Value, json};

const NATIVE: [u8; 32] = [0; 32];
const GAS: u64 = 2_000_000;
const MAX_FEE: u128 = (GAS as u128 + 100_000) * 64;

struct Chain {
    url: String,
    program: AccountId,
    fund_cmd: String,
}

impl Chain {
    fn rpc(&self, method: &str, params: Value) -> Value {
        let r: Value = ureq::post(&self.url)
            .send_json(json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
            .expect("the sequencer answers")
            .into_json()
            .expect("JSON");
        r
    }

    /// (nonce, shards: program base58 → bytes)
    fn account(&self, id: &AccountId) -> (u128, serde_json::Map<String, Value>) {
        let r = self.rpc("getAccount", json!([id.to_string()]));
        let a = &r["result"];
        let nonce = a["nonce"].as_u64().map(u128::from)
            .or_else(|| a["nonce"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0);
        (nonce, a["data"]["shards"].as_object().cloned().unwrap_or_default())
    }

    fn shard(&self, id: &AccountId, program: &AccountId) -> Vec<u8> {
        let (_, shards) = self.account(id);
        shards.get(&program.to_string()).and_then(Value::as_array)
            .map(|v| v.iter().map(|b| b.as_u64().unwrap() as u8).collect()).unwrap_or_default()
    }

    fn native_balance(&self, id: &AccountId) -> u128 {
        let d = self.shard(id, &AccountId::new(NATIVE));
        if d.is_empty() { 0 } else { u128::from_le_bytes(d.try_into().unwrap()) }
    }

    fn fund(&self, id: &AccountId, amount: u128) {
        let hex: String = id.value().iter().map(|b| format!("{b:02x}")).collect();
        let ok = Command::new("sh").arg("-c").arg(format!("{} {hex} {amount}", self.fund_cmd))
            .status().expect("the fund command runs").success();
        assert!(ok, "funding {id} failed");
    }

    fn wait<F: Fn() -> bool>(&self, what: &str, cond: F) {
        for _ in 0..60 {
            if cond() { return; }
            sleep(Duration::from_secs(1));
        }
        panic!("not within a minute: {what}");
    }

    /// A transaction to the multisig: `signers` sign (their nonces, in order), the first one
    /// pays. Returns whether the chain included it (the payer's nonce advanced) — included,
    /// not succeeded: a refused call is included too, and pays.
    fn send(&self, signers: &[&PrivateKey], rows: Vec<ProgramShardSelector>, ins: &Instruction) -> bool {
        let ids: Vec<AccountId> = signers.iter().map(|k| AccountId::from(&PublicKey::new_from_private_key(k))).collect();
        let payer = ids[0];
        let nonces: Vec<Nonce> = ids.iter().map(|i| Nonce(self.account(i).0)).collect();
        let before = nonces[0].0;
        let mut data = vec![];
        ins.serialize(&mut data).unwrap();
        let msg = Message::new_preserialized(self.program, rows, nonces, data,
                                             Some(FeeDeclaration::new(payer, GAS, 0, MAX_FEE)));
        let ws = WitnessSet::for_message(&msg, signers);
        let tx = LeeTransaction::Public(PublicTransaction::new(msg, ws));
        let r = self.rpc("sendTransaction", json!([STANDARD.encode(borsh::to_vec(&tx).unwrap())]));
        if r.get("error").is_some() { return false; }
        for _ in 0..45 {
            if self.account(&payer).0 > before { return true; }
            sleep(Duration::from_secs(1));
        }
        false
    }
}

fn key() -> PrivateKey {
    PrivateKey::try_new(rand::random::<[u8; 32]>()).unwrap()
}

fn id(k: &PrivateKey) -> AccountId {
    AccountId::from(&PublicKey::new_from_private_key(k))
}

fn mine(c: &Chain, a: &AccountId) -> ProgramShardSelector {
    ProgramShardSelector { account_id: *a, program_account_id: c.program }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 4, "usage: e2e_v03 <sequencer url> <program account> <fund command>");
    let c = Chain { url: args[1].clone(), program: args[2].parse().expect("a base58 account id"), fund_cmd: args[3].clone() };
    let p = c.program;
    let (ka, kb, kc, kd) = (key(), key(), key(), key());
    let (a, b, cc, d) = (id(&ka), id(&kb), id(&kc), id(&kd));
    let r = id(&key());
    let create_key: [u8; 32] = rand::random();
    let state = state_pda(&p, &create_key);
    let vault = vault_pda(&p, &create_key);
    for who in [&a, &b, &d] { c.fund(who, 1_000_000_000); }
    c.fund(&vault, 1_000);
    c.wait("funding lands", || c.native_balance(&a) > 0 && c.native_balance(&b) > 0
                                && c.native_balance(&d) > 0 && c.native_balance(&vault) == 1_000);

    // 1. create
    assert!(c.send(&[&ka], vec![mine(&c, &state)],
        &Instruction::CreateMultisig { create_key, threshold: 2, members: vec![*a.value(), *b.value(), *cc.value()] }));
    let st: MultisigState = borsh::from_slice(&c.shard(&state, &p)).unwrap();
    assert_eq!((st.threshold, st.member_count), (2, 3));
    println!("1. a 2-of-3 on chain at {state}; its vault {vault} holds 1000 OK");

    // 2. propose a native transfer out of the vault; B approves
    let call = TargetCall {
        program_account_id: NATIVE,
        shard_selectors: vec![(*vault.value(), NATIVE), (*r.value(), NATIVE)],
        instruction_data: borsh::to_vec(&lee_core::native_token::Instruction::Transfer { amount: 100 }).unwrap(),
        pda_seeds: vec![vault_seed(&create_key)],
    };
    let prop = proposal_pda(&p, &create_key, 1);
    assert!(c.send(&[&ka], vec![mine(&c, &state), mine(&c, &prop), mine(&c, &a)],
        &Instruction::Propose { create_key, index: 1, target: call.clone() }));
    let b_before = c.native_balance(&b);
    assert!(c.send(&[&kb], vec![mine(&c, &state), mine(&c, &prop), mine(&c, &b)],
        &Instruction::Approve { create_key, index: 1 }));
    let pr: Proposal = borsh::from_slice(&c.shard(&prop, &p)).unwrap();
    assert_eq!(pr.approved, vec![*a.value(), *b.value()]);
    println!("2. A proposed a transfer of 100 to R; B approved (B paid {} in fees) OK", b_before - c.native_balance(&b));

    // 3. refusals: an outsider votes; a substituted recipient; another multisig names this vault.
    // Each is judged by the state it would have changed.
    let d_before = c.native_balance(&d);
    let included = c.send(&[&kd], vec![mine(&c, &state), mine(&c, &prop), mine(&c, &d)],
        &Instruction::Approve { create_key, index: 1 });
    let pr: Proposal = borsh::from_slice(&c.shard(&prop, &p)).unwrap();
    assert_eq!((pr.approved.len(), pr.rejected.len()), (2, 0), "an outsider's vote must not count");
    println!("3a. an outsider's vote refused (included: {included}; D paid {} in fees; the proposal unchanged) OK",
             d_before - c.native_balance(&d));
    let mut other = call.clone();
    let r2 = id(&key());
    other.shard_selectors[1] = (*r2.value(), NATIVE);
    let rows = |t: &TargetCall| {
        let mut v = vec![mine(&c, &state), mine(&c, &prop)];
        v.extend(t.shard_selectors.iter().map(|(x, y)| ProgramShardSelector { account_id: AccountId::new(*x), program_account_id: AccountId::new(*y) }));
        v
    };
    let included = c.send(&[&ka], rows(&other),
        &Instruction::Execute { create_key, index: 1, approvers: vec![*a.value(), *b.value()], call: other.clone() });
    let pr: Proposal = borsh::from_slice(&c.shard(&prop, &p)).unwrap();
    assert_eq!(pr.status, ProposalStatus::Active, "a substituted recipient must not execute the proposal");
    assert_eq!((c.native_balance(&vault), c.native_balance(&r2)), (1_000, 0), "a substituted recipient must not be paid");
    println!("3b. a substituted recipient refused (included: {included}; nothing moved) OK");
    let ck2: [u8; 32] = rand::random();
    let state2 = state_pda(&p, &ck2);
    assert!(c.send(&[&kd], vec![mine(&c, &state2)],
        &Instruction::CreateMultisig { create_key: ck2, threshold: 1, members: vec![*d.value()] }));
    let st2: MultisigState = borsh::from_slice(&c.shard(&state2, &p)).unwrap();
    assert_eq!((st2.threshold, st2.members.clone()), (1, vec![*d.value()]));
    let prop2 = proposal_pda(&p, &ck2, 1);
    let included = c.send(&[&kd], vec![mine(&c, &state2), mine(&c, &prop2), mine(&c, &d)],
        &Instruction::Propose { create_key: ck2, index: 1, target: call.clone() });
    assert!(c.shard(&prop2, &p).is_empty(), "another multisig naming this vault's seed must not open a proposal");
    let st2: MultisigState = borsh::from_slice(&c.shard(&state2, &p)).unwrap();
    assert_eq!(st2.transaction_index, 0);
    println!("3c. a 1-of-1 of D's naming this vault's seed refused (included: {included}; no proposal opened) OK");
    assert_eq!((c.native_balance(&vault), c.native_balance(&r)), (1_000, 0));

    // 4. execute
    assert!(c.send(&[&ka], rows(&call),
        &Instruction::Execute { create_key, index: 1, approvers: vec![*a.value(), *b.value()], call: call.clone() }));
    assert_eq!((c.native_balance(&vault), c.native_balance(&r)), (900, 100), "Execute moved the vault's 100 to R");
    let pr: Proposal = borsh::from_slice(&c.shard(&prop, &p)).unwrap();
    assert_eq!(pr.status, ProposalStatus::Executed);
    println!("4. executed: R holds 100, the vault 900, the proposal is executed OK");

    // 5. once only
    let included = c.send(&[&ka], rows(&call),
        &Instruction::Execute { create_key, index: 1, approvers: vec![*a.value(), *b.value()], call });
    assert_eq!((c.native_balance(&vault), c.native_balance(&r)), (900, 100), "a second Execute must move nothing");
    println!("5. a second Execute refused (included: {included}; nothing moved) OK");
    println!("e2e_v03: the multisig on a real LEZ v0.3.0 chain — all OK");
}
