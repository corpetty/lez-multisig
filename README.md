# LEZ Multisig — M-of-N On-Chain Governance

An M-of-N multisig governance program for the [Logos Execution Zone (LEZ)](https://github.com/logos-blockchain/logos-execution-zone). Inspired by [Squads Protocol v4](https://squads.so/): proposals live on-chain as separate PDA accounts, and members approve asynchronously, each in their own transaction.

**This branch targets LEZ v0.3.0**, the line the public testnet runs since 2026-09-30. LEZ v0.3.0 replaced the program ABI: a program is now a pair, `run_program(plan, apply)`. `plan` sees the instruction and each row's account id, authorization and program shard, but no account data, and it emits one effect per shard. `apply` sees one shard's data and checks or changes it. SPEL generates code for the old stateful ABI, so this port is a plain v0.3 program, like LEZ's own token program. The SPEL-based crates (`cli/`, `idl-gen/`, `lez-multisig-ffi/`, `e2e_tests/`) are out of the workspace until SPEL supports v0.3.

The v0.2.4 program (SPEL v0.7.0) is on `main`, at ImageID `2ced3d30…d4c7` on the v0.2.4 testnet.

## How it works

```
CreateMultisig → Propose → Approve (×M) → Execute { approvers, call } → the call, chained
```

1. **Create** a multisig: N members, threshold M, and a unique `create_key`. The creator's own transaction pays its fee. Members need no setup, and any funded account can be one.
2. **Propose** a call or a config change, as the next proposal index. The proposal commits to one `Commitment`. A call commits to the target program's account id, every row it touches as an (account, program shard) pair, its instruction bytes, and its PDA seeds. The proposer's vote counts.
3. **Approve** or **Reject**: each member votes in their own transaction, and pays for it.
4. **Execute** names the approvers it counts and carries the call. The proposal's `apply` refuses unless the call hashes to its commitment and every named approver approved it. The state's `apply` refuses unless they are distinct **current** members, at least M of them. The call then runs, chained from `plan`, and the proposal is Executed. **ExecuteConfig** does the same for a config change (add or remove a member, change the threshold).

Because the rows are committed, a recipient cannot be substituted at Execute. The PDA seeds a call carries can only be this multisig's own vault seed. The vault holds native LEZ in its native shard, and anyone funds it by an ordinary transfer to its id.

**On v0.3 a refused transaction is still included.** It reverts, keeps its fee, and burns its signers' nonces. The sequencer's RPC reports no outcome, so a client judges each step by the state it reads back, never by inclusion. A refusal is billed its whole gas limit: on a local zone, a refused vote cost 16,003,672 base units, and an accepted approval 456,112.

## Accounts

| account | seed | shard | holds |
|---|---|---|---|
| state | `create_key` | the program's | `MultisigState { create_key, threshold, member_count, members, transaction_index }` |
| proposal #i | SHA-256(`"multisig_prop___"` ‖ create_key ‖ i LE) | the program's | `Proposal { index, proposer, create_key, commitment, approved, rejected, status }` |
| vault | SHA-256(`"multisig_vault__"` ‖ create_key) | the native token's | native LEZ |

Every PDA is `AccountId::for_public_pda(P, seed)`: SHA-256(`"/LEE/v0.2/AccountId/PDA/"` padded ‖ P ‖ seed). Here `P` is the program's account id, which is its deployment header account on v0.3. Strings in seeds are zero-padded to 32 bytes, and several seeds are combined by SHA-256, as SPEL did.

Rows, in order:
- **CreateMultisig:** the state.
- **Propose, ProposeConfig, Approve and Reject:** the state, the proposal, then the signing member.
- **Execute:** the state, the proposal, then the call's own rows in order. A chained call can select only rows its transaction carries.
- **ExecuteConfig:** the state and the proposal.

## Project structure

```
multisig_core/      — the types: state, proposal, commitment, instructions, effects, PDAs
multisig_program/   — plan + apply, and in-process tests of every rule (src/tests.rs)
methods/            — the risc0 guest: run_program(plan, apply)
e2e_v03/            — the end-to-end test against a running v0.3 sequencer, and the client vectors (src/bin/vectors.rs)
```

## Build, test, deploy

Needs Rust 1.98.1 (`rust-toolchain.toml`, as LEZ v0.3.0) and risc0's guest toolchain (`rzup install rust 1.91.1`). The host side links RocksDB and risc0's circuit kernels, so it also needs a C++ compiler and `libclang`.

```bash
# every plan/apply rule, in process (no zkVM)
RISC0_SKIP_BUILD=1 cargo test -p multisig_program

# the guest: target/riscv-guest/multisig-methods/multisig-guest/riscv32im-risc0-zkvm-elf/release/multisig.bin
cargo build --release -p multisig-methods

# deploy through program_loader with LEZ's wallet CLI: the user ELF in 96 KiB segments,
# one fresh account each, then a header account naming them; the header's id is the
# program's account id
wallet program-loader deploy --elf multisig.bin --header Public/<header> --segments Public/<s1> … --payer Public/<funded>

# end to end on a running sequencer: <fund command> is run as `<cmd> <account hex> <amount>`
cargo run --release -p e2e_v03 -- http://127.0.0.1:3040 <program account> "<fund command>"
```

The e2e creates a 2-of-3, funds its vault, proposes a native transfer out of it, and approves it. It checks four refusals, each with state unchanged: an outsider's vote, a substituted recipient, another multisig naming this vault's seed, and a second Execute. It also executes the transfer. Every step is judged by the state read back.

`cargo run --release -p e2e_v03 --bin vectors` prints, from `multisig_core` itself, the borsh bytes of a state, a call proposal, a config proposal and every instruction, plus the PDAs, for clients to be held to.

## References

- [LEZ (logos-execution-zone)](https://github.com/logos-blockchain/logos-execution-zone), v0.3.0: `lee/state_machine/core/src/program/` (the plan/apply ABI), `native_token.rs` (a v0.3 program of the same shape)
- [SPEC.md](SPEC.md), [FURPS.md](FURPS.md), [ADR.md](ADR.md): the v0.2.x design this port carries over
- [Squads Protocol v4](https://squads.so/): design inspiration

## Disclaimer

This repository contains a POC implementation forming part of an experimental development environment and is not intended for production use.

See the [Logos Core repository](https://github.com/logos-co/logos-liblogos) for additional information about the experimental development environment.
