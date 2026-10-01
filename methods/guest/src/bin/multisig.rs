//! The LEZ multisig guest on LEZ v0.3.0: one plan or one apply per invocation.
#![no_main]

risc0_zkvm::guest::entry!(main);

fn main() {
    lee_core::program::run_program(multisig_program::plan, multisig_program::apply)
}
