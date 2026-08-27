use crate::{
    guest_programs::{GenericGuestFixture, GuestFixture},
    stateless_validator::{eest::EestStatelessFixture, ExecutionClient},
};
use anyhow::{Context, Result};
use ere_dockerized::Input;
use serde::Serialize;
use std::collections::BTreeMap;
use stateless_validator_zilkworm::StatelessValidatorZilkwormInput;

#[derive(Debug, Clone, Serialize)]
struct EestBlockMetadata {
    fixture_format: &'static str,
    original_test_name: String,
    source_path: String,
    block_index: usize,
    network: String,
    chain_id: u64,
    block_number: Option<u64>,
    block_used_gas: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    opcode_count: Option<BTreeMap<String, u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_opcode: Option<String>,
}

fn eest_metadata(f: &EestStatelessFixture) -> EestBlockMetadata {
    EestBlockMetadata {
        fixture_format: "eest",
        original_test_name: f.original_test_name.clone(),
        source_path: f.source_path.clone(),
        block_index: f.block_index,
        network: f.network.clone(),
        chain_id: f.chain_id,
        block_number: f.block_number,
        block_used_gas: f.block_used_gas,
        opcode_count: f.opcode_count.clone(),
        target_opcode: f.target_opcode.clone(),
    }
}

pub(crate) fn stateless_validator_input_from_fixture(
    fixture: EestStatelessFixture,
    el: ExecutionClient,
) -> Result<Box<dyn GuestFixture>> {
    match el {
        ExecutionClient::Reth | ExecutionClient::Ethrex | ExecutionClient::Zesu => {
            raw_eest_input_from_fixture(fixture)
        }
        ExecutionClient::Zilkworm => zilkworm_input_from_fixture(fixture),
    }
}

/// Reth/Ethrex/Zesu consume the canonical `statelessInputBytes` unchanged on
/// stdin and expect the raw `statelessOutputBytes` as public values.
fn raw_eest_input_from_fixture(fixture: EestStatelessFixture) -> Result<Box<dyn GuestFixture>> {
    let metadata = eest_metadata(&fixture);
    let fixture = GenericGuestFixture::<EestBlockMetadata> {
        name: fixture.name,
        input: Input::new().with_stdin(fixture.stateless_input_bytes),
        expected_public_values: fixture.stateless_output_bytes,
        metadata,
    };

    Ok(fixture.into_boxed())
}

/// Zilkworm consumes an MFBD flat bundle, not raw `statelessInputBytes`. The
/// host decodes the canonical SIOB (BAL-derived preimage keys) into the MFBD
/// envelope and derives the guest's expected public values (#133 layout).
fn zilkworm_input_from_fixture(fixture: EestStatelessFixture) -> Result<Box<dyn GuestFixture>> {
    // `successful_validation` sits at byte 32 of the SSZ `StatelessValidationResult`
    // (after the fixed 32-byte new_payload_request_root; no schema prefix).
    let valid_block = fixture.stateless_output_bytes.get(32) == Some(&1);
    let prepared =
        StatelessValidatorZilkwormInput::from_ere_eest(&fixture.stateless_input_bytes, valid_block)
            .with_context(|| format!("building Zilkworm MFBD input for {}", fixture.name))?;
    let metadata = eest_metadata(&fixture);
    let fixture = GenericGuestFixture::<EestBlockMetadata> {
        name: fixture.name,
        input: Input::new().with_stdin(prepared.flat_bundle),
        expected_public_values: prepared.public_values,
        metadata,
    };

    Ok(fixture.into_boxed())
}
