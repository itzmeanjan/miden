use super::{execute, Felt, FieldElement, ProgramInputs, Script, STACK_TOP_SIZE};
use crate::Word;
use proptest::prelude::*;
use rand::Rng;
use sha2::{Digest, Sha256};

mod aux_table_trace;
mod crypto_ops;
mod field_ops;
mod flow_control;
mod io_ops;
mod u32_ops;

// TESTS
// ================================================================================================

#[test]
fn simple_program() {
    let script = compile("begin push.1 push.2 add end");

    let inputs = ProgramInputs::none();
    let trace = super::execute(&script, &inputs).unwrap();

    let last_state = trace.last_stack_state();
    let expected_state = convert_to_stack(&[3]);
    assert_eq!(expected_state, last_state);
}

#[test]
fn sha256_2_to_1_hash() {
    let script = compile(
        "
        use.std::crypto::hashes::sha256

        begin
            exec.sha256::hash
        end",
    );

    // prepare random input byte array
    let mut rng = rand::thread_rng();
    let mut i_bytes = [0; STACK_TOP_SIZE << 2];

    for i in 0..(STACK_TOP_SIZE << 2) {
        i_bytes[i] = rng.gen::<u8>();
    }

    // allocate space on stack so that bytes can be converted to sha256 words
    let mut i_words = [0u64; STACK_TOP_SIZE];

    // convert each of four consecutive big endian bytes (of input) to blake3 words
    for i in 0..STACK_TOP_SIZE {
        i_words[i] = from_be_bytes_to_words(&i_bytes[i * 4..(i + 1) * 4]) as u64;
    }
    i_words.reverse();

    let mut hasher = Sha256::new();
    hasher.update(&i_bytes);
    let digest = hasher.finalize();

    // prepare digest in desired sha256 word form so that assertion writing becomes easier
    let mut digest_words = [0u64; STACK_TOP_SIZE >> 1];
    // convert each of four consecutive big endian bytes (of digest) to sha256 words
    for i in 0..(STACK_TOP_SIZE >> 1) {
        digest_words[i] = from_be_bytes_to_words(&digest[i * 4..(i + 1) * 4]) as u64;
    }

    // finally execute miden program on VM
    let inputs = ProgramInputs::new(&i_words, &[], Vec::new()).unwrap();
    let trace = super::execute(&script, &inputs).unwrap();
    let last_state = trace.last_stack_state();

    // and assert top 8 elements of stack, because they're holding 32 -bytes wide
    // sha256 digest
    for i in 0..(STACK_TOP_SIZE >> 1) {
        assert_eq!(Felt::new(digest_words[i]), last_state[i]);
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn compile(source: &str) -> Script {
    let assembler = assembly::Assembler::new();
    assembler.compile_script(source).unwrap()
}

fn build_inputs(stack_init: &[u64]) -> ProgramInputs {
    ProgramInputs::new(stack_init, &[], vec![]).unwrap()
}

/// Takes an array of u64 values and builds a stack, perserving their order and converting them to
/// field elements.
fn convert_to_stack(values: &[u64]) -> [Felt; STACK_TOP_SIZE] {
    let mut result = [Felt::ZERO; STACK_TOP_SIZE];
    for (&value, result) in values.iter().zip(result.iter_mut()) {
        *result = Felt::new(value);
    }
    result
}

/// Takes an array of u64 values, converts them to elements, and pushes them onto a stack,
/// reversing their order.
fn push_to_stack(values: &[u64]) -> [Felt; STACK_TOP_SIZE] {
    let mut result = [Felt::ZERO; STACK_TOP_SIZE];
    for (&value, result) in values.iter().rev().zip(result.iter_mut()) {
        *result = Felt::new(value);
    }
    result
}

/// This helper function tests that when the given assembly script is executed on the
/// the provided inputs, it results in the specified final stack state.
/// - `inputs` should be provided in "normal" order. They'll be pushed onto the stack, reversing
/// their order.
/// - `final_stack` should be ordered to match the expected order of the stack after execution,
/// starting from the top.
fn test_script_execution(script: &Script, inputs: &[u64], final_stack: &[u64]) {
    let expected_stack = convert_to_stack(final_stack);
    let last_state = run_test_execution(script, inputs);
    assert_eq!(expected_stack, last_state);
}

/// This helper function tests that when the given assembly instruction is executed on the
/// the provided inputs, it results in the specified final stack state.
/// - `inputs` should be provided in "normal" order. They'll be pushed onto the stack, reversing
/// their order.
/// - `final_stack` should be ordered to match the expected order of the stack after execution,
/// starting from the top.
fn test_op_execution(asm_op: &str, inputs: &[u64], final_stack: &[u64]) {
    let script = compile(format!("begin {} end", asm_op).as_str());
    test_script_execution(&script, inputs, final_stack);
}

/// This helper function is the same as `test_op_execution`, except that when it is used inside a
/// proptest it will return a test failure instead of panicking if the assertion condition fails.
fn test_op_execution_proptest(
    asm_op: &str,
    inputs: &[u64],
    final_stack: &[u64],
) -> Result<(), proptest::test_runner::TestCaseError> {
    let script = compile(format!("begin {} end", asm_op).as_str());
    let expected_stack = convert_to_stack(final_stack);
    let last_state = run_test_execution(&script, inputs);

    prop_assert_eq!(expected_stack, last_state);

    Ok(())
}

/// Executes the given script over the provided inputs and returns the last state of the resulting
/// stack for validation.
fn run_test_execution(script: &Script, inputs: &[u64]) -> [Felt; STACK_TOP_SIZE] {
    let inputs = build_inputs(inputs);
    let trace = execute(script, &inputs).unwrap();

    trace.last_stack_state()
}

/// This helper function tests failures where the execution of a given assembly script with the
/// provided inputs is expected to panic. This function catches the panic and tests it against a
/// provided string to make sure it contains the expected error string.
fn test_script_execution_failure(script: &Script, inputs: &[u64], err_substr: &str) {
    let inputs = build_inputs(inputs);
    assert_eq!(
        std::panic::catch_unwind(|| execute(script, &inputs).unwrap())
            .err()
            .and_then(|a| { a.downcast_ref::<String>().map(|s| s.contains(err_substr)) }),
        Some(true)
    );
}

/// This helper function tests failures where the execution of a given assembly operation with the
/// provided inputs is expected to panic. This function catches the panic and tests it against a
/// provided string to make sure it contains the expected error string.
fn test_execution_failure(asm_op: &str, inputs: &[u64], err_substr: &str) {
    let script = compile(format!("begin {} end", asm_op).as_str());

    test_script_execution_failure(&script, inputs, err_substr);
}

/// This helper function tests failures where the compilation of a given assembly operation is
/// expected to panic. This function catches the panic and tests it against a provided string to
/// make sure it contains the expected error string.
fn test_compilation_failure(asm_op: &str, err_substr: &str) {
    assert_eq!(
        std::panic::catch_unwind(|| compile(format!("begin {} end", asm_op).as_str()))
            .err()
            .and_then(|a| { a.downcast_ref::<String>().map(|s| s.contains(err_substr)) }),
        Some(true)
    );
}

/// This helper function tests a provided assembly operation which takes a single parameter
/// to ensure that it fails when that parameter is over the maximum allowed value (out of bounds).
fn test_param_out_of_bounds(asm_op_base: &str, gt_max_value: u64) {
    let build_asm_op = |param: u64| format!("{}.{}", asm_op_base, param);

    test_compilation_failure(build_asm_op(gt_max_value).as_str(), "parameter");
}

// This is a proptest strategy for generating a random word with 4 values of type T.
fn rand_word<T: proptest::arbitrary::Arbitrary>() -> impl Strategy<Value = Vec<T>> {
    prop::collection::vec(any::<T>(), 4)
}

/// Takes four consecutive big endian bytes and interprets them as a SHA256 word
fn from_be_bytes_to_words(be_bytes: &[u8]) -> u32 {
    ((be_bytes[0] as u32) << 24)
        | ((be_bytes[1] as u32) << 16)
        | ((be_bytes[2] as u32) << 8)
        | ((be_bytes[3] as u32) << 0)
}
