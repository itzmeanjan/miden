use super::{execute, Felt, FieldElement, ProgramInputs, Script, STACK_TOP_SIZE};
use crate::Word;
use proptest::prelude::*;

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
fn sha256_function_small_sigma_0() {
    let script = compile(
        "
        # SHA256 function; see https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/sha2.hpp#L73-L79 #
        proc.small_sigma_0
            dup
            u32rotr.7

            swap

            dup
            u32rotr.18

            swap

            u32shr.3

            u32xor
            u32xor
        end

        begin
            exec.small_sigma_0
        end",
    );

    let in_words = [1];

    let inputs = ProgramInputs::new(&in_words, &[], vec![]).unwrap();
    let trace = super::execute(&script, &inputs).unwrap();

    let last_state = trace.last_stack_state();

    let out_words = [small_sigma_0(in_words[0] as u32) as u64];
    let expected_state = convert_to_stack(&out_words);

    assert_eq!(expected_state, last_state);
}

#[test]
fn sha256_function_small_sigma_1() {
    let script = compile(
        "
        # SHA256 function; see https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/sha2.hpp#L81-L87 #
        proc.small_sigma_1
            dup
            u32rotr.17

            swap

            dup
            u32rotr.19

            swap

            u32shr.10

            u32xor
            u32xor
        end

        begin
            exec.small_sigma_1
        end",
    );

    let in_words = [1];

    let inputs = ProgramInputs::new(&in_words, &[], vec![]).unwrap();
    let trace = super::execute(&script, &inputs).unwrap();

    let last_state = trace.last_stack_state();

    let out_words = [small_sigma_1(in_words[0] as u32) as u64];
    let expected_state = convert_to_stack(&out_words);

    assert_eq!(expected_state, last_state);
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

/// Taken from https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/utils.hpp#L4-L14
#[inline]
fn rotr(x: u32, n: usize) -> u32 {
    (x >> n) | (x << (32 - n))
}

/// Taken from https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/sha2.hpp#L73-L79
#[inline]
fn small_sigma_0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

/// Taken from https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/sha2.hpp#L81-L87
#[inline]
fn small_sigma_1(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

/// Taken from https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/sha2.hpp#L89-L113
fn prepare_message_schedule(in_words: &[u64], out_words: &mut [u64]) {
    for i in 0..16 {
        out_words[i] = in_words[i];
    }

    for i in 16..64 {
        let t0: u32 = small_sigma_1(out_words[i - 2] as u32) + out_words[i - 7] as u32;
        let t1: u32 = small_sigma_0(out_words[i - 15] as u32) + out_words[i - 16] as u32;

        out_words[i] = (t0 + t1) as u64;
    }
}
