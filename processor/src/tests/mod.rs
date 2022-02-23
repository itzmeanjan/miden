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

#[test]
fn sha256_function_cap_sigma_0() {
    let script = compile(
        "
        # SHA256 function; see https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/sha2.hpp#L57-L63 #
        proc.cap_sigma_0
            dup
            u32rotr.2

            swap

            dup
            u32rotr.13

            swap

            u32rotr.22

            u32xor
            u32xor
        end

        begin
            exec.cap_sigma_0
        end",
    );

    let in_words = [1];

    let inputs = ProgramInputs::new(&in_words, &[], vec![]).unwrap();
    let trace = super::execute(&script, &inputs).unwrap();

    let last_state = trace.last_stack_state();

    let out_words = [cap_sigma_0(in_words[0] as u32) as u64];
    let expected_state = convert_to_stack(&out_words);

    assert_eq!(expected_state, last_state);
}

#[test]
fn sha256_function_cap_sigma_1() {
    let script = compile(
        "
        # SHA256 function; see https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/sha2.hpp#L65-L71 #
        proc.cap_sigma_1
            dup
            u32rotr.6

            swap

            dup
            u32rotr.11

            swap

            u32rotr.25

            u32xor
            u32xor
        end

        begin
            exec.cap_sigma_1
        end",
    );

    let in_words = [1];

    let inputs = ProgramInputs::new(&in_words, &[], vec![]).unwrap();
    let trace = super::execute(&script, &inputs).unwrap();

    let last_state = trace.last_stack_state();

    let out_words = [cap_sigma_1(in_words[0] as u32) as u64];
    let expected_state = convert_to_stack(&out_words);

    assert_eq!(expected_state, last_state);
}

#[test]
fn sha256_function_ch() {
    let script = compile(
        "
        # SHA256 function; see https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/sha2.hpp#L37-L45 #
        proc.ch
            swap
            dup.1
            u32and

            swap
            u32not

            movup.2
            u32and

            u32xor
        end

        begin
            exec.ch
        end",
    );

    let in_words = [3, 2, 1];

    let inputs = ProgramInputs::new(&in_words, &[], vec![]).unwrap();
    let trace = super::execute(&script, &inputs).unwrap();

    let last_state = trace.last_stack_state();

    let out_words = [ch(in_words[0] as u32, in_words[1] as u32, in_words[2] as u32) as u64];
    let expected_state = convert_to_stack(&out_words);

    assert_eq!(expected_state, last_state);
}

#[test]
fn sha256_function_maj() {
    let script = compile(
        "
        # SHA256 function; see https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/sha2.hpp#L47-L55 #
        proc.maj
            dup.1
            dup.1
            u32and

            swap
            dup.3
            u32and

            movup.2
            movup.3
            u32and

            u32xor
            u32xor
        end

        begin
            exec.maj
        end",
    );

    let in_words = [3, 2, 1];

    let inputs = ProgramInputs::new(&in_words, &[], vec![]).unwrap();
    let trace = super::execute(&script, &inputs).unwrap();

    let last_state = trace.last_stack_state();

    let out_words = [maj(in_words[0] as u32, in_words[1] as u32, in_words[2] as u32) as u64];
    let expected_state = convert_to_stack(&out_words);

    assert_eq!(expected_state, last_state);
}

#[test]
fn sha256_prepare_message_schedule() {
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

        # SHA256 function; see https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/sha2.hpp#L89-L113 #
        proc.prepare_message_schedule.5
            # compute message schedule msg[16] #
            dup.14
            exec.small_sigma_1

            dup.10
            u32add.unsafe
            drop

            dup.2
            exec.small_sigma_0

            dup.2
            u32add.unsafe
            drop

            u32add.unsafe
            drop

            popw.local.0

            # compute message schedule msg[17] #
            dup.12
            exec.small_sigma_1

            dup.8
            u32add.unsafe
            drop

            pushw.local.0

            dup.3
            exec.small_sigma_0

            dup.3
            u32add.unsafe
            drop

            movup.5
            u32add.unsafe
            drop

            # compute message schedule msg[18] #
            dup.1
            exec.small_sigma_1

            dup.14
            u32add.unsafe
            drop

            dup.6
            exec.small_sigma_0

            dup.6
            u32add.unsafe
            drop

            u32add.unsafe
            drop

            # compute message schedule msg[19] #
            dup.1
            exec.small_sigma_1

            popw.local.0
            dup.12
            pushw.local.0

            movup.4
            u32add.unsafe
            drop

            dup.8
            exec.small_sigma_0

            dup.8
            u32add.unsafe
            drop

            u32add.unsafe
            drop

            # compute message schedule msg[20] #
            dup.1
            movdn.4

            popw.local.0
            exec.small_sigma_1

            dup.14
            u32add.unsafe
            drop

            dup.6
            exec.small_sigma_0

            dup.6
            u32add.unsafe
            drop

            u32add.unsafe
            drop

            pushw.local.0
            movup.4

            # compute message schedule msg[21] #
            dup.1
            exec.small_sigma_1

            movdn.4
            popw.local.0
            movdn.4
            popw.local.1

            dup.12
            u32add.unsafe
            drop
            
            dup.4
            exec.small_sigma_0

            dup.4
            u32add.unsafe
            drop

            u32add.unsafe
            drop

            pushw.local.1
            movup.4

            pushw.local.0
            movup.4

            # compute message schedule msg[22] #
            dup.1
            exec.small_sigma_1

            movdn.4
            popw.local.0
            movdn.4
            popw.local.1

            dup.14
            u32add.unsafe
            drop

            dup.6
            exec.small_sigma_0

            dup.6
            u32add.unsafe
            drop

            u32add.unsafe
            drop

            pushw.local.1
            movup.4

            pushw.local.0
            movup.4

            # compute message schedule msg[23] #
            dup.1
            exec.small_sigma_1

            dup.7
            u32add.unsafe
            drop

            movdn.4
            popw.local.0
            movdn.4
            popw.local.1

            dup.8
            exec.small_sigma_0

            dup.8
            u32add.unsafe
            drop

            u32add.unsafe
            drop

            pushw.local.1
            movup.4

            pushw.local.0
            movup.4

            # compute message schedule msg[24] #
            dup.1
            exec.small_sigma_1

            dup.7
            u32add.unsafe
            drop

            movdn.4
            popw.local.0
            
            dup.14
            exec.small_sigma_0

            dup.14
            u32add.unsafe
            drop

            u32add.unsafe
            drop

            pushw.local.0
            movup.4

            # compute message schedule msg[25] #
            dup.1
            exec.small_sigma_1

            dup.7
            u32add.unsafe
            drop

            movdn.4
            popw.local.0
            movdn.4
            popw.local.1

            dup.12
            exec.small_sigma_0

            dup.12
            u32add.unsafe
            drop
            
            u32add.unsafe
            drop

            pushw.local.1
            movup.4
            pushw.local.0
            movup.4

            # compute message schedule msg[26] #
            dup.1
            exec.small_sigma_1

            dup.7
            u32add.unsafe
            drop

            movdn.4
            popw.local.0
            movdn.4
            popw.local.1

            dup.14
            exec.small_sigma_0

            dup.14
            u32add.unsafe
            drop

            u32add.unsafe
            drop

            pushw.local.1
            movup.4
            pushw.local.0
            movup.4

            # compute message schedule msg[27] #
            dup.1
            exec.small_sigma_1

            movupw.3
            popw.local.0 # holds message schedule msg[0, 1, 2, 3] #
            movupw.3
            popw.local.1 # holds message schedule msg[4, 5, 6, 7] #

            dup.7
            u32add.unsafe
            drop

            movupw.2
            popw.local.2 # holds message schedule msg[19, 18, 17, 16] #

            dup.12
            exec.small_sigma_0

            dup.12
            u32add.unsafe
            drop

            u32add.unsafe
            drop

            # compute message schedule msg[28] #
            dup.1
            exec.small_sigma_1

            dup.7
            u32add.unsafe
            drop

            dup.14
            exec.small_sigma_0

            dup.14
            u32add.unsafe
            drop

            u32add.unsafe
            drop

            # compute message schedule msg[29] #
            movupw.2
            popw.local.3 # holds message schedule msg[20, 8, 9, 10] #

            dup.1
            exec.small_sigma_1

            dup.7
            u32add.unsafe
            drop

            dup.12
            exec.small_sigma_0

            dup.12
            u32add.unsafe
            drop

            u32add.unsafe
            drop

            # compute message schedule msg[30] #
            dup.1
            exec.small_sigma_1

            dup.7
            u32add.unsafe
            drop

            dup.14
            exec.small_sigma_0

            dup.14
            u32add.unsafe
            drop

            u32add.unsafe
            drop

            # compute message schedule msg[31] #
            dup.1
            exec.small_sigma_1

            movupw.2
            popw.local.4 # holds message schedule msg[23, 22, 21, 11] #

            dup.7
            u32add.unsafe
            drop

            dup.11

            pushw.local.2
            dup.3
            exec.small_sigma_0

            movup.5
            u32add.unsafe
            drop

            movup.5
            u32add.unsafe
            drop
        end

        begin
            exec.prepare_message_schedule
        end",
    );

    let in_words = [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];

    let inputs = ProgramInputs::new(&in_words, &[], vec![]).unwrap();
    let trace = super::execute(&script, &inputs).unwrap();

    let last_state = trace.last_stack_state();

    let mut msg_words = in_words;
    msg_words.reverse();

    let mut out_words = [0; STACK_TOP_SIZE << 2];
    prepare_message_schedule(&msg_words, &mut out_words);

    let expected_state = convert_to_stack(&[
        out_words[31],
        out_words[19],
        out_words[18],
        out_words[17],
        out_words[16],
        out_words[30],
        out_words[29],
        out_words[28],
        out_words[27],
        out_words[26],
        out_words[25],
        out_words[24],
        out_words[12],
        out_words[13],
        out_words[14],
        out_words[15],
    ]);

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

/// Taken from https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/sha2.hpp#L57-L63
#[inline]
fn cap_sigma_0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

/// Taken from https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/sha2.hpp#L65-L71
#[inline]
fn cap_sigma_1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

/// Taken from https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/sha2.hpp#L37-L45
#[inline]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

/// Taken from https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/sha2.hpp#L47-L55
#[inline]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// Taken from https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/sha2.hpp#L89-L113
fn prepare_message_schedule(in_words: &[u64], out_words: &mut [u64]) {
    for i in 0..16 {
        out_words[i] = in_words[i];
    }

    for i in 16..64 {
        let t0 = small_sigma_1(out_words[i - 2] as u32).wrapping_add(out_words[i - 7] as u32);
        let t1 = small_sigma_0(out_words[i - 15] as u32).wrapping_add(out_words[i - 16] as u32);

        out_words[i] = t0.wrapping_add(t1) as u64;
    }
}
