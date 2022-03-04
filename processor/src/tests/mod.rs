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
        
        # assume top 4 elements of stack are [3, 2, 1, 0, ...], then after execution of this function, stack should look like [0, 1, 2, 3, ...] #
        proc.rev_element_order
            swap
            movup.2
            movup.3
        end

        proc.gen_four_message_words.1
            # compute message schedule msg[a + 0] | a % 4 == 0 #
            dup.6
            exec.small_sigma_1

            dup.2
            u32add.unsafe
            drop

            dup.10
            exec.small_sigma_0

            u32add.unsafe
            drop

            dup.9
            u32add.unsafe
            drop

            # compute message schedule msg[a + 1] #
            dup.8
            exec.small_sigma_1

            dup.4
            u32add.unsafe
            drop

            dup.12
            exec.small_sigma_0

            u32add.unsafe
            drop

            dup.11
            u32add.unsafe
            drop

            # compute message schedule msg[a + 2] #
            dup.1
            exec.small_sigma_1

            dup.6
            u32add.unsafe
            drop

            dup.14
            exec.small_sigma_0

            u32add.unsafe
            drop

            dup.13
            u32add.unsafe
            drop
            
            # compute message schedule msg[a + 3] #
            dup.1
            exec.small_sigma_1

            dup.8
            u32add.unsafe
            drop

            popw.local.0

            dup.12
            exec.small_sigma_0

            dup.12
            u32add.unsafe
            drop

            pushw.local.0
            movup.4

            u32add.unsafe
            drop

            # stack = [a + 3, a + 2, a + 1, a + 0, ...] #
            exec.rev_element_order
            # stack = [a + 0, a + 1, a + 2, a + 3, ...] #
        end

        proc.reorder_stack_words
            swapw
            movupw.3
            movupw.2
            movupw.3
        end

        # SHA256 function; see https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/sha2.hpp#L89-L113 #
        proc.prepare_message_schedule.5
            popw.local.0
            popw.local.1
            popw.local.2
            popw.local.3

            movupw.3
            movupw.3

            # --- #

            exec.gen_four_message_words

            popw.local.4
            movupw.2

            pushw.local.0
            repeat.3
                swap
                drop
            end

            popw.mem # write to mem msg[0, 1, 2, 3] #
            pushw.local.4

            exec.reorder_stack_words
            
            # --- #

            exec.gen_four_message_words

            popw.local.4
            movupw.2

            pushw.local.0
            drop
            repeat.2
                swap
                drop
            end

            popw.mem # write to mem msg[4, 5, 6, 7] #
            pushw.local.4

            exec.reorder_stack_words

            # --- #

            exec.gen_four_message_words

            popw.local.4
            movupw.2

            pushw.local.0
            drop
            drop
            swap
            drop

            popw.mem # write to mem msg[8, 9, 10, 11] #
            pushw.local.4

            exec.reorder_stack_words

            # --- #

            exec.gen_four_message_words

            popw.local.4
            movupw.2

            pushw.local.0
            drop
            drop
            drop

            popw.mem # write to mem msg[12, 13, 14, 15] #
            pushw.local.4

            exec.reorder_stack_words

            # --- #
            # --- #

            exec.gen_four_message_words

            popw.local.4
            movupw.2

            pushw.local.1
            repeat.3
                swap
                drop
            end

            popw.mem # write to mem msg[16, 17, 18, 19] #
            pushw.local.4

            exec.reorder_stack_words

            # --- #

            exec.gen_four_message_words

            popw.local.4
            movupw.2

            pushw.local.1
            drop
            repeat.2
                swap
                drop
            end

            popw.mem # write to mem msg[20, 21, 22, 23] #
            pushw.local.4

            exec.reorder_stack_words

            # --- #

            exec.gen_four_message_words

            popw.local.4
            movupw.2

            pushw.local.1
            drop
            drop
            swap
            drop

            popw.mem # write to mem msg[24, 25, 26, 27] #
            pushw.local.4

            exec.reorder_stack_words

            # --- #

            exec.gen_four_message_words

            popw.local.4
            movupw.2

            pushw.local.1
            drop
            drop
            drop

            popw.mem # write to mem msg[28, 29, 30, 31] #
            pushw.local.4

            exec.reorder_stack_words

            # --- #
            # --- #

            exec.gen_four_message_words

            popw.local.4
            movupw.2

            pushw.local.2
            repeat.3
                swap
                drop
            end

            popw.mem # write to mem msg[32, 33, 34, 35] #
            pushw.local.4

            exec.reorder_stack_words

            # --- #

            exec.gen_four_message_words

            popw.local.4
            movupw.2

            pushw.local.2
            drop
            repeat.2
                swap
                drop
            end

            popw.mem # write to mem msg[36, 37, 38, 39] #
            pushw.local.4

            exec.reorder_stack_words

            # --- #

            exec.gen_four_message_words

            popw.local.4
            movupw.2

            pushw.local.2
            drop
            drop
            swap
            drop

            popw.mem # write to mem msg[40, 41, 42, 43] #
            pushw.local.4

            exec.reorder_stack_words

            # --- #

            exec.gen_four_message_words

            popw.local.4
            movupw.2

            pushw.local.2
            drop
            drop
            drop

            popw.mem # write to mem msg[44, 45, 46, 47] #
            pushw.local.4

            movupw.3
            pushw.local.3
            repeat.3
                swap
                drop
            end
            popw.mem # write to mem msg[48, 49, 50, 51] #

            swapw
            pushw.local.3
            drop
            repeat.2
                swap
                drop
            end
            popw.mem # write to mem msg[52, 53, 54, 55] #

            swapw
            pushw.local.3
            drop
            drop
            swap
            drop
            popw.mem # write to mem msg[56, 57, 58, 59] #

            pushw.local.3
            drop
            drop
            drop
            popw.mem # write to mem msg[60, 61, 62, 63] #

            # --- #
        end

        proc.update_hash_state
            # stack = [a, b, c, d, e, f, g, h,  a, b, c, d, e, f, g, h] #

            movup.15
            movup.8
            u32add.unsafe
            drop # = h #

            movup.14
            movup.8
            u32add.unsafe
            drop # = g #

            movup.13
            movup.8
            u32add.unsafe
            drop # = f #

            movup.12
            movup.8
            u32add.unsafe
            drop # = e #

            movup.11
            movup.8
            u32add.unsafe
            drop # = d #

            movup.10
            movup.8
            u32add.unsafe
            drop # = c #

            movup.9
            movup.8
            u32add.unsafe
            drop # = b #

            movup.8
            movup.8
            u32add.unsafe
            drop # = a #

            # stack = [a, b, c, d, e, f, g, h] #
        end

        # can be treated same as https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/sha2_256.hpp#L168-L175 #
        proc.compute_next_working_variables
            # stack = [tmp1, tmp0, a, b, c, d, e, f, g, h] #

            movup.8 # = h #
            movup.8 # = g #
            movup.8 # = f #
            dup.4
            movup.9
            u32add.unsafe
            drop # = e #
            movup.8 # = d #
            movup.8 # = c #
            movup.8 # = b #
            movup.8
            movup.8
            u32add.unsafe
            drop # = a #
            movup.8
            drop

            # stack = [a', b', c', d', e', f', g', h'] #
        end

        # can be translated to https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/sha2_256.hpp#L144-L187, where single round of SHA256 mixing is performed #
        proc.mix.4
            popw.local.0
            popw.local.1
            popw.local.2
            popw.local.3
            
            # --- begin iteration t = 0 --- #

            dupw.1
            dupw.1

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x428a2f98
            u32add.unsafe
            drop

            pushw.local.0
            repeat.3
                swap
                drop
            end
            pushw.mem
            repeat.3
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 1 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x71374491
            u32add.unsafe
            drop

            pushw.local.0
            repeat.3
                swap
                drop
            end
            pushw.mem
            drop
            repeat.2
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 2 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0xb5c0fbcf
            u32add.unsafe
            drop

            pushw.local.0
            repeat.3
                swap
                drop
            end
            pushw.mem
            drop
            drop
            swap
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 3 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0xe9b5dba5
            u32add.unsafe
            drop

            pushw.local.0
            repeat.3
                swap
                drop
            end
            pushw.mem
            drop
            drop
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 4 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x3956c25b
            u32add.unsafe
            drop

            pushw.local.0
            drop
            repeat.2
                swap
                drop
            end
            pushw.mem
            repeat.3
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 5 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x59f111f1
            u32add.unsafe
            drop

            pushw.local.0
            drop
            repeat.2
                swap
                drop
            end
            pushw.mem
            drop
            repeat.2
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 6 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x923f82a4
            u32add.unsafe
            drop

            pushw.local.0
            drop
            repeat.2
                swap
                drop
            end
            pushw.mem
            drop
            drop
            swap
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 7 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0xab1c5ed5
            u32add.unsafe
            drop

            pushw.local.0
            drop
            repeat.2
                swap
                drop
            end
            pushw.mem
            drop
            drop
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 8 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0xd807aa98
            u32add.unsafe
            drop

            pushw.local.0
            drop
            drop
            swap
            drop
            pushw.mem
            repeat.3
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 9 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x12835b01
            u32add.unsafe
            drop

            pushw.local.0
            drop
            drop
            swap
            drop
            pushw.mem
            drop
            repeat.2
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 10 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x243185be
            u32add.unsafe
            drop

            pushw.local.0
            drop
            drop
            swap
            drop
            pushw.mem
            drop
            drop
            swap
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 11 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x550c7dc3
            u32add.unsafe
            drop

            pushw.local.0
            drop
            drop
            swap
            drop
            pushw.mem
            drop
            drop
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 12 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x72be5d74
            u32add.unsafe
            drop

            pushw.local.0
            drop
            drop
            drop
            pushw.mem
            repeat.3
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 13 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x80deb1fe
            u32add.unsafe
            drop

            pushw.local.0
            drop
            drop
            drop
            pushw.mem
            drop
            repeat.2
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 14 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x9bdc06a7
            u32add.unsafe
            drop

            pushw.local.0
            drop
            drop
            drop
            pushw.mem
            drop
            drop
            swap
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 15 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0xc19bf174
            u32add.unsafe
            drop

            pushw.local.0
            drop
            drop
            drop
            pushw.mem
            drop
            drop
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 16 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0xe49b69c1
            u32add.unsafe
            drop

            pushw.local.1
            repeat.3
                swap
                drop
            end
            pushw.mem
            repeat.3
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 17 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0xefbe4786
            u32add.unsafe
            drop

            pushw.local.1
            repeat.3
                swap
                drop
            end
            pushw.mem
            drop
            repeat.2
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 18 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x0fc19dc6
            u32add.unsafe
            drop

            pushw.local.1
            repeat.3
                swap
                drop
            end
            pushw.mem
            drop
            drop
            swap
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 19 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x240ca1cc
            u32add.unsafe
            drop

            pushw.local.1
            repeat.3
                swap
                drop
            end
            pushw.mem
            drop
            drop
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 20 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x2de92c6f
            u32add.unsafe
            drop

            pushw.local.1
            drop
            repeat.2
                swap
                drop
            end
            pushw.mem
            repeat.3
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 21 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x4a7484aa
            u32add.unsafe
            drop

            pushw.local.1
            drop
            repeat.2
                swap
                drop
            end
            pushw.mem
            drop
            repeat.2
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 22 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x5cb0a9dc
            u32add.unsafe
            drop

            pushw.local.1
            drop
            repeat.2
                swap
                drop
            end
            pushw.mem
            drop
            drop
            swap
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 23 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x76f988da
            u32add.unsafe
            drop

            pushw.local.1
            drop
            repeat.2
                swap
                drop
            end
            pushw.mem
            drop
            drop
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 24 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x983e5152
            u32add.unsafe
            drop

            pushw.local.1
            drop
            drop
            swap
            drop
            pushw.mem
            repeat.3
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 25 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0xa831c66d
            u32add.unsafe
            drop

            pushw.local.1
            drop
            drop
            swap
            drop
            pushw.mem
            drop
            repeat.2
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 26 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0xb00327c8
            u32add.unsafe
            drop

            pushw.local.1
            drop
            drop
            swap
            drop
            pushw.mem
            drop
            drop
            swap
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 27 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0xbf597fc7
            u32add.unsafe
            drop

            pushw.local.1
            drop
            drop
            swap
            drop
            pushw.mem
            drop
            drop
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 28 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0xc6e00bf3
            u32add.unsafe
            drop

            pushw.local.1
            drop
            drop
            drop
            pushw.mem
            repeat.3
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 29 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0xd5a79147
            u32add.unsafe
            drop

            pushw.local.1
            drop
            drop
            drop
            pushw.mem
            drop
            repeat.2
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 30 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x06ca6351
            u32add.unsafe
            drop

            pushw.local.1
            drop
            drop
            drop
            pushw.mem
            drop
            drop
            swap
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 31 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x14292967
            u32add.unsafe
            drop

            pushw.local.1
            drop
            drop
            drop
            pushw.mem
            drop
            drop
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 32 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x27b70a85
            u32add.unsafe
            drop

            pushw.local.2
            repeat.3
                swap
                drop
            end
            pushw.mem
            repeat.3
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 33 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x2e1b2138
            u32add.unsafe
            drop

            pushw.local.2
            repeat.3
                swap
                drop
            end
            pushw.mem
            drop
            repeat.2
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 34 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x4d2c6dfc
            u32add.unsafe
            drop

            pushw.local.2
            repeat.3
                swap
                drop
            end
            pushw.mem
            drop
            drop
            swap
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 35 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x53380d13
            u32add.unsafe
            drop

            pushw.local.2
            repeat.3
                swap
                drop
            end
            pushw.mem
            drop
            drop
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 36 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x650a7354
            u32add.unsafe
            drop

            pushw.local.2
            drop
            repeat.2
                swap
                drop
            end
            pushw.mem
            repeat.3
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 37 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x766a0abb
            u32add.unsafe
            drop

            pushw.local.2
            drop
            repeat.2
                swap
                drop
            end
            pushw.mem
            drop
            repeat.2
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 38 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x81c2c92e
            u32add.unsafe
            drop

            pushw.local.2
            drop
            repeat.2
                swap
                drop
            end
            pushw.mem
            drop
            drop
            swap
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 39 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x92722c85
            u32add.unsafe
            drop

            pushw.local.2
            drop
            repeat.2
                swap
                drop
            end
            pushw.mem
            drop
            drop
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 40 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0xa2bfe8a1
            u32add.unsafe
            drop

            pushw.local.2
            drop
            drop
            swap
            drop
            pushw.mem
            repeat.3
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 41 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0xa81a664b
            u32add.unsafe
            drop

            pushw.local.2
            drop
            drop
            swap
            drop
            pushw.mem
            drop
            repeat.2
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 42 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0xc24b8b70
            u32add.unsafe
            drop

            pushw.local.2
            drop
            drop
            swap
            drop
            pushw.mem
            drop
            drop
            swap
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 43 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0xc76c51a3
            u32add.unsafe
            drop

            pushw.local.2
            drop
            drop
            swap
            drop
            pushw.mem
            drop
            drop
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 44 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0xd192e819
            u32add.unsafe
            drop

            pushw.local.2
            drop
            drop
            drop
            pushw.mem
            repeat.3
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 45 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0xd6990624
            u32add.unsafe
            drop

            pushw.local.2
            drop
            drop
            drop
            pushw.mem
            drop
            repeat.2
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 46 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0xf40e3585
            u32add.unsafe
            drop

            pushw.local.2
            drop
            drop
            drop
            pushw.mem
            drop
            drop
            swap
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 47 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x106aa070
            u32add.unsafe
            drop

            pushw.local.2
            drop
            drop
            drop
            pushw.mem
            drop
            drop
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 48 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x19a4c116
            u32add.unsafe
            drop

            pushw.local.3
            repeat.3
                swap
                drop
            end
            pushw.mem
            repeat.3
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 49 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x1e376c08
            u32add.unsafe
            drop

            pushw.local.3
            repeat.3
                swap
                drop
            end
            pushw.mem
            drop
            repeat.2
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 50 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x2748774c
            u32add.unsafe
            drop

            pushw.local.3
            repeat.3
                swap
                drop
            end
            pushw.mem
            drop
            drop
            swap
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 51 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x34b0bcb5
            u32add.unsafe
            drop

            pushw.local.3
            repeat.3
                swap
                drop
            end
            pushw.mem
            drop
            drop
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 52 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x391c0cb3
            u32add.unsafe
            drop

            pushw.local.3
            drop
            repeat.2
                swap
                drop
            end
            pushw.mem
            repeat.3
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 53 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x4ed8aa4a
            u32add.unsafe
            drop

            pushw.local.3
            drop
            repeat.2
                swap
                drop
            end
            pushw.mem
            drop
            repeat.2
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 54 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x5b9cca4f
            u32add.unsafe
            drop

            pushw.local.3
            drop
            repeat.2
                swap
                drop
            end
            pushw.mem
            drop
            drop
            swap
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 55 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x682e6ff3
            u32add.unsafe
            drop

            pushw.local.3
            drop
            repeat.2
                swap
                drop
            end
            pushw.mem
            drop
            drop
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 56 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x748f82ee
            u32add.unsafe
            drop

            pushw.local.3
            drop
            drop
            swap
            drop
            pushw.mem
            repeat.3
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 57 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x78a5636f
            u32add.unsafe
            drop

            pushw.local.3
            drop
            drop
            swap
            drop
            pushw.mem
            drop
            repeat.2
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 58 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x84c87814
            u32add.unsafe
            drop

            pushw.local.3
            drop
            drop
            swap
            drop
            pushw.mem
            drop
            drop
            swap
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 59 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x8cc70208
            u32add.unsafe
            drop

            pushw.local.3
            drop
            drop
            swap
            drop
            pushw.mem
            drop
            drop
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 60 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0x90befffa
            u32add.unsafe
            drop

            pushw.local.3
            drop
            drop
            drop
            pushw.mem
            repeat.3
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 61 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0xa4506ceb
            u32add.unsafe
            drop

            pushw.local.3
            drop
            drop
            drop
            pushw.mem
            drop
            repeat.2
                swap
                drop
            end

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 62 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0xbef9a3f7
            u32add.unsafe
            drop

            pushw.local.3
            drop
            drop
            drop
            pushw.mem
            drop
            drop
            swap
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            # --- begin iteration t = 63 --- #

            dupw.1
            exec.ch
            u32add.unsafe
            drop
            dup.5
            exec.cap_sigma_1
            u32add.unsafe
            drop
            push.0xc67178f2
            u32add.unsafe
            drop

            pushw.local.3
            drop
            drop
            drop
            pushw.mem
            drop
            drop
            drop

            u32add.unsafe
            drop

            dupw
            drop
            exec.maj
            dup.2
            exec.cap_sigma_0
            u32add.unsafe
            drop

            exec.compute_next_working_variables

            exec.update_hash_state
        end

        proc.wrapper.16
            push.env.locaddr.15
            push.env.locaddr.14
            push.env.locaddr.13
            push.env.locaddr.12

            push.env.locaddr.11
            push.env.locaddr.10
            push.env.locaddr.9
            push.env.locaddr.8

            push.env.locaddr.7
            push.env.locaddr.6
            push.env.locaddr.5
            push.env.locaddr.4

            push.env.locaddr.3
            push.env.locaddr.2
            push.env.locaddr.1
            push.env.locaddr.0

            exec.prepare_message_schedule

            # SHA256 initial hash values https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/sha2_256.hpp#L15-L20 #
            push.0x5be0cd19.0x1f83d9ab.0x9b05688c.0x510e527f
            push.0xa54ff53a.0x3c6ef372.0xbb67ae85.0x6a09e667

            push.env.locaddr.15
            push.env.locaddr.14
            push.env.locaddr.13
            push.env.locaddr.12

            push.env.locaddr.11
            push.env.locaddr.10
            push.env.locaddr.9
            push.env.locaddr.8

            push.env.locaddr.7
            push.env.locaddr.6
            push.env.locaddr.5
            push.env.locaddr.4

            push.env.locaddr.3
            push.env.locaddr.2
            push.env.locaddr.1
            push.env.locaddr.0

            exec.mix
        end

        begin
            exec.wrapper
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
    let mut hash_state = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    mix(&mut hash_state, &out_words, 64);

    // check only top 8 elements of stack
    for i in 0..8 {
        assert_eq!(Felt::new(hash_state[i]), last_state[i]);
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

/// Taken from https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/sha2.hpp#L20-L35
const K: [u64; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Taken from https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/sha2_256.hpp#L148-L187
fn mix(hash_state: &mut [u64], msg_schld: &[u64], rounds: usize) {
    assert_eq!(rounds >= 1 && rounds <= 64, true);

    let mut a = hash_state[0];
    let mut b = hash_state[1];
    let mut c = hash_state[2];
    let mut d = hash_state[3];
    let mut e = hash_state[4];
    let mut f = hash_state[5];
    let mut g = hash_state[6];
    let mut h = hash_state[7];

    for t in 0..rounds {
        let tmp0 = (h as u32)
            .wrapping_add(cap_sigma_1(e as u32))
            .wrapping_add(ch(e as u32, f as u32, g as u32))
            .wrapping_add(K[t] as u32)
            .wrapping_add(msg_schld[t] as u32);
        let tmp1 = cap_sigma_0(a as u32).wrapping_add(maj(a as u32, b as u32, c as u32));
        h = g;
        g = f;
        f = e;
        e = (d as u32).wrapping_add(tmp0) as u64;
        d = c;
        c = b;
        b = a;
        a = tmp0.wrapping_add(tmp1) as u64;
    }

    hash_state[0] = (hash_state[0] as u32).wrapping_add(a as u32) as u64;
    hash_state[1] = (hash_state[1] as u32).wrapping_add(b as u32) as u64;
    hash_state[2] = (hash_state[2] as u32).wrapping_add(c as u32) as u64;
    hash_state[3] = (hash_state[3] as u32).wrapping_add(d as u32) as u64;
    hash_state[4] = (hash_state[4] as u32).wrapping_add(e as u32) as u64;
    hash_state[5] = (hash_state[5] as u32).wrapping_add(f as u32) as u64;
    hash_state[6] = (hash_state[6] as u32).wrapping_add(g as u32) as u64;
    hash_state[7] = (hash_state[7] as u32).wrapping_add(h as u32) as u64;
}
