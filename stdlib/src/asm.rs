//! This module is automatically generated during build time and should not be modified manually.

/// An array of modules defined in Miden standard library.
///
/// Entries in the array are tuples containing module namespace and module source code.
#[rustfmt::skip]
pub const MODULES: [(&str, &str); 4] = [
// ----- std::crypto::hashes::blake3 --------------------------------------------------------------
("std::crypto::hashes::blake3", ""),
// ----- std::crypto::hashes::sha256 --------------------------------------------------------------
("std::crypto::hashes::sha256", "# SHA256 function; see https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/sha2.hpp#L73-L79 #
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

# Computes SHA256 2-to-1 hash function; see https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/sha2_256.hpp#L121-L196 #
export.hash.16
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

    # see https://github.com/itzmeanjan/merklize-sha/blob/8a2c006a2ffe1e6e8e36b375bc5a570385e9f0f2/include/sha2_256.hpp#L89-L99 #
    push.0x200.0x0.0x0.0x0
    push.0x0.0x0.0x0.0x0
    push.0x0.0x0.0x0.0x0
    push.0x0.0x0.0x0.0x80000000

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
"),
// ----- std::math::u256 --------------------------------------------------------------------------
("std::math::u256", "export.add_unsafe
    swapw.3
    movup.3
    movup.7
    u32add.unsafe
    movup.4
    movup.7
    u32addc.unsafe
    movup.4
    movup.6
    u32addc.unsafe
    movup.4
    movup.5
    u32addc.unsafe
    movdn.12
    swapw.2
    movup.12
    movup.4
    movup.8
    u32addc.unsafe
    movup.4
    movup.7
    u32addc.unsafe
    movup.4
    movup.6
    u32addc.unsafe
    movup.4
    movup.5
    u32addc.unsafe
    drop
end

export.sub_unsafe
    swapw.3
    movup.3
    movup.7
    u32sub.unsafe
    movup.7
    u32add.unsafe
    movup.5
    movup.2
    u32sub.unsafe
    movup.2
    add
    movup.6
    u32add.unsafe
    movup.5
    movup.2
    u32sub.unsafe
    movup.2
    add
    movup.5
    u32add.unsafe
    movup.5
    movup.2
    u32sub.unsafe
    movup.2
    add
    movdn.12
    swapw.2
    movup.12
    movup.4
    u32add.unsafe
    movup.8
    movup.2
    u32sub.unsafe
    movup.2
    add
    movup.4
    u32add.unsafe
    movup.7
    movup.2
    u32sub.unsafe
    movup.2
    add
    movup.4
    u32add.unsafe
    movup.6
    movup.2
    u32sub.unsafe
    movup.2
    add
    movup.5
    movup.5
    movup.2
    u32add.unsafe
    drop
    u32sub.unsafe
    drop
end

export.and
    swapw.3
    movup.3
    movup.7
    u32and
    movup.3
    movup.6
    u32and
    movup.3
    movup.5
    u32and
    movup.3
    movup.4
    u32and
    swapw.2
    movup.3
    movup.7
    u32and
    movup.3
    movup.6
    u32and
    movup.3
    movup.5
    u32and
    movup.3
    movup.4
    u32and
end

export.or
    swapw.3
    movup.3
    movup.7
    u32or
    movup.3
    movup.6
    u32or
    movup.3
    movup.5
    u32or
    movup.3
    movup.4
    u32or
    swapw.2
    movup.3
    movup.7
    u32or
    movup.3
    movup.6
    u32or
    movup.3
    movup.5
    u32or
    movup.3
    movup.4
    u32or
end

export.u256xor
    swapw.3
    movup.3
    movup.7
    u32xor
    movup.3
    movup.6
    u32xor
    movup.3
    movup.5
    u32xor
    movup.3
    movup.4
    u32xor
    swapw.2
    movup.3
    movup.7
    u32xor
    movup.3
    movup.6
    u32xor
    movup.3
    movup.5
    u32xor
    movup.3
    movup.4
    u32xor
end

export.iszero_unsafe
    eq.0
    repeat.7
        swap
        eq.0
        and
    end
end

export.eq_unsafe
    swapw.3
    eqw
    movdn.8
    dropw
    dropw
    movdn.8
    eqw
    movdn.8
    dropw
    dropw
    and
end"),
// ----- std::math::u64 ---------------------------------------------------------------------------
("std::math::u64", "export.add_unsafe
    swap
    movup.3
    u32add.unsafe
    movup.3
    movup.3
    u32addc
    drop
end"),
];
