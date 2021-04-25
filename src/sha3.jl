function transform!(context::T) where {T<:SHA3_CTX}
    # First, update state with buffer
    pbuf = Ptr{eltype(context.state)}(pointer(context.buffer))
    for idx in 1:div(blocklen(T),8)
        context.state[idx] = context.state[idx] ⊻ unsafe_load(pbuf, idx)
    end
    bc = context.bc
    state = context.state

    # We always assume 24 rounds
    @inbounds for round in 0:23
        # Theta function
        for i in 1:5
            bc[i] = state[i] ⊻ state[i + 5] ⊻ state[i + 10] ⊻ state[i + 15] ⊻ state[i + 20]
        end

        for i in 0:4
            temp = bc[rem(i + 4, 5) + 1] ⊻ L64(1, bc[rem(i + 1, 5) + 1])
            j = 0
            while j <= 20
                state[Int(i + j + 1)] = state[i + j + 1] ⊻ temp
                j += 5
            end
        end

        # Rho Pi
        temp = state[2]
        for i in 1:24
            j = SHA3_PILN[i]
            bc[1] = state[j]
            state[j] = L64(SHA3_ROTC[i], temp)
            temp = bc[1]
        end

        # Chi
        j = 0
        while j <= 20
            for i in 1:5
                bc[i] = state[i + j]
            end
            for i in 0:4
                state[j + i + 1] = state[j + i + 1] ⊻ (~bc[rem(i + 1, 5) + 1] & bc[rem(i + 2, 5) + 1])
            end
            j += 5
        end

        # Iota
        state[1] = state[1] ⊻ SHA3_ROUND_CONSTS[round+1]
    end

    return context.state
end

# Finalize data in the buffer, append total bitlength, and return our precious hash!
function digest!(context::T) where {T<:SHA3_CTX}
    return digest_impl!(context, 0x06)
end

# The original Keccak implementation of SHA3 which is used by Ethereum.
# The only difference is the byte used for padding.
function digest!(context::SHA3_256_KECCAK_CTX)
    return digest_impl!(context, 0x01)
end

function digest_impl!(context::T, padding_byte) where {T<:SHA3_CTX}
    usedspace = context.bytecount % blocklen(T)
    # If we have anything in the buffer still, pad and transform that data
    if usedspace < blocklen(T) - 1
        # Begin padding with the padding byte (0x06 unless Keccak)
        context.buffer[usedspace+1] = padding_byte
        # Fill with zeros up until the last byte
        context.buffer[usedspace+2:end-1] .= 0x00
        # Finish it off with a 0x80
        context.buffer[end] = 0x80
    else
        # Otherwise, we have to add on a whole new buffer just for the zeros and 0x80
        context.buffer[end] = padding_byte
        transform!(context)

        context.buffer[1:end-1] .= 0x0
        context.buffer[end] = 0x80
    end

    # Final transform:
    transform!(context)

    # Return the digest
    return reinterpret(UInt8, context.state)[1:digestlen(T)]
end