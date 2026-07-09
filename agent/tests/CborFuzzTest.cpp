// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// libFuzzer target for the CBOR decoder (untrusted-parser hardening, D1). The
// decoder must never crash / invoke UB on arbitrary input; it either returns a
// bounded CborValue or a CborError. A returned value must re-encode without
// crashing (exercises the encode path on fuzz-derived structures too).
//
// Built only with -DLIBREDARWIN_BUILD_FUZZERS=ON (AppleClang
// -fsanitize=fuzzer,address). Run: ./CborFuzz -max_total_time=60 corpus/
#include <LibreSCRS/Darwin/backend/wire/Cbor.h>

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    const auto decoded = LibreSCRS::Darwin::wire::decode(std::span<const std::uint8_t>(data, size));
    if (decoded.has_value()) {
        // A successfully decoded (thus canonical) value must re-encode to exactly
        // the input — the decoder's own contract.
        const auto reencoded = decoded->encode();
        if (reencoded.size() != size) {
            __builtin_trap();
        }
    }
    return 0;
}
