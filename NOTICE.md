# NOTICE

ristgo — a pure Go implementation of the RIST protocol (VSF TR-06 family).
Copyright (c) 2026 Thomas Symborski. Licensed under the [MIT License](LICENSE).

This file records attributions for third-party code ported into this
repository.

## github.com/pion/rtp

`internal/rtp` contains code ported (trimmed and adapted) from
[pion/rtp](https://github.com/pion/rtp): the RTP `Header`/`Packet`
marshalling and unmarshalling logic from `packet.go`. Notable modifications
for ristgo: only the classic RFC 3550 header extension is kept (the RFC 8285
one-/two-byte element parsing was dropped; all extension payloads are carried
opaquely), marshalling validates the version and CSRC-count fields instead of
silently truncating them, decode is zero-copy into the input buffer, and
RIST-specific retransmit-SSRC helpers were added.

pion/rtp is licensed under the MIT License, Copyright (c) The Pion community
(<https://github.com/pion/rtp/blob/master/LICENSE>), reproduced here:

> MIT License
>
> Copyright (c) The Pion community <https://pion.ly>
>
> Permission is hereby granted, free of charge, to any person obtaining a
> copy of this software and associated documentation files (the "Software"),
> to deal in the Software without restriction, including without limitation
> the rights to use, copy, modify, merge, publish, distribute, sublicense,
> and/or sell copies of the Software, and to permit persons to whom the
> Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in
> all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
> FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
> DEALINGS IN THE SOFTWARE.

## github.com/pion/rtcp

`internal/rtcp/nack.go` contains code ported (trimmed and adapted) from
[pion/rtcp](https://github.com/pion/rtcp)'s `TransportLayerNack`
(`transport_layer_nack.go`): the Generic NACK FCI packing logic
(`nackPairsFromSequenceNumbers`, after pion's
`NackPairsFromSequenceNumbers`) and the `NackPair` bitmask expansion, used
for the RFC 4585 Generic NACK encoding that carries RIST bitmask NACKs
(RTCP PT=205, FMT=1). Notable modifications for ristgo: the input is the
session's `[]uint32` seq list (low 16 bits used), duplicate sequence
numbers start a fresh pair instead of being shift-dropped, and the encoder
splits output at 16 FCIs per packet per VSF TR-06-1 §5.3.2.3. The ported
sites carry an attribution comment referencing this section.

pion/rtcp is licensed under the MIT License, Copyright (c) The Pion
community <https://pion.ly>
(<https://github.com/pion/rtcp/blob/master/LICENSE>). The license text is
word-for-word identical to the pion/rtp MIT License text reproduced in the
section above, and that reproduction equally covers this port.

## LZ4 (lz4/lz4)

`internal/lpc` is a pure-Go reimplementation of the LZ4 *block* format
compressor and decompressor, ported from the published LZ4 block-format
specification and the algorithm of the reference implementation,
[lz4/lz4](https://github.com/lz4/lz4) (Yann Collet's `lz4.c`/`lz4.h`). It is
used by the RIST Advanced Profile for payload compression (Layer Payload
Compression, LPC=1 = LZ4). libRIST vendors the same reference LZ4 source and
uses the raw block format via `LZ4_compress_default` (send) and
`LZ4_decompress_safe` with an external decompressed bound (receive); this port
mirrors that API shape — `Compress` emits a raw block and `Decompress` decodes
one against a caller-supplied maximum-output bound. Notable points: no C code
is copied (the implementation is idiomatic Go that allocates nothing on the
decode path and never panics on malformed input); the match finder is the
simple LZ4 "fast" single-table variant (match-finding parameters affect only
compression ratio, never decodability); and the decoder is verified against
golden blocks produced by libRIST's own vendored `lz4.c`, while blocks this
package emits are verified to decode under libRIST's `LZ4_decompress_safe`.

lz4 is licensed under the BSD 2-Clause License, Copyright (C) 2011-2023, Yann
Collet (<https://github.com/lz4/lz4/blob/dev/lib/LICENSE>), reproduced here:

> LZ4 - Fast LZ compression algorithm
> Copyright (C) 2011-2023, Yann Collet.
>
> BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)
>
> Redistribution and use in source and binary forms, with or without
> modification, are permitted provided that the following conditions are met:
>
>     * Redistributions of source code must retain the above copyright notice,
>       this list of conditions and the following disclaimer.
>     * Redistributions in binary form must reproduce the above copyright
>       notice, this list of conditions and the following disclaimer in the
>       documentation and/or other materials provided with the distribution.
>
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
> AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
> IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
> ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
> LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
> CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
> SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
> INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
> CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
> ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
> POSSIBILITY OF SUCH DAMAGE.

## Future attributions

Additional ports planned for later phases will be attributed here when the
code arrives.
