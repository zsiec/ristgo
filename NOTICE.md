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

## Future attributions

Additional ports planned for later phases (for example a pure-Go LZ4
implementation for the Advanced-profile LPC feature, also MIT-licensed) will
be attributed here when the code arrives.
