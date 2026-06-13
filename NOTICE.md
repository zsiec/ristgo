# NOTICE

ristgo — a pure Go implementation of the RIST protocol (VSF TR-06 family).
Copyright (c) 2026 Thomas Symborski. Licensed under the [MIT License](LICENSE).

This file records attributions for third-party code ported into this
repository. The sections below are declared ahead of the code itself: the
ports land in a later workpackage, but the attribution obligations are
recorded now so they are never forgotten.

## github.com/pion/rtp

`internal/rtp` will contain code ported (trimmed and adapted) from
[pion/rtp](https://github.com/pion/rtp): RTP header and header-extension
marshalling/unmarshalling.

pion/rtp is licensed under the MIT License, Copyright (c) Pion contributors
(<https://github.com/pion/rtp/blob/master/LICENSE>). The license text will be
reproduced alongside the ported sources when they arrive.

## github.com/pion/rtcp

`internal/rtcp` will contain code ported (trimmed and adapted) from
[pion/rtcp](https://github.com/pion/rtcp): in particular `TransportLayerNack`
(the RFC 4585 Generic NACK encoding used for RIST bitmask NACKs, RTCP PT=205
FMT=1).

pion/rtcp is licensed under the MIT License, Copyright (c) Pion contributors
(<https://github.com/pion/rtcp/blob/master/LICENSE>). The license text will be
reproduced alongside the ported sources when they arrive.

## Future attributions

Additional ports planned for later phases (for example a pure-Go LZ4
implementation for the Advanced-profile LPC feature, also MIT-licensed) will
be attributed here when the code arrives.
