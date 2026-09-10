# pillar-UDP whitepaper

`pillar-udp-congestion.tex` — *Clustered Multipath Congestion Avoidance and
Redundant Delivery over Lossy Networks*. Demonstrates pillar-UDP's
congestion-avoidance, cell-to-cell full-mesh, automatic geographic
load-balancing, and redundancy characteristics, citing the TLA+ models in
`../../specs/PillarUdpClient.tla` (one-to-many, non-node client) and
`../../specs/PillarUdpMesh.tla` (many-to-many, inter-cell full mesh).

The TLC results quoted in Table 1 are produced by `../../specs/check.sh`
(both specs are in the permanent gate). Re-verify:

```
cd ../../specs && ./check.sh          # runs every spec incl. the two pillar-UDP ones
```

Build the PDF (needs a TeX install with tikz + pgfplots):

```
pdflatex pillar-udp-congestion.tex && pdflatex pillar-udp-congestion.tex
```

A companion paper will cover the redundancy-header format and the quantitative
loss/bandwidth scaling.

`pillar-message-format.md` — *The Pillar Message Format*. The single sealed,
content-addressed, version-stamped `PillarMessage` envelope that carries every
byte Pillar persists or transmits — streamdb ops, observability signals, and all
libp2p control traffic — and the convergent cell-seal that keeps the `Cid` stable
under encryption (transport-agnostic). Design of record for the `pillar-wire`
crate; implementation is TLA+-gated (method #1).

`pillar-udp-encryption.md` — *pillar-udp Encryption: the portable cell-minted
session key*. How a **pillar-udp** datagram is encrypted on the wire, replacing the
libp2p Noise upgrade: a cell-as-KDC scheme distributing a deterministically-derived,
**portable** session key over streamdb (any cell node can serve the session), with
anonymous sessions handled by policy (not a separate crypto scheme) and forward
secrecy deliberately bounded to cell-key security for cross-node portability. QUIC/TCP
fallbacks use their own TLS instead. TLA+-gated by `../../specs/PillarUdpEncryption.tla`.
Rendered as a formal LaTeX paper with a packet-flow diagram in
`pillar-udp-encryption.tex` (companion to the congestion paper; the `.md` is the
design-of-record prose). Build the PDF (needs a TeX install with tikz + pgfplots):

```
pdflatex pillar-udp-encryption.tex && pdflatex pillar-udp-encryption.tex
```
