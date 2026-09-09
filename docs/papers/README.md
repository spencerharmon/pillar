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
libp2p control traffic — the convergent cell-seal that keeps the `Cid` stable
under encryption, and the handshakeless (WoT-keyed) pillar-udp datagram seal that
replaces the libp2p Noise upgrade. Design of record for the `pillar-wire` crate;
implementation is TLA+-gated (method #1).
