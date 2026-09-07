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
