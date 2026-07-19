# Bitcoin anchoring

HAP uses an ordinary Bitcoin transaction containing a 38-byte `OP_RETURN` commitment:

```text
HIST | version 03 | batch type 01 | 32-byte batch identifier
```

The commitment contains no human-readable allegation, name, evidence file, locator, or HAP governance instruction.

Bitcoin miners need no HAP-aware software or protocol upgrade. They validate and confirm an ordinary Bitcoin transaction under existing Bitcoin rules.

HAP nodes identify an anchor by `txid:vout`, scan the active Bitcoin chain, track confirmations and reorganisations, and independently match the committed batch package.

Bitcoin proves that an exact commitment existed by a block. It does not prove that the external-world statement inside the corresponding off-chain package is true.
