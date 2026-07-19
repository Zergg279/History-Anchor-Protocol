# Operations

- Keep Bitcoin RPC private and use a dedicated minimally funded wallet.
- Keep mainnet disabled until regtest and signet commissioning are complete.
- Back up the SQLite database, portable packages, evidence store, wallet material, configuration, and survival archive separately.
- Test destruction and restoration, not merely backup creation.
- Monitor disk, peer response size, unresolved commitments, Bitcoin scan height, reorganisation state, and evidence verification failures.
- Use `/v1/feed` for the reference responsible-publication feed. Raw `/v1/records` data is protocol transport, not a safe editorial feed.
- Publish the local responsible-profile version, cooling period, and recognised accountable-author list.
- Leave the accountable-author list empty rather than inventing authority during cold start.
- Do not enable raw evidence serving without legal, safety, malware, and storage procedures appropriate to the jurisdiction.
