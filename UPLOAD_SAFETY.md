# Upload and relay safety

Base validity and local acceptance are separate.

Every node rejects malformed schemas, invalid signatures, invalid hashes, unknown critical fields, invalid targets, oversized objects, and invalid packages deterministically.

The reference safe relay additionally applies:

- request and record size limits;
- plain-text and control-character checks;
- HTTPS external source links or strict `hap:record:<id>` references;
- no embedded credentials in source links;
- no raw file upload through record endpoints;
- no retrieval locator in safe-relay evidence metadata;
- rate limits and optional record-bound proof-of-work;
- one person-impact declaration on claims when the responsible-publication profile is enabled;
- strict action tags for `view_decision` records.

A node may refuse to relay, retrieve, store, index, or display a protocol-valid object under local lawful policy. That refusal does not globally invalidate the Bitcoin publication.

Ordinary nodes never automatically download every referenced evidence file. Archive operation is explicit and locally controlled.
