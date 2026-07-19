# Recovery

A survival archive contains:

- signed records and append-only context;
- deterministic batches and packages;
- locally known anchor references;
- all evidence bytes the operator chose and remained permitted to preserve.

Every imported record, package, link, and evidence file is independently revalidated. Imported anchor status remains untrusted until checked against local Bitcoin history.

One complete surviving lawful archive plus Bitcoin history can reconstruct and re-seed the surviving HAP layer.

This does not mean every historical file can be recovered from a hash. If every physical copy is destroyed or lawfully removed, the Bitcoin commitment proves prior publication but cannot reconstruct the bytes.
