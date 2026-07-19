# Security Policy

## Supported release

Security fixes target the latest v1 release and are published as versioned source changes. Existing protocol objects retain their original interpretation.

## Reporting

Do not disclose an exploitable vulnerability first through a public record, issue, or social post. Use the private security contact configured by the repository operator. A public GitHub mirror should enable private vulnerability reporting before launch.

## Scope

High-priority reports include:

- signature, canonicalisation, ID, Merkle, package, or Bitcoin-verification bypasses;
- parser divergence between implementations;
- remote code execution, SSRF, path traversal, decompression, or evidence-store escape;
- authentication or role bypasses;
- snapshot or peer import trust escalation;
- responsible-feed bypass in the reference client;
- silent omission of linked context in a client claiming responsible-profile conformance.

## Boundaries

A protocol-valid false statement is not a cryptographic vulnerability. A hostile non-conforming republisher ignoring context is a documented ecosystem limitation, though vulnerabilities that let a conforming client silently do so are in scope.

Never expose private keys, Bitcoin wallet credentials, personal data, or illegal content in a vulnerability report.
