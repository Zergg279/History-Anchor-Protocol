# Responsible Publication Profile v1

## Boundary

HAP base publication is permissionless. Amplification is an editorial and operational action performed by a client, indexer, or archive.

This profile constrains the reference client. It does not alter Bitcoin validity and cannot control hostile software.

## Mechanical first-hour rule

A claim begins outside the reference discovery feed unless:

- it is canonically confirmed in Bitcoin; and
- it declares `hap:person-impact:none`.

Direct, indirect/mosaic, uncertain, or missing person-impact declarations begin protected. False positives create discovery friction, not deletion.

## Mosaic identifiability

Names and faces are not the only identifiers. Role, location, time, relationships, or circumstances can identify a person by mosaic. Automated detection cannot catch every case.

An anchored `person_impact_notice` may start one fixed, non-renewable challenge window without publicly identifying the subject. Later notices do not extend that window. It affects discovery and amplification, not base validity or exact-ID access.

## Public interest

A `public_interest_justification` records the publisher's signed reasoning. It never lifts protection automatically.

The justification should explain the asserted public interest, why identification is necessary, less harmful alternatives considered, expected harm, evidence relied upon, and who accepts responsibility.

## Cooling and accountable decisions

A protected record may enter the reference feed only after:

- the configured Bitcoin-block cooling period has elapsed;
- an anchored `view_decision` requests `hap:view:enable-discovery`;
- that decision's author is recognised by the local client's disclosed accountability trust store;
- no recognised accountable restriction or active fixed challenge window applies.

An anchored notice from an unrecognised key can create only the fixed challenge window. Persistent restriction requires a `restriction_notice` or `view_decision` from an author recognised by the local client.

Pseudonymous publication remains permissionless. Pseudonymous keys are not automatically entitled to privileged amplification or indefinite suppression.

## No unilateral emergency bypass

The v1 reference profile implements no emergency amplification bypass. Emergency trust-store and threshold designs remain an ecosystem concern and must not be introduced as a self-certifying tag.

## Context-complete exact-ID views

Exact-ID access remains available. A conforming record view returns the original record together with linked subject responses, impact notices, restrictions, withdrawals, adjudications, public-interest claims, disputes, corrections, and view decisions.

Subject responses and disputes are not ranked by wealth, institutional prestige, or credential issuer. They remain prominent context but do not automatically grant burner keys indefinite suppression power. Credentials may describe identity provenance but do not purchase prominence or truth status.

## Good-faith limitation

A hostile aggregator can scrape raw protocol objects and omit context. HAP cannot cryptographically force a non-conforming publisher to behave responsibly.

The reference node exposes `/v1/view-manifest`, including its exact profile version, cooling periods, trust-store entries, and endpoint roles. The manifest is content-derived; operational identity may additionally be established through the server's domain/TLS or external signatures.

The profile's value comes from transparent conformance, legal and reputational pressure on identifiable operators, open reference software, view manifests, and user ability to choose another interface.
