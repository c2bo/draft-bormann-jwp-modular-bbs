%%%
title = "BBS and Modular Sub-proofs with JSON Web Proofs"
abbrev = "JWP-BBS"
ipr = "trust200902"
area = "Security"
workgroup = "JOSE"
keyword = ["zero-knowledge proofs", "multi-message signatures", "BBS", "JWP"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-bormann-jwp-modular-bbs-latest"
stream = "IETF"
status = "standard"

[[author]]
initials = "C."
surname = "Bormann"
fullname = "Christian Bormann"
organization = "SPRIND GmbH"
  [author.address]
  email = "chris.bormann@gmx.de"

[[author]]
initials = "B."
surname = "Zundel"
fullname = "Brent Zundel"
organization = "Yubico"
  [author.address]
  email = "brent.zundel@gmail.com"

%%%

.# Abstract

This document defines a digital credential format that uses JSON Web Proofs (JWP) as its container format and Blind BBS Signatures as its signature scheme combined with a modular framework for attaching zero-knowledge sub-proofs. This allows a Holder to reveal some attributes directly while proving predicates such as range or equality over the ones they keep hidden. A credential can additionally be bound to a Holder-held device key, with possession of the key proven in every presentation without revealing the public key or signature. Concrete sub-proof and device-binding constructions are not defined in this document, only the core serialization. The credential type definition and data model follow SD-JWT VC [@!I-D.ietf-oauth-sd-jwt-vc].

{mainmatter}

# Introduction {#introduction}

The BBS signature scheme [@!I-D.irtf-cfrg-bbs-signatures] is a multi-message signature (MMS) scheme where the signer produces a single signature over a vector of messages m_0 through m_(n-1), and the Holder can prove knowledge of the signature in zero knowledge while disclosing only a chosen subset of those messages.

The Blind BBS Signatures extension [@!I-D.irtf-cfrg-bbs-blind-signatures] adds Pedersen commitments to the scheme that allow the Holder to mark each message as disclosed, hidden, or committed at proof time, and the resulting proof carries a fresh Pedersen commitment for every committed message. Those commitments become public inputs to further proofs over the values they hide.

Building on those core building blocks, this document defines a digital credential format that:

- Uses JSON Web Proofs [@!I-D.ietf-jose-json-web-proof] as the serialization/container format for both issuance and presentation, and defines a JSON Proof Algorithm [@!I-D.ietf-jose-json-proof-algorithms] profile based on Blind BBS Signatures.
- Builds its core proof on `CoreProofGen` of [@!I-D.irtf-cfrg-bbs-blind-signatures], exposing fresh Pedersen commitments to selected messages as public inputs for sub-proofs.
- Defines a sub-proof container carrying optional sub-proofs, each bound to the core proof via a Pedersen commitment.
- Optionally binds a credential to a Holder-held device key by encoding that key as messages in the BBS signature vector

This modular architecture builds on prior work [@?TS14] and [@?LSZ25], and the credential type model is reused from SD-JWT VC [@!I-D.ietf-oauth-sd-jwt-vc].

~~~ ascii-art
 +----------------+
 |                | ---------> +----------------+
 |                |            |   Revealed     |
 |                |            |   Attributes   |
 |                |            +----------------+
 |                |                    |
 |                |                    |
 |                | ---------> +--------------+      +--------------+
 |      MMS       |            |  Commitment  | ---> |  Sub-Proof   |
 |   Signature    |            +--------------+      +--------------+
 |                |                    |
 |                |                    |
 |                | ---------> +--------------+      +--------------+
 |                |            |  Commitment  | ---> |  Sub-Proof   |
 |                |            +--------------+      +--------------+
 |                |                    |
 +----------------+                    |
        |                              |
        |         +-----+------+-------+
        |         |     |      |
        v         v     v      v
        +----------------------------------------> +----------------+
        (revealed + commitment openings feed down) |    Core Proof  |
                                                   +----------------+
~~~

## Requirements Notation and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [@!RFC2119] [@!RFC8174]
when, and only when, they appear in all capitals, as shown here.

## Notational Conventions

All examples in this document are non-normative.

Indexing into vectors is 0-based. The notation `m_i` denotes the i-th element of the message vector: `m_0` is the first element. Ranges are written `[a, b]` for inclusive endpoints and `[a, b)` for a half-open interval.

## Terms and Definitions

This document uses the Issuer-Holder-Verifier model and terminology of [@!I-D.ietf-oauth-sd-jwt-vc].

Additional terms used are:

Core proof:
: A zero-knowledge proof of knowledge of a BBS signature on a message vector, where some messages are disclosed and others are exposed only as commitments.

Sub-proof:
: A zero-knowledge proof attached to a core proof, asserting a predicate over a message whose Pedersen commitment that core proof exposes.

Committed disclosure:
: Exposing a Pedersen commitment to a signed message in place of the value itself that is used as an input for sub-proofs.

Device binding:
: Tying a credential presentation to control of a Holder-held private key, by carrying a fresh proof of possession in every presentation.

# Data Model

A credential exists in two forms: the Issued Form an Issuer transmits to a Holder, and the Presented Form a Holder derives from it for a Verifier (see (#presentation)).

## Issued Credential {#issued-credential}

A credential is issued in the Issued Form (see [@!I-D.ietf-jose-json-web-proof, section 6.1]) consisting of:

- An Issuer Header ([@!I-D.ietf-jose-json-web-proof, section 6.1.1]) with the contents specified in (#issuer-header).
- `n` Issuer Payloads ([@!I-D.ietf-jose-json-web-proof, section 6.1.2]), where `n` is the length of the BBS message vector (see (#claims-mapping)). The Issuer Payload at position `i` is the octet string from which the scalar message `m_i` is derived per (#message-derivation).
- An Issuer Proof ([@!I-D.ietf-jose-json-web-proof, section 6.1.3]) carrying the BBS signature over `header_octets` and the message vector `(m_0, ..., m_(n-1))`.

`header_octets` is the Issuer Header as transmitted, i.e., the octets obtained by base64url-decoding the Issuer Header component of the Compact Serialization. All parties MUST use those octets as received and MUST NOT alter the header (e.g., re-encode).

The Issued Form is serialized using the Compact Serialization (see [@!I-D.ietf-jose-json-web-proof, section 7.1]). CBOR Serialization is (currently) out of scope for this document.

## Issuer Header {#issuer-header}

The Issuer Header is a JSON object with the following Header Parameters.

`alg` (REQUIRED):
: The Algorithm Header Parameter ([@!I-D.ietf-jose-json-web-proof, section 5.2.1]). This profile defines the JPA value `BBS-MOD` (see (#cipher-suite)).

`vct` (string, REQUIRED):
: The credential type identifier as defined in [@!I-D.ietf-oauth-sd-jwt-vc, section 2.2.2.1].

`cmap` (JSON object, REQUIRED):
: The mapping from claim names to message-vector positions and per-message encoding - see (#claims-mapping) for more details.

`kb` (string, OPTIONAL):
: The device-binding identifier - see (#device-binding-header). When absent, the credential is not device-bound, and a presentation MUST NOT include a device-binding sub-proof.

Temporal claims (`exp`, `nbf`, `iat`) MUST NOT appear as Issuer Header values - see (#temporal-claims) for more details.

The JWP `iek`, `hpk`, and `hpa` Header Parameters (Sections 5.2.5, 5.2.6, and 5.2.7 of [@!I-D.ietf-jose-json-web-proof]) MUST NOT appear in the Issuer Header.

## Claims Mapping {#claims-mapping}

`cmap` mirrors the credential's JSON tree structurally. Each leaf is replaced by an index annotation: a two-element array `[i, scalar]`, where:

- `i` is the 0-based index of the leaf value in the message vector.
- `scalar` is a boolean selecting how the leaf becomes the BBS message m_i:
  - `false`: the leaf is encoded as octets and mapped to a scalar via the cipher suite's hash-to-scalar primitive (see (#message-derivation)).
  - `true`: the leaf MUST be a JSON integer in `[0, r - 1]` (where `r` is the order of the BBS scalar field) and is used directly as m_i (see (#scalar-encoding)).

Let `n` be the length of the message vector, and `N` the number of payload slots reserved for the device-key encoding (see (#device-binding-header)), with `N = 0` when `kb` is absent. Every index in `[N, n-1]` MUST appear in exactly one annotation in `cmap`. Indices `[0, N-1]` MUST NOT appear in `cmap`.

The top-level member names of `cmap` MUST NOT be `vct`, `alg`, `cmap`, or `kb`. This keeps the reconstructed payload (see (#reconstructed-payload)) free of collisions with the `vct` member taken from the Issuer Header and prevents claim values from masquerading as header-derived members.

Receivers MUST validate `cmap` before use: every leaf is a two-element annotation of a non-negative integer index and a boolean, every index in `[N, n-1]` appears in exactly one annotation, no other index appears, and the name restrictions above hold. Holders MUST reject an issued credential and Verifiers MUST reject a presentation that violates any of these constraints.

Payload slots defined by the credential type's structural layout (see (#layout)) but not populated by a given credential MUST carry the decoy value defined in (#decoys).

## Example: Issuance {#example-issuer-header}

Starting from an SD-JWT VC-style claim set [@!I-D.ietf-oauth-sd-jwt-vc]:

~~~ json
{
  "vct": "https://credentials.example.com/identity_credential",
  "given_name": "Erika",
  "family_name": "Mustermann",
  "email": "erika@example.com",
  "phone_number": "+49 123456789",
  "address": {
    "street_address": "Heidestraße 17",
    "locality": "Köln",
    "region": "Nordrhein-Westfalen",
    "country": "DE"
  },
  "birthdate": 19630812,
  "iat": 1683000000,
  "exp": 1786000000
}
~~~

The `vct` claim becomes a Header Parameter and the other 11 attributes become leaves in `cmap`, with `address` mirrored as a nested object. No device binding is used, so `N = 0` and the leaves occupy indices 0 through 10. The temporal claims `iat` and `exp` are carried as `scalar = true` leaves (see (#temporal-claims)) to allow range sub-proofs over them. The resulting Issuer Header is:

~~~ json
{
  "alg": "BBS-MOD",
  "vct": "https://credentials.example.com/identity_credential",
  "cmap": {
    "given_name": [0, false],
    "family_name": [1, false],
    "email": [2, false],
    "phone_number": [3, false],
    "address": {
      "street_address": [4, false],
      "locality": [5, false],
      "region": [6, false],
      "country": [7, false]
    },
    "birthdate": [8, true],
    "iat": [9, true],
    "exp": [10, true]
  }
}
~~~

Indices 0–7 use hash-to-scalar and indices 8–10 carry their integer values directly as scalars, with `iat` and `exp` as NumericDate integers ([@!RFC7519]). A presentation can then mark `iat`/`exp` as `COMMIT` (see (#core-proof)) and attach range sub-proofs (see (#sub-proofs)) to prove validity without disclosing the timestamps.

A real deployment would define a structural layout covering all optional attributes and array slots up to their maximum length, with absent slots filled by decoys (see (#decoys)).

## Message Derivation {#message-derivation}

For an annotation `[i, false]` with leaf value `v`:

1. `o` is a JSON serialization of `v` - a single JSON text [@!RFC8259] encoded in UTF-8 (e.g., `"Erika"` for a string, `true` for a boolean) - carried as Issuer Payload `i`. The Issuer MAY produce any serialization of `v`, as the payload octets rather than the abstract value are what is mapped to the message scalar. Holders and Verifiers MUST use the received payload octets as-is and MUST NOT re-serialize them.
1. m_i = `hash_to_scalar(o, map_dst)`, with `map_dst = api_id || "MAP_MSG_TO_SCALAR_AS_HASH_"` and `api_id` the Interface identifier of (#cipher-suite). This is the per-message derivation of `BBS.messages_to_scalars` ([@!I-D.irtf-cfrg-bbs-signatures, section 4.1.2]).

Numeric leaves recovered via JSON parsing are subject to JSON number-precision interoperability limits - Issuers SHOULD keep `scalar = false` number values within the I-JSON [@?RFC7493] range.

For an annotation `[i, true]` with leaf value `v`:

1. `o` is the canonical decimal octet encoding of `v` (see (#scalar-encoding)), carried as Issuer Payload `i`.
1. m_i is the integer denoted by `o`, interpreted as an element of the BBS scalar field.

## Scalar Encoding {#scalar-encoding}

A leaf with `scalar = true` MUST be a JSON integer in `[0, r - 1]`, where `r` is the order of the BBS scalar field. Implementations MUST reject any other value.

The Issuer Payload for such a leaf is the canonical decimal octet encoding of the integer: ASCII digits without sign or leading zeros, with `0` represented as the single digit `0`. Future extensions MAY define additional scalar encodings provided they deterministically map a JSON value to an element of `[0, r - 1]`.

\[Editor's Note: The whole scalar = true construction might be solved by the blind bbs draft and be removed from this draft]

## Temporal Claims {#temporal-claims}

The JWT temporal claims `exp`, `nbf`, and `iat` ([@!RFC7519, section 4.1]), when present in a credential, MUST be declared as `scalar = true` leaves in `cmap` carrying their NumericDate values. They MUST NOT appear as Issuer Header values.

## Device Binding Header {#device-binding-header}

When present, the `kb` Header Parameter is a string identifier selecting both the device public key type and its encoding into the BBS message vector. The reserved slots are always indices `[0, N-1]`, where `N` depends on the `kb` value. If `kb` is not present, no slots are reserved.

A `kb` value and its matching device-binding sub-proof algorithm (see (#sub-proofs)) share the same algorithm identifier string. Valid `kb` values are the entries of the Sub-Proof Algorithms registry whose Device Binding field is `yes` - see (#iana). The specification defining such an entry MUST define the number of reserved slots `N`, the encoding of the device public key into the messages and Issuer Payloads at indices `[0, N-1]`, any validation the Issuer performs on the key before computing the message vector, and the matching device-binding sub-proof.

This document does not define any `kb` value.

\[Editor's Note: A device binding based on ECDSA P-256 keys (encoding the affine coordinates as 128-bit limbs and proving possession via a signature on a message derived from `presentation_header_octets`) is expected to be defined in a companion document.]

\[Editor's Note: Discuss an alternative design that would allow every claim to point to an array of indices (messages in bbs). This would allow us to get rid of the special kb treatment and instead move the relevant information into normal claims.]

## Structural Layout {#layout}

For claims containing objects, the Issuer either mirrors the object structure within `cmap` or treats the JSON-encoded object as a single leaf. This is a policy decision by the Issuer and allows some objects to be discloseable only as one object containing all values or not at all.

For bounded-length array claims, `cmap` contains an array of index annotations sized to the credential type's maximum array length. All entries in such an array SHOULD share the same `scalar` flag to guarantee a single decoy encoding (see (#decoys)).

For optional claims, `cmap` MUST contain the index entry regardless of whether the attribute is present in a given credential.

## Decoys {#decoys}

Decoys fill payload slots that the credential type's layout defines, but a specific credential does not populate. They keep the message-vector length and `cmap` identical across all credentials of a given `vct` to avoid correlation.

Every decoy slot carries the same fixed scalar:

~~~
m_decoy = hash_to_scalar("JWP-BBS-DECOY", map_dst)
~~~

with `hash_to_scalar` and `map_dst` as defined in (#message-derivation).

The Issuer Payload for a decoy slot depends on the slot's `scalar` flag:

- `scalar = false`: the ASCII octets of `"JWP-BBS-DECOY"`.
- `scalar = true`: the canonical decimal octet encoding of `m_decoy` (see (#scalar-encoding)).

A Verifier detects a disclosed decoy by comparing the disclosed Presentation Payload octets to the fixed decoy octets defined above. The `scalar = false` decoy octets are deliberately not a valid JSON text, so no payload produced per (#message-derivation) can collide with them. Decoys SHOULD NOT be disclosed unless required by the use case (for example, a proof over all members of a bounded-length array).

# Issuance

## Issuer Key Generation

The Issuer key pair is a BBS key pair ([@!I-D.irtf-cfrg-bbs-signatures, section 3.4]) using the cipher suite of (#cipher-suite).

## Credential Issuance

To issue a credential, the Issuer performs the following steps:

1. Construct the Issuer Header per (#issuer-header) and (#claims-mapping).
1. Derive the message vector `(m_0, ..., m_(n-1))` per (#message-derivation) and (#device-binding-header), filling decoys per (#decoys).
1. Compute the signature with `CoreSign` ([@!I-D.irtf-cfrg-bbs-signatures, section 3.6.1]) over `generators = create_generators(n + 1, api_id)`, `header_octets`, and the message vector, with `api_id` as in (#cipher-suite). No messages are Holder-committed at issuance, so the `Commit`/`BlindSign` flow of [@!I-D.irtf-cfrg-bbs-blind-signatures] is not used.
1. Assemble and serialize the Issued Form per (#issued-credential).

A non-normative example of the Compact Serialization:

~~~
<base64url(Issuer Header)>
.
<m_0>~<m_1>~ ... ~<m_10>
.
<base64url(BBS signature)>
~~~

Each `<m_i>` is the base64url-encoded Issuer Payload for index `i` (e.g., m_1 is `"Mustermann"` including the quotes, m_10 is `1786000000`). For `scalar = true` leaves the canonical decimal encoding coincides with the JSON serialization of the integer.

## Holder Verification

The Holder verifies an issued credential by:

1. Parsing the Issued Form.
1. Validating the `cmap` object per (#claims-mapping). Reject on violation.
1. Verifying the signature with `CoreVerify` ([@!I-D.irtf-cfrg-bbs-signatures, section 3.6.2]) over the same generators, `header_octets`, and message vector as issuance. Reject on failure.
1. For every `scalar = true` leaf, confirming the corresponding Issuer Payload decodes to an integer in `[0, r - 1]`.
1. For every `scalar = false` leaf, confirming the corresponding Issuer Payload either is byte-equal to the decoy octets (see (#decoys)) or parses as a single JSON text [@!RFC8259].
1. If `kb` is present, confirming that the device public key decoded from the reserved slots per the `kb` definition matches the Holder's device public key.

# Presentation

## Presented Form {#presented-form}

A presentation is a Presented Form ([@!I-D.ietf-jose-json-web-proof, section 6.2]) consisting of:

1. A Presentation Header as defined in (#presentation-header).
1. The unmodified Issuer Header.
1. `n` Presentation Payloads ([@!I-D.ietf-jose-json-web-proof, section 6.2.2]): disclosed positions carry the corresponding Issuer Payload and undisclosed positions are omitted (see [@!I-D.ietf-jose-json-web-proof, section 7.1]).
1. A Presentation Proof ([@!I-D.ietf-jose-json-web-proof, section 6.2.4]) consisting of one or more octet strings. The first octet string is the encoded core proof (see (#core-proof)). Subsequent optional octet strings are UTF-8 JSON-serialized sub-proof objects (see (#sub-proofs)) and MAY appear in any order. The Compact Serialization base64url-encodes each octet string.

## Presentation Header {#presentation-header}

The Presentation Header is a JSON object with the following Header Parameters.

`alg` (REQUIRED):
: The Algorithm Header Parameter ([@!I-D.ietf-jose-json-web-proof, section 5.2.1]). MUST be identical to the `alg` value of the Issuer Header.

`nonce` (string, REQUIRED):
: The Nonce Header Parameter ([@!I-D.ietf-jose-json-web-proof, section 5.2.10]).

`aud` (string, REQUIRED):
: The Audience Header Parameter ([@!I-D.ietf-jose-json-web-proof, section 5.2.9]).

Additional Header Parameters MAY be present, but their use is out of scope for this document.

`presentation_header_octets` is the Presentation Header as transmitted, i.e., the octets obtained by base64url-decoding the Presentation Header component of the Compact Serialization. It is bound into the core proof challenge (see (#core-proof)). Verifiers MUST use those octets as received.

## Core Proof {#core-proof}

The Holder builds a per-message disclosure map assigning each index in `[0, n-1]` one of `DISCLOSE`, `HIDE`, or `COMMIT`:

- `DISCLOSE`: the message is revealed and its value MUST match the corresponding disclosed Presentation Payload.
- `COMMIT`: a fresh Pedersen commitment to the message is carried in the proof. Every index referenced by a sub-proof (see (#sub-proofs)) MUST be marked `COMMIT`.
- `HIDE`: all other indices in `[0, n-1]`

The Holder generates the core proof by invoking `CoreProofGen` of [@!I-D.irtf-cfrg-bbs-blind-signatures] with:

- `PK`: Issuer public key.
- `signature`: BBS signature from the Issuer Proof.
- `generators`: `create_generators(n + 1, api_id)` (see [@!I-D.irtf-cfrg-bbs-signatures, section 4.1.1]).
- `header`: `header_octets`.
- `ph`: `presentation_header_octets` (binds `nonce` and `aud` into the challenge).
- `messages`: `(m_0, ..., m_(n-1))`.
- `disclosed_indexes`: indices marked `DISCLOSE`.
- `commits_indexes`: indices marked `COMMIT`.
- `api_id`: the cipher suite identifier of (#cipher-suite).

`CoreProofGen` returns `(proof, add_zkp_info)`. `add_zkp_info` contains, per committed index, the Pedersen commitment `C_i` and the blinding scalar `s_i`. The Holder retains it locally to build sub-proofs and MUST NOT transmit it. Only `proof` is carried as the first octet string of the Presentation Proof.

The core proof establishes that the Holder knows a BBS signature under the Issuer's public key on a message vector whose disclosed-index values match the disclosed Presentation Payloads, and that each carried `C_i` commits to the message at index `i` of that vector.

The Verifier verifies the core proof with `CoreProofVerify`, passing `PK`, the core proof, the generators, `header_octets`, `presentation_header_octets`, the disclosed scalar messages, and `api_id`. The disclosed and committed indices are recovered from the proof octets, not passed separately. On success, the Verifier recovers the committed indices and the corresponding `C_i` from the proof octets which are used in the sub-proof verification (see (#sub-proofs)).

## Sub-Proofs {#sub-proofs}

A sub-proof is a JSON object carried as an additional octet string of the Presentation Proof (see (#presented-form)) with the following members:

`alg` (string, REQUIRED):
: The sub-proof algorithm identifier from the Sub-Proof Algorithms registry (see (#iana)).

`input` (JSON object, REQUIRED):
: Public inputs to the sub-proof. MUST contain `i` and MAY contain algorithm-specific members.

  `i` is a non-empty array of message-vector indices, each of which MUST be a `COMMIT`-marked index of the core proof. Each algorithm fixes the length of `i` and the role of its entries.

`proof` (string, REQUIRED):
: The base64url [@!RFC4648] encoding of the sub-proof bytes specified by `alg`.

For each sub-proof, the Verifier MUST confirm that every value in `i` is among the committed indices recovered from the core proof, and MUST then run the algorithm-specific verification routine against the corresponding `C_i`, `input`, and `proof`.

Sub-proof freshness is inherited from the core proof: every `C_i` is randomized per presentation, and the core proof's challenge binds to `presentation_header_octets`. Sub-proof algorithms that include public material not derived from `C_i` (for example, a device signature in a device-binding sub-proof) MUST bind that material to the current presentation by other means, such as including `presentation_header_octets` in the signed message.

Sub-proof transcripts use the BBS encoding primitives of [@!I-D.irtf-cfrg-bbs-signatures, section 4.2.4.1]:

- BLS12-381 G1 points are serialized in their compressed form (48 octets)
- scalars as 32-octet big-endian integers
- integer lengths are encoded as `I2OSP(int, 8)`

A Verifier MUST reject a sub-proof carrying an encoded group element (in `input` or `proof`) that does not decode to a valid non-identity point of the G1 subgroup.

This document does not define any sub-proof algorithm. A specification registering a sub-proof algorithm (see (#iana)) MUST define:

- the length of `i` and the role of each of its entries,
- any additional members of `input` and their encoding,
- the layout of the proof bytes carried in `proof`,
- the verification routine, taking the commitments `C_i`, `input`, and `proof` as inputs, and
- how any public material not derived from `C_i` is bound to the current presentation.

## Presentation Verification {#presentation-verification}

The Verifier verifies a presentation by:

1. Parsing the Presented Form and validating the `cmap` object of the Issuer Header per (#claims-mapping). Reject on violation.
1. Confirming that the Presentation Header `alg` equals the Issuer Header `alg`, that `nonce` matches the value the Verifier supplied for this presentation, and that `aud` identifies this Verifier.
1. Deriving the disclosed message scalars from the disclosed Presentation Payloads per (#message-derivation). For a `scalar = true` leaf, the payload MUST be the canonical decimal encoding of an integer in `[0, r - 1]` (see (#scalar-encoding)). Reject otherwise.
1. Verifying the core proof with `CoreProofVerify` - see (#core-proof). Reject on failure. Confirming that the disclosed indices recovered from the proof are exactly the positions of the non-empty Presentation Payloads.
1. If `kb` is present in the Issuer Header, confirming that exactly one sub-proof with `alg` equal to the `kb` value is present. If `kb` is absent, confirming that no device-binding sub-proof is present.
1. Verifying every sub-proof per (#sub-proofs). Reject if any sub-proof fails to verify or carries an `alg` the Verifier does not support.

Whether the disclosed claims and the predicates established by sub-proofs satisfy the Verifier's requirements is an application-level decision and out of scope for this document. After successful verification, the Verifier reconstructs the JSON payload per (#reconstructed-payload).

## Example Presentation {#example-presentation}

Continuing the example of (#example-issuer-header), a Verifier requests `family_name` and asks the Holder to prove `exp` is in the future without disclosing it. The Presentation Header:

~~~ json
{
  "alg": "BBS-MOD",
  "nonce": "f4Oa3wT0r8m2Vn1pQ7sKdA",
  "aud": "https://verifier.example.com"
}
~~~

The Holder marks index 1 (`family_name`) as `DISCLOSE`, index 10 (`exp`) as `COMMIT`, and the rest as `HIDE`. The core proof then carries a fresh Pedersen commitment to m_10. The Holder attaches a range sub-proof over index 10 proving `now <= exp < 2^63` (with `now = 1779926400`).

~~~ json
{
  "alg": "<range sub-proof identifier>",
  "input": { "i": [10], "l": 1779926400, "u": 9223372036854775808 },
  "proof": "..."
}
~~~

The Compact Serialization concatenates with `.`: Presentation Header, Issuer Header, Presentation Payloads, Presentation Proof. The disclosed `family_name` at index 1 is the only populated payload and the other ten slots are empty:

~~~
<base64url(Presentation Header)>
.
<base64url(Issuer Header)>
.
~Ik11c3Rlcm1hbm4i~~~~~~~~~
.
<core proof>~<range sub-proof>
~~~

The Verifier verifies the core proof, recovers `C_10`, and checks the sub-proof against it. It learns `family_name` and that the credential has not expired.

## Reconstructed JSON Payload {#reconstructed-payload}

After verifying the core proof and any sub-proofs, the Verifier SHOULD convey to the application a JSON object reconstructed from the disclosed information, analogous to the Processed SD-JWT Payload of [@?RFC9901]. Reconstruction presupposes that `cmap` passed the validation of (#claims-mapping) - a presentation whose `cmap` object fails it MUST be rejected, not reconstructed. The procedure:

1. Start from `{ "vct": <vct from Issuer Header> }`.
1. Walk `cmap`. For each leaf at a disclosed index `i`, first compare the Presentation Payload octets to the decoy octets for that leaf's `scalar` flag (see (#decoys)) - on a byte-equal match, omit the leaf. Otherwise set the leaf's value by parsing the payload octets as a single JSON text [@!RFC8259] when `scalar` is `false`, or as the integer they denote (see (#scalar-encoding)) when `scalar` is `true`. A presentation containing a disclosed payload that fails to parse MUST be rejected. Hidden and committed-but-not-disclosed leaves are omitted.
1. Preserve the object and array structure of `cmap` for surviving leaves. Array entries that were omitted do not appear, so reconstructed array indices may differ from those in the `cmap` annotations.

Predicates established by sub-proofs are not represented as leaf values. The reconstruction procedure MUST NOT populate values for hidden or committed-but-not-disclosed leaves.

For (#example-presentation), the reconstructed payload is:

~~~ json
{
  "vct": "https://credentials.example.com/identity_credential",
  "family_name": "Mustermann"
}
~~~

# Cipher Suite {#cipher-suite}

This profile fixes exactly one cipher suite, so that `alg` does not vary across a credential population and split its anonymity set (see (#anonymity)).

## Identifier

JPA Algorithm JSON Label: `BBS-MOD`.

Cipher suite identifier (also used as `api_id` for hash-to-scalar, generator derivation, and sub-proof domain separation):

~~~
BBS-MOD_BLS12381G1_XMD:SHA-256_SSWU_RO_BLIND_H2G_HM2S_
~~~

The `BBS-MOD_` prefix separates this profile from both the base BBS JPA (`BBS` of [@!I-D.ietf-jose-json-proof-algorithms, section 9.1.2.4]) and the base blind BBS Interface (`BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_BLIND_H2G_HM2S_`). This profile invokes the core proof operations of that Interface directly to expose committed-message proofs - see (#core-proof). It also bypasses hash-to-scalar on a per-message basis under the `scalar` flag and attaches sub-proofs as described in (#sub-proofs).

## Parameters

- **Curve / group**: BLS12-381, G1 subgroup.
- **BBS ciphersuite**: `BBS-MOD_BLS12381G1_XMD:SHA-256_SSWU_RO_` - identical to `BLS12-381-SHA-256` ([@!I-D.irtf-cfrg-bbs-signatures, section 7.2.2], with hash-to-curve SHA-256 SSWU random oracle [@!RFC9380]) in all parameters except the ciphersuite identifier.
- **Hash-to-scalar**: as in the underlying BBS ciphersuite, with domain separation derived from `api_id`.
- **Core proof operations**: `CoreProofGen` / `CoreProofVerify` of [@!I-D.irtf-cfrg-bbs-blind-signatures] invoked directly (not via `BlindProofGen`), so implementations MUST apply the `commits_indexes` and `disclosed_indexes` checks of `CoreProofGen`.
- **Pedersen commitment generators**: `(G, H) = (Y_1, Y_0)` where `(Y_0, Y_1) = BBS.create_generators(2, "COM_DIS_" || api_id)`. Every committed-index commitment has the form `C_i = m_i * G + s_i * H` with `s_i` sampled per presentation by `CoreProofGen`.
- **Per-message hash-to-scalar bypass**: governed by each leaf's `scalar` flag (see (#claims-mapping)).

The `api_id` above follows the Interface identifier rule of [@!I-D.irtf-cfrg-bbs-blind-signatures, section 4.2] - `ciphersuite_id || "BLIND_H2G_HM2S_"` - applied to the ciphersuite identifier `BBS-MOD_BLS12381G1_XMD:SHA-256_SSWU_RO_`. All BBS operations used by this document are the Blind BBS Interface operations, or the core operations they wrap, which that document parameterizes with this `api_id`.

# Security Considerations

## Random Number Generation {#random}

All randomness used by this document MUST be generated using a cryptographically secure random number generator. Reuse or predictability of a blinding scalar or proof nonce could break unlinkability or soundness, or even leak the signing key.

## Replay and Presentation Freshness

Freshness relies on the Verifier-supplied `nonce`. Verifiers MUST generate nonces with enough entropy to make them unpredictable and MUST NOT accept a presentation carrying a `nonce` they did not supply for that transaction - see (#presentation-verification). The `aud` binding limits a captured presentation to its intended Verifier.

## Holder Binding

Without device binding (`kb` absent), possession of the Issued Form is sufficient to derive presentations, so anyone who obtains the credential in its Issued Form can present it. Deployments that need resistance against credential theft or pooling SHOULD use device binding - see (#device-binding-header).

# Privacy Considerations

## Issuer Header Correlation {#anonymity}

The Issuer Header is sent in clear to the Verifier. Any variation in it across Holders of the same `vct` narrows the anonymity set.

Implementations SHOULD make the Issuer Header byte-identical across the entire population of a `vct`, by:

- Fixing the `cmap` layout (including all optional attributes and maximum-length array slots) with a constant serialization.
- Filling unused slots with decoys per (#decoys).
- Carrying per-credential metadata (issuance time, expiry, identifiers) as messages in the message vector

## Cipher Suite and Algorithm Identifiers

`alg` and `kb` likewise split the anonymity set when they vary across the population of a `vct`. Implementations SHOULD use a single `alg` and a single `kb` type across all credentials of a `vct`, and SHOULD NOT mix device-bound and non-device-bound credentials under the same `vct`.

## Unlinkability Scope

The core proof hides everything except the disclosed messages, the carried commitments, and the sub-proof predicates. Parties observing multiple presentations (including colluding Verifiers, or an Issuer colluding with a Verifier) can still correlate them through disclosed attribute values, sub-proof predicate parameters, or transport-level metadata.

# IANA Considerations {#iana}

This document requests the following registrations and registry creations.

## JPA `alg` Value

IANA is requested to register the following JSON Proof Algorithm in the "JSON Web Proof Algorithms" registry established by [@!I-D.ietf-jose-json-proof-algorithms]:

- Algorithm Name: BBS-MOD using SHA-256
- Algorithm JSON Label: `BBS-MOD`
- Algorithm CBOR Label: TBD (requested assignment 11)
- Algorithm Description: Blind BBS over BLS12-381 with `CoreProofGen`-based committed-message proofs, the per-message `scalar` flag, and the sub-proof attachment mechanism of (#sub-proofs). Cipher suite identifier `BBS-MOD_BLS12381G1_XMD:SHA-256_SSWU_RO_BLIND_H2G_HM2S_`.
- Algorithm Usage Location(s): Issued, Presented
- JWP Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): (#cipher-suite) of this document.
- Algorithm Analysis Document(s): [@?LSZ25], [@?CT25]

## Header Parameter Registrations

IANA is requested to register the following Header Parameters in the "JSON Web Proof Header Parameters" registry established by [@!I-D.ietf-jose-json-web-proof]:

- Header Parameter Name: Claims Mapping
- Header Parameter JSON Label: `cmap`
- Header Parameter CBOR Label: TBD (requested assignment 11)
- Header Parameter Usage Location(s): Issued
- Change Controller: IETF
- Specification Document(s): (#claims-mapping) of this document.

- Header Parameter Name: Device Key Binding
- Header Parameter JSON Label: `kb`
- Header Parameter CBOR Label: TBD (requested assignment 12)
- Header Parameter Usage Location(s): Issued
- Change Controller: IETF
- Specification Document(s): (#device-binding-header) of this document.

## Sub-Proof Algorithms Registry

IANA is requested to create a new "Sub-Proof Algorithms" registry.

Allocation policy: Designated experts SHOULD verify that each entry pins its underlying group, generators, transcript hash, and that the sub-proof is bound to a commitment attested by the core proof per (#sub-proofs). For entries with Device Binding set to `yes`, they SHOULD additionally verify that the reference defines the reserved slot count `N` and the device-key encoding required by (#device-binding-header).

Registry fields:

- Identifier (the `alg` value of a sub-proof object)
- Description
- Device Binding (whether the identifier is also a valid `kb` value - see (#device-binding-header))
- Reference
- Change Controller

Initial entries: none. Concrete sub-proof algorithms are expected to be registered by companion documents.

{backmatter}

<reference anchor="TS14" target="https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts14-zkps-from-mms.md">
  <front>
    <title>Specification for the implementation of Zero-Knowledge Proofs based on multi-message signatures in the EUDI Wallet (TS-14)</title>
    <author>
      <organization>European Commission, EUDI Wallet Expert Group</organization>
    </author>
    <date year="2025"/>
  </front>
  <seriesInfo name="EUDI" value="TS-14"/>
  <refcontent>Work in Progress.</refcontent>
</reference>

<reference anchor="LSZ25" target="https://eprint.iacr.org/2025/1981">
  <front>
    <title>Vision: A Modular Framework for Anonymous Credential Systems</title>
    <author initials="A." surname="Lehmann"/>
    <author initials="A." surname="Sidorenko"/>
    <author initials="A." surname="Zacharakis"/>
    <date year="2025"/>
  </front>
  <seriesInfo name="IACR ePrint" value="2025/1981"/>
</reference>

<reference anchor="CT25" target="https://eprint.iacr.org/2025/1093">
  <front>
    <title>On the Concrete Security of BBS/BBS+ Signatures</title>
    <author initials="R." surname="Chairattana-Apirom"/>
    <author initials="S." surname="Tessaro"/>
    <date year="2025"/>
  </front>
  <seriesInfo name="IACR ePrint" value="2025/1093"/>
</reference>

# Acknowledgments

This document rests on the work captured in [@?TS14] by the EUDI Wallet expert group. The committed-message core proof builds on [@!I-D.irtf-cfrg-bbs-blind-signatures], and the modular committed-disclosure framework draws on [@?LSZ25].

# Document History

[[ pre Working Group Adoption: ]]

-03

* editorial fixes
* Remove the concrete sub-proof constructions - the document now only defines the sub-proof container and its serialization

-02

* rename the `claims` Header Parameter to `cmap` to avoid the JPT `claims` parameter
* add `alg` to the Presentation Header
* add more security considerations
* align IANA registrations with the registry templates (usage locations, requested CBOR labels)
* mandate JSON encoding for `scalar = false` payloads
* require `claims` validation
* add Presentation Verification section
* pin issuance signing to `CoreSign`
* define `kb` registration via a Device Binding registry field
* define canonical decimal encoding
* remove sigma-range construction, trim and reorder sub-proofs
* align cipher suite text with latest blind BBS draft

-01

* Fix venue note (was showing JOSE, should've been empty)
* Add ASCII Art overview
* some tweaks for sub-proof text
* update range proof reference to adopted draft-ietf-privacypass-arc-crypto (section moved to 5.4)
* add missing generators input to the CoreProofGen and CoreProofVerify descriptions
* align header parameter registrations with the JWP registry template

-00

* Initial Version
