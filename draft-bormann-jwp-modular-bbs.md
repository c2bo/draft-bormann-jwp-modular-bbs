%%%
title = "BBS and Modular Sub-proofs with JSON Web Proofs"
abbrev = "JWP-BBS"
ipr = "trust200902"
area = "Security"
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

%%%

.# Abstract

This document specifies a digital credential format that uses JSON Web Proofs (JWP) as a container, Blind BBS Signatures as the signature scheme, and a modular framework for attaching zero-knowledge sub-proofs to signed but undisclosed attributes. The format supports selective disclosure, predicate sub-proofs over undisclosed attributes, and optional device binding via an ECDSA P-256 proof of possession. It reuses the credential type and metadata model of SD-JWT Verifiable Credentials.

{mainmatter}

# Introduction {#introduction}

The BBS signature scheme [@!I-D.irtf-cfrg-bbs-signatures] is a multi-message signature (MMS) scheme: the signer produces a single signature over a vector of messages m_0 through m_(n-1), and the Holder can prove knowledge of the signature in zero knowledge while disclosing only a subset of those messages.

The Blind BBS Signatures extension [@!I-D.irtf-cfrg-bbs-blind-signatures] adds Pedersen commitments to the scheme. Its `CoreProofGen` operation allows the Holder to mark each message as disclosed, hidden, or committed at proof time. The resulting proof carries fresh Pedersen commitments to the committed messages. These commitments serve as public inputs to additional proofs over the committed values.

This document defines a digital credential format that:

- Uses JSON Web Proofs [@!I-D.ietf-jose-json-web-proof] as the container for both issuance and presentation, and defines a JSON Proof Algorithm [@!I-D.ietf-jose-json-proof-algorithms] profile based on Blind BBS Signatures.
- Uses `CoreProofGen` of [@!I-D.irtf-cfrg-bbs-blind-signatures] as the core proof, exposing fresh Pedersen commitments to selected messages as public inputs for sub-proofs.
- Defines a sub-proof container carrying zero or more sub-proofs, each bound to the core proof via a Pedersen commitment to a signed message.
- Optionally supports device binding to an ECDSA P-256 key by encoding the device public key as messages in the BBS signature vector.

The modular architecture follows [@TS14] and [@LSZ25]. The credential type and metadata model are reused from SD-JWT VC [@!I-D.ietf-oauth-sd-jwt-vc].

## Requirements Notation and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [@!RFC2119] [@!RFC8174]
when, and only when, they appear in all capitals, as shown here.

## Notational Conventions

All examples in this document are non-normative.

Indexing into vectors is 0-based. The notation `m_i` denotes the i-th element of the message vector: `m_0` is the first element. Ranges are written `[a, b]` for inclusive endpoints and `[a, b)` for a half-open interval.

## Terms and Definitions

This document uses the Issuer-Holder-Verifier model and terminology of Section 1 of [@!I-D.ietf-oauth-sd-jwt-vc].

Additional terms used are:

Core proof:
: A zero-knowledge proof establishing knowledge of a blind BBS signature on a message vector, with selective disclosure of some messages and committed disclosure of others.

Sub-proof:
: A zero-knowledge proof, attached to a core proof, that proves a predicate over a message whose Pedersen commitment is exposed by that core proof. Examples include range, equality, set-membership, and ECDSA device-binding sub-proofs.

Committed disclosure:
: Exposing a Pedersen commitment to a signed message in place of the message value itself, enabling further proofs over that message without revealing it.

Device binding:
: A mechanism that ties a credential presentation to control of a Holder-held private key by including a fresh proof of possession in every presentation.

# Data Model

This section specifies the credential and presentation data model.

## Issued Credential {#issued-credential}

A credential is issued in the Issued Form (Section 6.1 of [@!I-D.ietf-jose-json-web-proof]) consisting of:

1. An Issuer Header (Section 6.1.1 of [@!I-D.ietf-jose-json-web-proof]) with the contents specified in (#issuer-header).
1. `n` Issuer Payloads (Section 6.1.2 of [@!I-D.ietf-jose-json-web-proof]), where `n` is the length of the BBS message vector (see (#claims-mapping)). The Issuer Payload at position `i` is the octet string from which the scalar message m_i is derived per (#message-derivation).
1. An Issuer Proof (Section 6.1.3 of [@!I-D.ietf-jose-json-web-proof]) carrying the blind BBS signature over `header_octets` and the message vector `(m_0, ..., m_(n-1))`.

`header_octets` is the Issuer Header as transmitted, i.e., the octets obtained by base64url-decoding the Issuer Header component of the Compact Serialization. All parties MUST use those octets as received and MUST NOT re-encode the header.

The Issued Form is serialized using the Compact Serialization (Section 7.1 of [@!I-D.ietf-jose-json-web-proof]). CBOR Serialization is out of scope for this document.

## Issuer Header {#issuer-header}

The Issuer Header is a JSON object with the following Header Parameters.

`alg` (REQUIRED):
: The Algorithm Header Parameter (Section 5.2.1 of [@!I-D.ietf-jose-json-web-proof]). This profile defines the JPA value `BBS-MOD` (see (#cipher-suite)).

`vct` (string, REQUIRED):
: The credential type identifier as defined in Section 3.2.2.1 of [@!I-D.ietf-oauth-sd-jwt-vc].

`claims` (JSON object, REQUIRED):
: The mapping from claim names to message-vector positions and per-message encoding - see (#claims-mapping) for more details.

`kb` (string, OPTIONAL):
: The device-binding identifier - see (#device-binding-header). When absent, the credential is not device-bound, and a presentation MUST NOT include a device-binding sub-proof.

Temporal claims (`exp`, `nbf`, `iat`) MUST NOT appear as Issuer Header values - see (#temporal-claims) for more details.

The JWP `iek`, `hpk`, and `hpa` Header Parameters (Sections 5.2.5–5.2.7 of [@!I-D.ietf-jose-json-web-proof]) MUST NOT appear in the Issuer Header.

## Claims Mapping {#claims-mapping}

`claims` mirrors the credential's attribute tree structurally. Each leaf is replaced by an *index annotation*: a two-element JSON array `[i, scalar]`, where:

- `i` is the 0-based index of the leaf value in the message vector.
- `scalar` is a boolean selecting how the leaf becomes the BBS message m_i:
  - `false`: the leaf is encoded as octets and mapped to a scalar via the cipher suite's hash-to-scalar primitive (see (#message-derivation)).
  - `true`: the leaf MUST be a JSON integer in `[0, r - 1]` (where `r` is the order of the BBS scalar field) and is used directly as m_i (see (#scalar-encoding)).

Let `n` be the length of the message vector, and `N` the number of payload slots reserved for the device-key encoding (see (#device-binding-header)), with `N = 0` when `kb` is absent). Every index in `[N, n-1]` MUST appear in exactly one annotation in `claims`. Indices `[0, N-1]` MUST NOT appear in `claims`.

Payload slots reserved by the credential type's structural layout (see (#layout)) but not populated by a given credential MUST carry the decoy value defined in (#decoys).

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
  "birthdate": "19630812",
  "is_over_18": true,
  "is_over_21": true,
  "is_over_65": false,
  "iat": 1683000000,
  "exp": 1786000000
}
~~~

The `vct` claim becomes a Header Parameter and the other 14 attributes become leaves in `claims`, with `address` mirrored as a nested object. No device binding is used, so `N = 0` and the leaves occupy indices 0 through 13. The temporal claims `iat` and `exp` are carried as `scalar = true` leaves (see (#temporal-claims)) so that range sub-proofs can be attached. The resulting Issuer Header is:

~~~ json
{
  "alg": "BBS-MOD",
  "vct": "https://credentials.example.com/identity_credential",
  "claims": {
    "given_name":   [0, false],
    "family_name":  [1, false],
    "email":        [2, false],
    "phone_number": [3, false],
    "address": {
      "street_address": [4, false],
      "locality":       [5, false],
      "region":         [6, false],
      "country":        [7, false]
    },
    "birthdate":  [8, false],
    "is_over_18": [9, false],
    "is_over_21": [10, false],
    "is_over_65": [11, false],
    "iat": [12, true],
    "exp": [13, true]
  }
}
~~~

Indices 0–11 use hash-to-scalar and indices 12–13 carry NumericDate integers ([@!RFC7519]) directly as scalars. A presentation can then mark `iat`/`exp` as `COMMIT` (see (#core-proof)) and attach `sigma-range` sub-proofs (see (#range-proof)) to prove validity without disclosing the timestamps.

A real deployment would fix a structural layout covering every optional attribute and every maximum-length array slot, with absent slots filled by decoys (see (#decoys)).

## Message Derivation {#message-derivation}

For an annotation `[i, false]` with leaf value `v`:

1. The Issuer chooses an octet encoding `o` of `v` (e.g., the UTF-8 octets of a string) and carries it as Issuer Payload `i`. This profile does not mandate a specific encoding. Holders MUST use the received payload octets as-is.
1. m_i = `hash_to_scalar(o, map_dst)`, with `map_dst = api_id || "MAP_MSG_TO_SCALAR_AS_HASH_"` and `api_id` the Interface identifier of (#cipher-suite). This is the per-message derivation of `BBS.messages_to_scalars` (Section 4.1.2 of [@!I-D.irtf-cfrg-bbs-signatures]).

For an annotation `[i, true]` with leaf value `v`:

1. `o` is the canonical decimal octet encoding of `v` (see (#scalar-encoding)), carried as Issuer Payload `i`.
1. m_i is the integer denoted by `o`, interpreted as an element of the BBS scalar field.

## Scalar Encoding {#scalar-encoding}

A leaf with `scalar = true` MUST be a JSON integer in `[0, r - 1]`, where `r` is the order of the BBS scalar field. Implementations MUST reject any other value.

The Issuer Payload for such a leaf is the *canonical decimal octet encoding* of the integer: the ASCII octets of its base-10 representation, with no leading zeros (the single octet `0` for value zero) and no sign character.

Future extensions MAY define additional scalar encodings provided they deterministically map a JSON value to an element of `[0, r - 1]`.

## Temporal Claims {#temporal-claims}

The JWT temporal claims `exp`, `nbf`, and `iat` (Section 4.1 of [@!RFC7519]), when present in a credential, MUST be declared as `scalar = true` leaves in `claims` carrying their NumericDate values. They MUST NOT appear as Issuer Header values.

## Device Binding Header {#device-binding-header}

When present, the `kb` Header Parameter is a string identifier selecting both the device public key type and its encoding into the BBS message vector. The reserved slots are always indices `[0, N-1]`, where `N` depends on the `kb` value. This document defines a single value: `ecdsa-p256-limb4-64`.

Note: `kb` here identifies a public-key encoding layout, not the SD-JWT "Key Binding JWT" mechanism (Section 4.3 of [@RFC9901]). The Holder proof of possession is conveyed by a sub-proof. See (#design-rationale) for the rationale behind the limb encoding.

For `kb = "ecdsa-p256-limb4-64"`, `N = 8` and:

- m_0..m_3 encode the x-coordinate of the device public key as four 64-bit little-endian limbs (m_0 least significant).
- m_4..m_7 encode the y-coordinate the same way.

Each limb is encoded as if `scalar = true`: the Issuer Payload is its canonical decimal octet encoding (see (#scalar-encoding)).

The Issuer MUST verify that `(x, y)` is a valid non-identity P-256 point [@!FIPS186-5] before computing the message vector.

## Structural Layout {#layout}

For object-valued claims, the Issuer either mirrors the object structure within `claims` or treats the JSON-encoded object as a single leaf.

For bounded-length array claims, `claims` contains a JSON array of index annotations sized to the credential type's maximum array length. All entries in such an array SHOULD share the same `scalar` flag so that a single decoy encoding (see (#decoys)) applies to every slot.

For optional claims, `claims` MUST contain the entry regardless of whether the attribute is present in a given credential.

## Decoys {#decoys}

A decoy fills a payload slot reserved by the credential type's structural layout but not populated for a specific credential. Decoys keep the message-vector length and `claims` structure identical across all credentials of a given `vct`, so that Issuer Header disclosure does not narrow the anonymity set (see (#anonymity)).

Every decoy slot carries the same fixed scalar:

~~~
m_decoy = hash_to_scalar("JWP-BBS-DECOY", map_dst)
~~~

with `hash_to_scalar` and `map_dst` as defined in (#message-derivation).

The Issuer Payload for a decoy slot depends on the slot's `scalar` flag so that running (#message-derivation) over it recovers `m_decoy`:

- `scalar = false`: the ASCII octets of `"JWP-BBS-DECOY"`.
- `scalar = true`: the canonical decimal octet encoding of `m_decoy` (see (#scalar-encoding)).

A Verifier detects a disclosed decoy by comparing the disclosed Presentation Payload octets to the fixed decoy octets defined above. Decoys SHOULD NOT be disclosed unless required by the use case (for example, a proof over all members of a bounded-length array).

# Issuance

## Issuer Key Generation

The Issuer key pair is a BBS key pair (Section 3.4 of [@!I-D.irtf-cfrg-bbs-signatures]) using the cipher suite of (#cipher-suite).

## Credential Issuance

To issue a credential:

1. Construct the Issuer Header per (#issuer-header) and (#claims-mapping).
1. Derive the message vector `(m_0, ..., m_(n-1))` per (#message-derivation) and (#device-binding-header), filling decoys per (#decoys).
1. Compute the blind BBS signature over `header_octets` and the message vector.
1. Assemble and serialize the Issued Form per (#issued-credential).

A non-normative example of the Compact Serialization:

~~~
<base64url(Issuer Header)>
.
<m_0>~<m_1>~ ... ~<m_13>
.
<base64url(blind BBS signature)>
~~~

Each `<m_i>` is the base64url-encoded Issuer Payload for index `i` (e.g., m_1 is "Mustermann", m_13 is `1786000000`).

## Holder Verification

The Holder verifies an issued credential by:

1. Parsing the Issued Form.
1. Verifying the blind BBS signature over `header_octets` and the message vector. Reject on failure.
1. For every `scalar = true` leaf, confirming the corresponding Issuer Payload decodes to an integer in `[0, r - 1]`.
1. If `kb` is present, repeating the P-256 validation of (#device-binding-header) on the point reconstructed from the limb messages and confirming it matches the Holder's device public key. How the Holder obtains the corresponding device key pair is out of scope.

# Presentation

## Presented Form {#presented-form}

A presentation is a Presented Form (Section 6.2 of [@!I-D.ietf-jose-json-web-proof]) consisting of:

1. A Presentation Header per (#presentation-header).
1. The Issuer Header from issuance, byte-identical to the issued form.
1. `n` Presentation Payloads (Section 6.2.2 of [@!I-D.ietf-jose-json-web-proof]): disclosed positions carry the corresponding Issuer Payload and undisclosed positions are omitted (see Section 7.1 of [@!I-D.ietf-jose-json-web-proof]).
1. A Presentation Proof (Section 6.2.4 of [@!I-D.ietf-jose-json-web-proof]) consisting of one or more octet strings. The first octet string is the encoded core proof (see (#core-proof)). Subsequent octet strings, if any, are UTF-8 JSON-serialized sub-proof objects (see (#sub-proofs)) and MAY appear in any order. The Compact Serialization base64url-encodes each octet string.

## Presentation Header {#presentation-header}

The Presentation Header is a JSON object with the following Header Parameters.

`nonce` (string, REQUIRED):
: The Nonce Header Parameter (Section 5.2.10 of [@!I-D.ietf-jose-json-web-proof]).

`aud` (string, REQUIRED):
: The Audience Header Parameter (Section 5.2.9 of [@!I-D.ietf-jose-json-web-proof]).

Additional Header Parameters MAY be present, but their use is out of scope for this document.

`presentation_header_octets` is the Presentation Header as transmitted, i.e., the octets obtained by base64url-decoding the Presentation Header component of the Compact Serialization. It is bound into the core proof challenge (see (#core-proof)). Verifiers MUST use those octets as received.

## Core Proof {#core-proof}

The Holder builds a per-message disclosure map assigning each index in `[N, n-1]` (where `N` is as in (#claims-mapping)) one of `DISCLOSE`, `HIDE`, or `COMMIT`:

- `DISCLOSE`: the message is revealed and its value MUST match the corresponding disclosed Presentation Payload.
- `COMMIT`: a fresh Pedersen commitment to the message is carried in the proof. Every index referenced by a sub-proof (see (#sub-proofs)) MUST be marked `COMMIT`.
- `HIDE`: all other indices in `[N, n-1]`. Device-key indices `[0, N-1]` are implicitly hidden.

The Holder generates the core proof by invoking `CoreProofGen` of [@!I-D.irtf-cfrg-bbs-blind-signatures] with:

- `PK`: Issuer public key.
- `signature`: blind BBS signature from the Issuer Proof.
- `header`: `header_octets`.
- `ph`: `presentation_header_octets` (binds `nonce` and `aud` into the challenge).
- `messages`: `(m_0, ..., m_(n-1))`.
- `disclosed_indexes`: indices marked `DISCLOSE`.
- `commits_indexes`: indices marked `COMMIT`.
- `api_id`: the cipher suite identifier of (#cipher-suite).

`CoreProofGen` returns `(proof, add_zkp_info)`. `add_zkp_info` contains, per committed index, the Pedersen commitment `C_i` and the blinding scalar `s_i`. The Holder retains it locally to build sub-proofs and MUST NOT transmit it. Only `proof` is carried as the first octet string of the Presentation Proof.

The core proof establishes that the Holder knows a blind BBS signature under the Issuer's public key on a message vector whose disclosed-index values match the disclosed Presentation Payloads, and that each carried `C_i` commits to the message at index `i` of that vector.

The Verifier verifies the core proof with `CoreProofVerify`, passing `PK`, the core proof, `header_octets`, `presentation_header_octets`, the disclosed scalar messages, and `api_id`. The disclosed and committed indices are recovered from the proof octets, not passed separately. On success, the Verifier recovers the committed indices and the corresponding `C_i` from the proof octets which are used in the sub-proof verification (see (#sub-proofs)).

## Sub-Proofs {#sub-proofs}

A sub-proof is a JSON object carried as an additional octet string of the Presentation Proof (see (#presented-form)) with the following members:

`alg` (string, REQUIRED):
: The sub-proof algorithm identifier from the Sub-Proof Algorithms registry (see (#iana)).

`input` (JSON object, REQUIRED):
: Public inputs to the sub-proof. MUST contain `i` and MAY contain algorithm-specific members.

  `i` is a non-empty JSON array of message-vector indices, each of which MUST be a `COMMIT`-marked index of the core proof. Each algorithm fixes the length of `i` and the role of its entries.

`proof` (string, REQUIRED):
: The base64url [@!RFC4648] encoding of the sub-proof bytes specified by `alg`.

For each sub-proof, the Verifier MUST confirm that every value in `i` is among the committed indices recovered from the core proof, and MUST then run the algorithm-specific verification routine against the corresponding `C_i`, `input`, and `proof`.

Sub-proof freshness is inherited from the core proof: every `C_i` is randomized per presentation, and the core proof's challenge binds to `presentation_header_octets`. Sub-proof algorithms that include public material not derived from `C_i` (for example, the device ECDSA signature in `ecdsa-p256-db`) MUST bind that material to the current presentation by other means (`ecdsa-p256-db` does so via `db_msg` - see (#ecdsa-db)).

Sub-proof transcripts use the BBS encoding primitives of Section 4.2.4.1 of [@!I-D.irtf-cfrg-bbs-signatures]: BLS12-381 G1 points are serialized in their compressed form (48 octets), scalars as 32-octet big-endian integers, and integer lengths are encoded as `I2OSP(int, 8)`. The `serialize(...)` notation used in (#range-proof) and (#equality-proof) denotes the concatenation of these per-element encodings.

\[Editor's Note: Some of the following sub-proofs already make very concrete choices to make the construction more concrete - all of these are open for discussion and might significantly change.]

### ECDSA Device-Binding Sub-Proof {#ecdsa-db}

This sub-proof MUST be present whenever `kb = "ecdsa-p256-limb4-64"` and MUST NOT be present otherwise.

Algorithm identifier:
: `ecdsa-p256-db`

Inputs (beyond the base sub-proof fields): none. The `i` field MUST be `[0, 1, 2, 3, 4, 5, 6, 7]`, naming the eight indices that carry the device public-key limbs (see (#device-binding-header)).

The device-signed message is not transmitted, it is recomputed as:

~~~
db_msg = "JWP-BBS-DB-CHAL" || presentation_header_octets
~~~

where `"JWP-BBS-DB-CHAL"` is the literal ASCII string. Binding `db_msg` to `presentation_header_octets` carries `nonce` and `aud` and is therefore sufficient for freshness.

The proof bytes encode a non-interactive zero-knowledge proof of knowledge of `(dpk, (r, s))` such that:

1. The 8 commitments at the indices in `i` open to the 64-bit limbs of `dpk` (in the layout of `kb`) under `(G, H)` (see (#cipher-suite)).
2. `(r, s)` is a valid ECDSA P-256 signature on `db_msg` under `dpk`.

\[Editor's Note: TODO - select and describe concrete mechanism.]

The Verifier accepts if the 8 indices in `i` are all committed in the core proof and the sub-proof verifies against the 8 commitments and the locally recomputed `db_msg`.

### Range Proof Sub-Proof {#range-proof}

Algorithm identifier:
: `sigma-range`

Inputs (beyond the base sub-proof fields): bounds `l` and `u` as JSON integers. The `i` field MUST be a single-element array `[idx]`. The sub-proof attests that m_idx, the message committed in the core proof at index `idx`, satisfies `l <= m_idx < u`.

`l < u`, `u - l >= 2`, and `u - l <= 2^64` MUST hold. The `2^64` ceiling accommodates NumericDate values (Section 4.1 of [@!RFC7519]). The lower bound rules out single-value ranges, for which the construction is degenerate. Implementations MUST parse `l` and `u` as bigints. A deployment profile MAY permit a larger width.

The construction operates in BLS12-381 G1 against `C_idx` and follows the sigma-protocol range proof of Section 5.5 of [@!I-D.ietf-privacypass-arc-crypto]:

- Let `k` and `(base[0], ..., base[k-1])` be the outputs of `ComputeBases(u - l)` (Section 5.5 of [@!I-D.ietf-privacypass-arc-crypto]). The Holder writes `m_idx - l` as the sum over j in `[0, k-1]` of `b[j] * base[j]`, with each `b[j]` constrained to `{0, 1}`.
- For each `j` in `[0, k-1]`, the Holder samples blinding scalars `s[j]` and `s2[j]` and forms the bit commitment `D[j] = b[j] * G + s[j] * H` over `(G, H)` of (#cipher-suite). The Holder then proves, in a single batched Schnorr step, knowledge of `(b[j], s[j], s2[j])` such that `D[j] = b[j] * G + s[j] * H` and `D[j] = b[j] * D[j] + s2[j] * H` (the linearized bit constraint), producing per-bit Schnorr commitments `T1[j]` and `T2[j]` from fresh per-bit random scalars.
- The challenge is `c = hash_to_scalar(transcript, challenge_dst)` with `challenge_dst = api_id || "SIGMA_RANGE_CHAL_"` and `hash_to_scalar` the base BBS primitive of (#cipher-suite). The transcript is:

\[Editor's Note: describe wire format of proof]

### Equality Proof Sub-Proof {#equality-proof}

Algorithm identifier:
: `schnorr-eq`

Inputs (beyond the base sub-proof fields):

- `i`: a single-element array `[idx]`.
- `c_ext`: a base64url-encoded BLS12-381 G1 point.

The sub-proof attests that `C_idx` (from the core proof) and `c_ext` open to the same scalar under the generators `(G, H)` of (#cipher-suite). Cross-group equality is out of scope.

The construction is a 3-DL Schnorr discrete-logarithm-equality (DLEQ) proof over BLS12-381 G1 with `(G, H)`, with witness `(m, s_1, s_2)` such that:

~~~
C_idx = m * G + s_1 * H
c_ext = m * G + s_2 * H
~~~

The Holder samples fresh random scalars `(r_m, r_s1, r_s2)` and computes Schnorr commitments `T_1 = r_m * G + r_s1 * H` and `T_2 = r_m * G + r_s2 * H`. The challenge is `c = hash_to_scalar(transcript, challenge_dst)` with `challenge_dst = api_id || "SCHNORR_EQ_CHAL_"` and `hash_to_scalar` the base BBS primitive of (#cipher-suite). 

\[Editor's Note: describe wire format of proof]

## Example Presentation {#example-presentation}

Continuing the example of (#example-issuer-header), a Verifier requests `family_name` and asks the Holder to prove `exp` is in the future without disclosing it. The Presentation Header:

~~~ json
{
  "nonce": "f4Oa3wT0r8m2Vn1pQ7sKdA",
  "aud": "https://verifier.example.com"
}
~~~

The Holder marks index 1 (`family_name`) as `DISCLOSE`, index 13 (`exp`) as `COMMIT`, and the rest as `HIDE`. The core proof then carries a fresh Pedersen commitment to m_13. The Holder attaches a `sigma-range` sub-proof over index 13 proving `now <= exp < 2^63` (with `now = 1779926400`):

~~~ json
{
  "alg": "sigma-range",
  "input": { "i": [13], "l": 1779926400, "u": 9223372036854775808 },
  "proof": "..."
}
~~~

The Compact Serialization concatenates with `.`: Presentation Header, Issuer Header, Presentation Payloads, Presentation Proof. The disclosed `family_name` at index 1 is the only populated payload and the other thirteen slots are empty:

~~~
<base64url(Presentation Header)>
.
<base64url(Issuer Header)>
.
~TXVzdGVybWFubg~~~~~~~~~~~~
.
<core proof>~<sigma-range sub-proof>
~~~

The Verifier verifies the core proof, recovers `C_13`, and checks the sub-proof against it. It learns `family_name` and that the credential has not expired.

## Reconstructed JSON Payload {#reconstructed-payload}

After verifying the core proof and any sub-proofs, the Verifier MAY hand the application a JSON object reconstructed from the disclosed information, analogous to the Processed SD-JWT Payload of [@RFC9901]:

1. Start from `{ "vct": <vct from Issuer Header> }`.
1. Walk `claims`. For each leaf at a disclosed index `i`, set its value from the corresponding Presentation Payload (per (#message-derivation)), except when the payload octets are byte-equal to the decoy octets for that leaf's `scalar` flag (see (#decoys)), in which case omit the leaf. Hidden and committed-but-not-disclosed leaves are omitted.
1. Preserve the object and array structure of `claims` for surviving leaves. Array entries that were omitted do not appear, so reconstructed array indices may differ from those in the `claims` annotations.

Predicates established by sub-proofs are not represented as leaf values. The reconstruction procedure MUST NOT populate values for hidden or committed-but-not-disclosed leaves.

For (#example-presentation), the reconstructed payload is:

~~~ json
{
  "vct": "https://credentials.example.com/identity_credential",
  "family_name": "Mustermann"
}
~~~

# Cipher Suite {#cipher-suite}

This document defines a single JPA cipher suite.

## Identifier

JPA Algorithm JSON Label: `BBS-MOD`.

Cipher suite identifier (also used as `api_id` for hash-to-scalar, generator derivation, and sub-proof domain separation):

~~~
BBS-MOD_BLS12381G1_XMD:SHA-256_SSWU_RO_BLIND_H2G_HM2S_
~~~

The `BBS-MOD_` prefix domain-separates this profile from both the base BBS JPA (`BBS` of Section 9.1.2.4 of [@!I-D.ietf-jose-json-proof-algorithms]) and the base blind BBS Interface (`BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_BLIND_H2G_HM2S_`). It signals: committed-message proof generation, per-message hash-to-scalar bypass via `scalar`, and the sub-proof attachment mechanism of (#sub-proofs).

## Parameters

- **Curve / group**: BLS12-381, G1 subgroup.
- **Underlying BBS ciphersuite**: `BLS12-381-SHA-256` (Section 7.2.2 of [@!I-D.irtf-cfrg-bbs-signatures]) with hash-to-curve SHA-256 SSWU random oracle [@!RFC9380].
- **Hash-to-scalar**: as in the underlying BBS ciphersuite, with domain separation derived from `api_id`.
- **Core proof operations**: `CoreProofGen` / `CoreProofVerify` of [@!I-D.irtf-cfrg-bbs-blind-signatures] invoked directly (not via `BlindProofGen`), so implementations MUST apply the input validity checks of Section 7.1 of that document.
- **Pedersen commitment generators**: `(G, H) = (Y_1, Y_0)` where `(Y_0, Y_1) = BBS.create_generators(2, "COM_DIS_" || api_id)`. Every committed-index commitment has the form `C_i = m_i * G + s_i * H` with `s_i` sampled per presentation by `CoreProofGen`.
- **Per-message hash-to-scalar bypass**: governed by each leaf's `scalar` flag (see (#claims-mapping)).

The base BBS `KeyGen`, `Sign`, and `Verify` operations defined by this document use the BBS ciphersuite identifier `BBS-MOD_BLS12381G1_XMD:SHA-256_SSWU_RO_`. The BBS draft's default `api_id = ciphersuite_id || "H2G_HM2S_"` is not used. All base-BBS operations are parameterized by the `api_id` defined above (carrying the `BLIND_H2G_HM2S_` suffix), so that `key_dst` and other domain-separation tags are derived deterministically across implementations.

# Security Considerations

## Random Number Generation

All randomness used by this document MUST be generated using a cryptographically secure random number generator. Reuse or predictability of any of these values can lead to loss of unlinkability, soundness, or signing-key compromise. ECDSA implementations SHOULD use deterministic nonces per [@RFC6979].

## Hash-to-Scalar Bypass

\[Editor's Note: TODO - Check what exactly the attack scenarios are / if there are some]

# Privacy Considerations

## Issuer Header Correlation {#anonymity}

The Issuer Header is sent in clear to the Verifier. Any variation in it across Holders of the same `vct` narrows the anonymity set.

Implementations SHOULD make the Issuer Header byte-identical across the entire population of a `vct`, by:

- Fixing the `claims` layout (including all optional attributes and maximum-length array slots) with a constant serialization.
- Filling unused slots with decoys per (#decoys).
- Carrying per-credential metadata (issuance time, expiry, identifiers) as messages in the message vector, not as Header Parameters.

## Cipher Suite and Algorithm Identifiers

`alg` and `kb` likewise split the anonymity set when they vary across the population of a `vct`. Implementations SHOULD use a single `alg` and a single `kb` value (or omit `kb` entirely) across all credentials of a `vct`, and SHOULD NOT mix device-bound and non-device-bound credentials under the same `vct`.

# IANA Considerations {#iana}

This document requests the following registrations and registry creations.

## JPA `alg` Value

IANA is requested to register the following JSON Proof Algorithm in the "JSON Web Proof Algorithms" registry established by [@!I-D.ietf-jose-json-proof-algorithms]:

- Algorithm Name: BBS-MOD using SHA-256
- Algorithm JSON Label: `BBS-MOD`
- Algorithm CBOR Label: (to be assigned by IANA)
- Algorithm Description: Blind BBS over BLS12-381 with `CoreProofGen`-based committed-message proofs, the per-message `scalar` flag, and the sub-proof attachment mechanism of (#sub-proofs). Cipher suite identifier `BBS-MOD_BLS12381G1_XMD:SHA-256_SSWU_RO_BLIND_H2G_HM2S_`.
- Algorithm Usage Location(s): Issued, Presented
- JWP Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): (#cipher-suite) of this document.
- Algorithm Analysis Document(s): [@LSZ25], [@CT25]

## Header Parameter Registrations

IANA is requested to register the following Header Parameters in the "JSON Web Proof Header Parameters" registry established by [@!I-D.ietf-jose-json-web-proof]:

- Header Parameter Name: `claims`
- Header Parameter Description: Mapping from credential attribute names to their position in the BBS message vector and whether each is hashed to a scalar or supplied directly as a scalar.
- Header Parameter Usage Location(s): Issued, Presented
- Change Controller: IETF
- Specification Document(s): (#claims-mapping) of this document.

- Header Parameter Name: `kb`
- Header Parameter Description: Identifier for the device public-key type and its encoding layout in the BBS message vector.
- Header Parameter Usage Location(s): Issued, Presented
- Change Controller: IETF
- Specification Document(s): (#device-binding-header) of this document.

## Sub-Proof Algorithms Registry

IANA is requested to create a new "Sub-Proof Algorithms" registry.

Allocation policy: Specification Required ([@!RFC8126]). Designated experts SHOULD verify that each entry pins its underlying group, generators, transcript hash, and Fiat-Shamir domain separation, and that the sub-proof is bound to a commitment attested by the core proof per (#sub-proofs).

Registry fields: Identifier (the `alg` value of a sub-proof object), Description, Reference, Change Controller.

Initial entries:

- Identifier: `ecdsa-p256-db`
- Description: ECDSA P-256 device-binding sub-proof.
- Reference: This document, (#ecdsa-db).
- Change Controller: IETF.

- Identifier: `sigma-range`
- Description: Sigma-protocol range proof over a committed scalar message.
- Reference: This document, (#range-proof).
- Change Controller: IETF.

- Identifier: `schnorr-eq`
- Description: Schnorr proof of equality between a committed message and an external commitment.
- Reference: This document, (#equality-proof).
- Change Controller: IETF.

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

<reference anchor="LSZ25" target="https://eprint.iacr.org/2025/1981.pdf">
  <front>
    <title>Vision: A Modular Framework for Anonymous Credential Systems</title>
    <author initials="A." surname="Lehmann"/>
    <author initials="A." surname="Sidorenko"/>
    <author initials="A." surname="Zacharakis"/>
    <date year="2025"/>
  </front>
  <seriesInfo name="IACR ePrint" value="2025/1981"/>
</reference>

<reference anchor="FIPS186-5" target="https://doi.org/10.6028/NIST.FIPS.186-5">
  <front>
    <title>Digital Signature Standard (DSS)</title>
    <author>
      <organization>National Institute of Standards and Technology</organization>
    </author>
    <date year="2023" month="February"/>
  </front>
  <seriesInfo name="FIPS PUB" value="186-5"/>
  <seriesInfo name="DOI" value="10.6028/NIST.FIPS.186-5"/>
</reference>

<reference anchor="CT25" target="https://eprint.iacr.org/2025/1093.pdf">
  <front>
    <title>On the Concrete Security of BBS/BBS+ Signatures</title>
    <author initials="R." surname="Chairattana-Apirom"/>
    <author initials="S." surname="Tessaro"/>
    <date year="2025"/>
  </front>
</reference>

# Design Rationale {#design-rationale}

This appendix is non-normative. It records the rationale behind selected design choices made in this document.

## Device Public Key Limb Encoding

The `ecdsa-p256-limb4-64` layout (see (#device-binding-header)) splits each P-256 coordinate into four 64-bit little-endian limbs encoded as separate BBS messages, rather than carrying each coordinate as a single multi-precision integer or a hash. This decision is driven by the device-binding sub-proof: the sub-proof's zero-knowledge proof must reconstruct the device public key from the message vector to verify the embedded ECDSA signature. The 64-bit-limb representation is chosen to optimize performance of that sub-proof.

# Acknowledgments

The technical foundation for this document is the work captured in [@TS14] by the EUDI Wallet expert group. The committed-message core proof builds on [@!I-D.irtf-cfrg-bbs-blind-signatures], and the modular committed-disclosure framework follows [@LSZ25].

# Document History

[[ pre Working Group Adoption: ]]

-00

* Initial Version
