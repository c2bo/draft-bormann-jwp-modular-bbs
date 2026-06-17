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

This document specifies a digital credential format that combines JSON Web Proofs (JWP) as a container format with the Blind BBS signature scheme and a modular sub-proof framework supporting committed disclosure. It re-uses the existing credential data model of SD-JWT Verifiable Credentials (SD-JWT VC) and aims to keep some level of compatibility with existing deployments.

The format supports selective disclosure of signed attributes, predicate sub-proofs (such as range, equality, and set-membership proofs) over undisclosed attributes, and optional device binding through a sub-proof of knowledge of an ECDSA P-256 signature under a device public key embedded in the BBS messages.

{mainmatter}

# Introduction {#introduction}

The BBS signature scheme as defined in [@!I-D.irtf-cfrg-bbs-signatures] is a multi-message signature (MMS) scheme: the signer produces a single signature over a vector of messages (m_0, ..., m_{n-1}) and a holder of the signature can prove, in zero knowledge, knowledge of a valid signature while disclosing only a subset of the messages.

The Blind BBS Signatures extension [@!I-D.irtf-cfrg-bbs-blind-signatures] extends this scheme with Pedersen commitments to messages and defines blind signing and proof operations over them. This document uses the committed-message proof generation of that extension (`CoreProofGen` of [@!I-D.irtf-cfrg-bbs-blind-signatures]): at proof time the Holder marks each message as disclosed, hidden, or committed, and the resulting proof carries fresh Pedersen commitments to the committed messages so that those commitments can be reused as inputs to further proofs.

This document defines a digital credential format that:

- Uses JSON Web Proofs [@!I-D.ietf-jose-json-web-proof] as the container format for both issuance and presentation, with a new JSON Proof Algorithm [@!I-D.ietf-jose-json-proof-algorithms] profile based on Blind BBS.
- Uses the committed-message proof generation of [@!I-D.irtf-cfrg-bbs-blind-signatures] as the core proof, so that fresh Pedersen commitments to undisclosed messages are carried within the core proof and used as inputs to sub-proofs.
- Defines a sub-proof container that contains zero or more sub-proofs (e.g., range proofs, equality proofs, set-membership proofs) that are attached to the core proof via commitments
- Optionally supports device binding to an ECDSA P-256 key by encoding the device public key into eight messages of the BBS signature vector (using a public key limb decomposition)

The design is informed by the modular architecture for MMS-based ZKP credentials proposed in [@TS14] and [@LSZ25], and re-uses the core data-model elements (like credential types, type metadata, claim metadata) from SD-JWT VC [@!I-D.ietf-oauth-sd-jwt-vc].

## Requirements Notation and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [@!RFC2119] [@!RFC8174]
when, and only when, they appear in all capitals, as shown here.

## Terms and Definitions

This document uses the Issuer-Holder-Verifier model and terminology as defined in Section 1 of [@!I-D.ietf-oauth-sd-jwt-vc].

Additional terminology used is:

BBS:
: The BBS signature scheme as specified in [@!I-D.irtf-cfrg-bbs-signatures].

Core proof:
: The zero-knowledge proof that establishes knowledge of a blind BBS signature on a message vector, with selective disclosure of a subset of messages and committed disclosure of others.

Sub-proof:
: A zero-knowledge proof, distinct from the core proof, that proves a predicate over a message committed in the core proof.
  Examples include range proofs, equality proofs, set-membership proofs, and the ECDSA device-binding proof defined in this document.

Committed disclosure:
: The disclosure of a commitment that corresponds to a signed message of the message vector.

Device binding:
: A cryptographic mechanism that ties a credential presentation to possession of a private key held by the Holder, by requiring a fresh proof of possession of that key for every presentation.

# Data Model

This section specifies the credential and presentation data model.

## Issued Credential {#issued-credential}

A credential is issued in the Issued Form (Section 6.1 of [@!I-D.ietf-jose-json-web-proof]) consisting of:

1. An Issuer Header as defined in (Section 6.1.1 of [@!I-D.ietf-jose-json-web-proof])
1. n Issuer Payloads as defined in (Section 6.1.2 of [@!I-D.ietf-jose-json-web-proof]).
  The payload at position i (0 <= i < n) is the octet encoding of the credential attribute value at index i, as specified in (#message-derivation).
1. An Issuer Proof (Section 6.1.3 of [@!I-D.ietf-jose-json-web-proof]) consisting of a single octet string carrying the blind BBS signature computed over `header_octets` (as the BBS `header` input) and the prepared scalar message vector `(m_0, ..., m_{n-1})` (see (#message-derivation), (#device-binding-header)).

`header_octets` denotes the octet string carrying the Issuer Header as transmitted: the octets obtained by base64url-decoding the Issuer Header component of the Compact Serialization. Issuers, Holders, and Verifiers MUST use the octets as received and MUST NOT re-encode the header.

The Issued Form is serialized using the Compact Serialization defined in (Section 7.1 of [@!I-D.ietf-jose-json-web-proof]). Serialization of this profile under the CBOR Serialization (Section 7.2 of [@!I-D.ietf-jose-json-web-proof]) is (currently) out of scope.

## Issuer Header {#issuer-header}

The Issuer Header is a JWP Issuer Header as defined in (Section 6.1.1 of [@!I-D.ietf-jose-json-web-proof]) represented as a JSON object with the following Header Parameters.

`alg` (REQUIRED):
: The Algorithm Header Parameter as defined in Section 5.2.1 of [@!I-D.ietf-jose-json-web-proof].
  This document defines the JPA value `BBS-MOD` (see (#cipher-suite)), which corresponds to a cipher suite identifier `BBS-MOD_BLS12381G1_XMD:SHA-256_SSWU_RO_BLIND_H2G_HM2S_`.

`vct` (string, REQUIRED):
: The credential type identifier as defined in Section 3.2.2.1 of [@!I-D.ietf-oauth-sd-jwt-vc].
  The associated type metadata applies to this credential format.

`claims` (JSON object, REQUIRED):
: A mapping from credential attribute names / claim names to their position in the message vector and whether each is hashed to a scalar or supplied directly as a scalar; see (#claims-mapping).

`kb` (string, OPTIONAL):
: The device-binding identifier specifying both the device public key type and its encoding into the BBS messages; see (#device-binding-header).
  When absent, the credential is not device-bound and presentations of this credential MUST NOT include a key binding proof.

Temporal validity claims such as `exp`, `nbf`, `iat` MUST NOT appear as values in the Issuer Header. When present in a credential, they are carried as messages in the message vector and referenced via the `claims` Header Parameter - see (#temporal-claims).

The JWP `iek` (Issuer Ephemeral Key), `hpk` (Holder Presentation Key), and `hpa` (Holder Presentation Algorithm) Header Parameters (Sections 5.2.5–5.2.7 of [@!I-D.ietf-jose-json-web-proof]) are not used by this profile.

## Claims Mapping {#claims-mapping}

The `claims` Header Parameter of the Issuer Header is a JSON object that mirrors the credential's attribute tree structurally. Leaf positions in the tree are replaced by an index annotation.

An index annotation is a JSON array of exactly two elements:

- element 0: a non-negative integer `i` giving the 0-based index in the payload vector of the leaf value.
- element 1: a boolean `scalar`. When `scalar` is `false`, the leaf value is first encoded to an octet string and then mapped to a scalar via the hash-to-scalar primitive of the cipher suite (see (#message-derivation)).
  When `scalar` is `true`, the leaf value MUST itself be a scalar in the BBS scalar field and is used directly as the message - see (#scalar-encoding) for more details.

Let `N` be the number of payload slots reserved for the device-key encoding as determined by the `kb` Header Parameter (see (#device-binding-header)), or 0 when `kb` is absent. Let `n` be the length of the message vector.
Every index in the closed range `[N, n-1]` (i.e., every index that is not part of the device-key encoding) MUST appear in exactly one annotation in `claims`.
Where the credential type permits optional attributes, the corresponding payload slot MUST be filled with a decoy message (see (#decoys)). Similarly, arrays SHOULD contain decoy messages to avoid fingerprinting based on the number of array elements.

When a `kb` Header Parameter is present, the indices reserved for device-key encoding (indices 0 through `N - 1`) MUST NOT appear in `claims`.

## Example: Issuance {#example-issuer-header}

The examples in this and the following sections are non-normative.

The Issuer starts from an SD-JWT VC style claim set [@!I-D.ietf-oauth-sd-jwt-vc]. This example uses the attributes of the example identity credential of that document:

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

The `vct` value becomes the `vct` Header Parameter and every other attribute becomes a leaf in the `claims` Header Parameter, with the nested `address` object mirrored per (#layout). No device binding is used (`kb` is absent), so `N = 0` and the fourteen claims occupy indices 0 through 13. Following (#temporal-claims), the `iat` and `exp` temporal claims are not Header Parameters but `claims` leaves carried as NumericDate scalars (`scalar` = true), so that a Verifier can create sub-proofs over them. The resulting Issuer Header is:

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

The claims at indices 0 through 11 use `scalar` = false: their values are mapped to BBS messages via hash-to-scalar (see (#message-derivation)). The temporal claims `iat` and `exp` (indices 12 and 13) use `scalar` = true: they are NumericDate integers as defined in [@!RFC7519] (no fractional component) used directly as scalars (see (#scalar-encoding)), which makes them valid range-proof targets. A presentation may then mark `iat` and/or `exp` as `COMMIT` (see (#core-proof)) and attach one or two `bp-range` sub-proofs (see (#range-proof)) to establish that the credential is currently valid without disclosing the timestamps themselves.

For a real-world deployment, the credential type would fix a structural layout covering every optional attribute and every maximum-length array slot, with absent slots filled by decoys (see (#decoys)).

## Message Derivation {#message-derivation}

For an annotation `[i, false]` with leaf value `v`:

1. Let `o` be the octet encoding of `v` that the Issuer carries as Issuer Payload i. This profile does not mandate a specific encoding of `v` to octets (for example, the UTF-8 octets of a string value) and the raw received payload values must be used by the Holder during presentation.
1. Compute m_i = `hash_to_scalar(o, map_dst)` where `hash_to_scalar` is the BBS primitive of (#cipher-suite) and `map_dst = api_id || "MAP_MSG_TO_SCALAR_AS_HASH_"`, with `api_id` the Interface identifier of this profile defined in (#cipher-suite). This matches the per-message derivation that `BBS.messages_to_scalars` (Section 4.1.2 of [@!I-D.irtf-cfrg-bbs-signatures]) would apply to `o`.

For an annotation `[i, true]` with leaf value `v` (a JSON integer per (#scalar-encoding)):

1. Let `o` be the canonical decimal octet encoding of `v` per (#scalar-encoding), which the Issuer carries as Issuer Payload i.
1. Set m_i to the integer denoted by `o`, interpreted as an element of the BBS scalar field.

## Scalar Encoding {#scalar-encoding}

A leaf with `scalar` = true MUST be a JSON number whose value is an integer in the range [0, r - 1], where r is the order of the BBS scalar field. Implementations MUST reject leaves with `scalar` = true that are not JSON integers or whose value lies outside of the allowed range.

The Issuer Payload for such a value is the aforementioned JSON number itself.

Future extensions MAY define additional scalar encodings (e.g., for fixed-point or string-keyed enumerations) provided that the encoding deterministically maps a JSON value to an element of [0, r - 1].

## Temporal Claims {#temporal-claims}

The JWT temporal claims `exp`, `nbf`, and `iat` (Section 4.1 of [@!RFC7519]) MUST NOT appear in the Issuer Header as values.
When a credential type uses any of these claims, the corresponding NumericDate values MUST be carried as scalar messages in the message vector.
Each such claim is declared as a leaf in `claims` (see (#claims-mapping)) with `scalar` = true and contributes one payload slot.

## Device Binding Header {#device-binding-header}

When present, the `kb` Header Parameter of the Issuer Header is a string identifier specifying both the type of device public key used for device binding and how it is embedded in the BBS messages. This document defines the single value `ecdsa-p256-limb4-64` (the NIST P-256 curve, encoded as four 64-bit little-endian limbs per coordinate as defined below).

Note: the `kb` parameter defined here identifies a *public-key encoding layout* for embedding into the BBS message vector. It is distinct from the SD-JWT "Key Binding JWT" mechanism (Section 4.3 of [@RFC9901]).
The Holder proof of possession is conveyed by a sub-proof, not by a separate JWT. The choice of 4 64 bit limbs is a performance optimization to make the required public key reconstruction easier in the sub-proof.

The value of `kb` fixes both the number of payload slots reserved for the device public key and their position: the reserved slots are the first N indices of the payload vector, i.e., indices 0 through N-1. Attribute messages declared in `claims` occupy indices N and above.

For `kb = "ecdsa-p256-limb4-64"`, N = 8 and the layout used to encode the P-256 public key is:

- m_0, m_1, m_2, m_3 encode the x-coordinate of the device public key as four 64-bit limbs, with m_0 the least significant 64 bits.
- m_4, m_5, m_6, m_7 encode the y-coordinate of the device public key in the same way.

Each limb is treated as a scalar in [0, 2^64) and signed with the hash-to-scalar step bypassed (as if `scalar` = true). Each limb is the canonical decimal octet encoding (see (#scalar-encoding)).

The Issuer MUST verify, before computing the message vector, that the device public key `(x, y)` is a valid point on P-256 [@!FIPS186-5]: both `x` and `y` MUST be integers in [0, p - 1] where p is the P-256 base field prime, `(x, y)` MUST satisfy the P-256 curve equation, and `(x, y)` MUST NOT be the point at infinity.

## Structural Layout {#layout}

For claims that are JSON objects, `claims` mirrors the object structure unless the whole object should be encoded and disclosed in one message - in that case the whole object is JSON encoded and treated as a leaf in the structure.

For claims that are JSON arrays of bounded length, `claims` contains a JSON array of index annotations of the maximum length supported by the credential type. All index annotations of such an array SHOULD share the same `scalar` flag, so that every payload slot of the array uses the same encoding and the same decoy octets (see (#decoys)). Array entries beyond the actual array length present in the issued credential SHOULD be filled with decoys.

For claims that are optional (per the credential type's metadata), `claims` MUST contain an entry, and the corresponding payload slot MUST be filled with a decoy when the attribute is absent.

## Decoys {#decoys}

A decoy message is a payload slot that is reserved by the credential type's fixed structural layout but not in use for a specific issued credential.
Decoy values MUST be supplied for all optional claims that are not being populated for a specific credential, and arrays SHOULD be padded with decoys to the maximum length declared by the credential type, so that the message-vector length and the `claims` structure do not vary with the specific credential contents.

The purpose of decoys is to ensure that the Issuer Header and allocation of indices in the message vector is identical across the entire population of credentials of a given type, so that header disclosure does not narrow the anonymity set (see (#anonymity)).

Every decoy slot in every credential MUST carry the same fixed scalar, derived once per cipher suite:

~~~
m_decoy = hash_to_scalar("JWP-BBS-DECOY", map_dst)
~~~

where `hash_to_scalar` and `map_dst` are as defined in (#message-derivation) and `"JWP-BBS-DECOY"` is the literal ASCII string.

The Issuer Payload carried for a decoy slot depends on the `scalar` flag of that slot's `claims` annotation (see (#claims-mapping)), so that the same scalar `m_decoy` is recovered through (#message-derivation) in both cases:

- For a slot with `scalar = false`, the Issuer Payload MUST be the 13 ASCII octets of `"JWP-BBS-DECOY"`. The Holder recovers m_decoy by applying the `scalar = false` step of (#message-derivation), i.e., `hash_to_scalar` over those octets with the same `map_dst` as above.
- For a slot with `scalar = true`, the Issuer Payload MUST be the canonical decimal octet encoding (per (#scalar-encoding)) of the integer m_decoy. The Holder recovers m_decoy by applying the `scalar = true` step of (#message-derivation).

Both encodings are fixed per cipher suite: the `scalar = false` decoy octets are the literal `"JWP-BBS-DECOY"` and are independent of the cipher suite, while the `scalar = true` decoy octets depend on the cipher suite via `m_decoy` and the order of its scalar field, and are computed once for the cipher suite identified by `alg`.

A Verifier detects a disclosed decoy by byte-comparing the disclosed Presentation Payload to the precomputed decoy octets for the cipher suite of `alg` and the slot's `scalar` flag.

This allows for detection of decoy payloads in cases where the presentation of a decoy value is necessary, e.g., a proof over all array members. Decoys SHOULD NOT be revealed unless explicitly required by the use-case.

# Issuance

## Issuer Key Generation

The Issuer key pair is a BBS key pair as specified in Section 3.4 of [@!I-D.irtf-cfrg-bbs-signatures], using the cipher suite of (#cipher-suite).

## Credential Issuance

To issue a credential:

1. Construct the Issuer Header per (#issuer-header) and (#claims-mapping).
1. Derive the message vector (m_0, ..., m_{n-1}) per (#message-derivation) and (#device-binding-header). Fill decoys per (#decoys).
1. Compute the blind BBS signature over `header_octets` (as defined in (#issued-credential)) and the prepared scalar message vector `(m_0, ..., m_{n-1})`.
1. Assemble the Issued Form (Section 6.1 of [@!I-D.ietf-jose-json-web-proof]) with the Issuer Header from step 1, n Issuer Payloads carrying (m_0, ..., m_{n-1}) in order, and an Issuer Proof equal to the blind BBS signature octets. Serialize per (#issued-credential).

The following is a non-normative example of an issued Credential in compact form:

~~~
<base64url(Issuer Header)>
.
<m_0>~<m_1>~ ... ~<m_13>
.
<base64url(blind BBS signature)>
~~~

Each `<m_i>` is the base64url-encoded Issuer Payload for index `i`: for `scalar` = false leaves, the octets of the attribute value (e.g., m_1 is the octets of "Mustermann"); for `scalar` = true leaves, the canonical decimal octets of the integer (e.g., m_13 is the octets `1786000000`).

## Holder Verification

Upon receiving an issued credential, the Holder verifies by:

1. Parsing the Issued Form into the Issuer Header, Issuer Payloads, and Issuer Proof
1. Verifying the blind BBS signature over `header_octets` and the prepared scalar message vector `(m_0, ..., m_{n-1})`. If verification fails, the credential MUST be rejected.
1. For every claim declared with `scalar` = true in `claims` (see (#claims-mapping)), re-parsing the corresponding Issuer Payload per (#scalar-encoding) and rejecting the credential if the recovered integer is not in `[0, r - 1]`.
1. If `kb` is present, the Holder repeats the P-256 validation of (#device-binding-header) on the point reconstructed from the limb messages, and rejects the credential if the validation fails or if the reconstructed point does not match the device public key the Holder controls. How the Holder obtains the corresponding device key pair (e.g., as part of an issuance request prior to receiving the credential) is out of scope of this profile.

# Presentation

## Presented Form {#presented-form}

A presentation is a Presented Form as defined in (Section 6.2 of [@!I-D.ietf-jose-json-web-proof]) consisting of:

1. A Presentation Header as defined in (Section 6.2.1 of [@!I-D.ietf-jose-json-web-proof]) with the concrete structure being specified in (#presentation-header).
1. The Issuer Header from issuance, presented as the same Header Parameter set with identical values. The core proof is bound to `header_octets` as defined in (#issued-credential); Verifiers obtain `header_octets` from the received Issuer Header component, using the octets as received.
1. n Presentation Payloads (Section 6.2.2 of [@!I-D.ietf-jose-json-web-proof]). Disclosed positions carry the corresponding Issuer Payload octet string and undisclosed positions MUST be omitted as defined by the Compact Serialization (Section 7.1 of [@!I-D.ietf-jose-json-web-proof]).
1. A Presentation Proof (Section 6.2.4 of [@!I-D.ietf-jose-json-web-proof]) consisting of one or more octet strings. The first octet string is the encoded core proof (see (#core-proof)). Each subsequent octet string, if present, is the UTF-8 encoding of a JSON-serialized sub-proof object (see (#sub-proofs)), in any order. The Compact Serialization base64url-encodes each octet string of the Presentation Proof for transmission.

## Presentation Header {#presentation-header}

The Presentation Header is a JWP Presentation Header (Section 6.2.1 of [@!I-D.ietf-jose-json-web-proof]) represented as a JSON object. It MUST contain the following Header Parameters:

`nonce` (REQUIRED):
: The Nonce Header Parameter as defined in Section 5.2.10 of [@!I-D.ietf-jose-json-web-proof].

`aud` (REQUIRED):
: The Audience Header Parameter as defined in Section 5.2.9 of [@!I-D.ietf-jose-json-web-proof].

`presentation_header_octets` denotes the octet string carrying the Presentation Header as transmitted: the octets obtained by base64url-decoding the Presentation Header component of the Compact Serialization. It MUST be bound into the core proof challenge (see (#core-proof)). Verifiers MUST use the octets as received and MUST NOT re-encode the header.

## Core Proof {#core-proof}

The Holder generates the core proof by invoking `CoreProofGen`. At the profile level, the Holder first builds a per-message disclosure map that assigns each index `i` in `[N, n-1]` (with `N` as defined in (#claims-mapping)) one of `DISCLOSE`, `HIDE`, or `COMMIT`, subject to the following constraints:

- The indices assigned `DISCLOSE` MUST be a subset of `[N, n-1]` (i.e., MUST NOT include any device-key indices, see (#device-binding-header)) and their values match the disclosed Presentation Payloads.
- The indices assigned `COMMIT` MUST include every index referenced by any sub-proof attached to this presentation (see (#sub-proofs)). For each such index the proof carries a fresh Pedersen commitment to the corresponding message, together with its proof of correctness and its index, using the commitment generators fixed in (#cipher-suite).
- All remaining indices MUST be assigned `HIDE`.

This map is translated into the `CoreProofGen` inputs as follows: `disclosed_indexes` is the set of indices marked `DISCLOSE`, `commits_indexes` is the set of indices marked `COMMIT`, and indices marked `HIDE` appear in neither set. The full set of `CoreProofGen` inputs is:

- `PK`: the Issuer public key.
- `signature`: the blind BBS signature recovered from the Issuer Proof of the issued credential.
- `header`: `header_octets` as defined in (#issued-credential).
- `ph`: `presentation_header_octets` (see (#presentation-header)), bound into the proof challenge so that the proof is non-malleable with respect to `nonce` and `aud`.
- `messages`: the full message vector `(m_0, ..., m_{n-1})`.
- `disclosed_indexes`: the indices marked `DISCLOSE` in the disclosure map above.
- `commits_indexes`: the indices marked `COMMIT` in the disclosure map above.

The core proof establishes that:

- The Holder knows a blind BBS signature under the Issuer's public key on a message vector whose values at the disclosed indices match the disclosed Presentation Payloads.
- For every committed index `i`, the commitment carried in the proof for `i` is a Pedersen commitment to the message at index `i` of the same message vector.

The Verifier verifies the core proof by invoking `CoreProofVerify` of [@!I-D.irtf-cfrg-bbs-blind-signatures], passing `PK`, the core proof, the generator set, `header_octets`, `presentation_header_octets`, and the disclosed scalar messages recovered from the disclosed Presentation Payloads per (#message-derivation), obtaining `header_octets` from the received Issuer Header and `presentation_header_octets` from the received Presentation Header, using the octets as received. On success, the Verifier recovers from the proof the committed indices and their Pedersen commitments, which are the inputs to the sub-proofs (see (#sub-proofs)).

## Sub-Proofs {#sub-proofs}

A sub-proof is a JSON object with the following members. Each sub-proof appears as an additional octet string in the Presentation Proof (see (#presented-form)), carrying the UTF-8 encoding of that JSON object.

`alg` (string, REQUIRED):
: The sub-proof algorithm identifier registered in the Sub-Proof Algorithms registry (see (#iana)).

`input` (JSON object, REQUIRED):
: Public inputs to the sub-proof. The input MUST include:

- `i`: A non-empty JSON array of non-negative integers, giving the message-vector index (or indices) to which this sub-proof is bound. Every value MUST be a committed index of the core proof (i.e., a message marked `COMMIT` - see (#core-proof)), so that the core proof carries a commitment for it. Each sub-proof algorithm fixes the required length of `i` and the role of each entry.

  Additional members are defined per sub-proof type.

`proof` (string, REQUIRED):
: The base64url [@!RFC4648] encoding of the sub-proof bytes, as specified by `alg`.

The Verifier MUST run the following validation steps for each sub-proof:

1. For every index value in `i`, confirm that it appears among the committed indices recovered from the verified core proof.
1. Obtain the commitment(s) for those indices from the verified core proof and pass them, together with the sub-proof's additional inputs and `proof`, to the verification routine defined for `alg`.

A presentation that includes a sub-proof whose `i` references an index for which the core proof carries no commitment MUST be rejected.

Sub-proof freshness is inherited from the core proof: for every committed index, the `CoreProofGen` operation of (#core-proof) MUST produce a freshly randomized Pedersen commitment `C_i` (with an independent blinding scalar `gamma` sampled per presentation), and the core proof's challenge MUST bind to `presentation_header_octets`.

Algorithms whose proof object does not bind to `C_i` (for example, `ecdsa-p256-db`, which creates a proof of knowledge over an ECDSA signature) MUST establish freshness another way. The `ecdsa-p256-db` sub-proof does so by signing `db_msg` (see (#ecdsa-db)).

### ECDSA Device-Binding Sub-Proof {#ecdsa-db}

This sub-proof MUST be present for any presentation of a device-bound credential where `kb = "ecdsa-p256-limb4-64"` in the Issuer Header, and MUST NOT be present otherwise.

Algorithm identifier:
: `ecdsa-p256-db`

Inputs:

None - This sub-proof always uses the first 8 messages in the message vector to convey the public key information, hence no explicit input is required.

The message signed by the device under `dpk` is not transmitted in the sub-proof object. It is fixed as the concatenation:

~~~
db_msg = "JWP-BBS-DB-CHAL" || presentation_header_octets
~~~

where `"JWP-BBS-DB-CHAL"` is the literal ASCII string (15 octets) and `presentation_header_octets` is defined in (#presentation-header). The device signs `db_msg` with standard ECDSA-P256 (the ECDSA signing operation hashes `db_msg` with SHA-256 internally); implementations MUST pass `db_msg` to the ECDSA signing/verification routine as the message input, not as a pre-computed digest. Holders and Verifiers MUST compute `db_msg` from the Presentation Header rather than accepting it as an input.

Binding `db_msg` to `presentation_header_octets` is sufficient for freshness: that octet string carries both the Verifier-supplied `nonce` and the target `aud` (see (#presentation-header)), so the same device signature cannot be replayed against a different Verifier or in a different protocol run. This is the same binding the core proof's challenge uses, so the ECDSA sub-proof and the core proof are bound to the same presentation context.

The proof bytes encode a non-interactive zero-knowledge proof of knowledge of `(dpk, (r, s))` such that:

1. The 8 commitments obtained from the core proof at the indices in `i` are Pedersen commitments (under the commitment generators `(G, H)` of (#cipher-suite)) to the 64-bit little-endian limbs of the x- and y-coordinates of `dpk`, in the layout fixed by `kb`.
2. `(r, s)` is a valid ECDSA P-256 signature on `db_msg` under `dpk`.

\[Editor's Note: TODO - select and describe concrete mechanism]

The Verifier accepts the sub-proof if and only if:

1. The 8 indices in `i` all appear among the committed indices recovered from the verified core proof.
2. The proof verifies, as a proof of the statement above against the 8 commitments obtained from the core proof and the locally recomputed `db_msg`, under the parameters of the concrete construction once specified.

### Range Proof Sub-Proof {#range-proof}

Algorithm identifier:
: `bp-range` (Bulletproofs over Pedersen commitments [@!BBBP18])

Inputs (in addition to the base sub-proof fields of (#sub-proofs)): the lower bound `l` and upper bound `u` (both JSON integers) and the encoded Bulletproof in the `proof` field. The `i` field MUST be a single-element JSON array `[idx]` naming the message-vector index `idx` whose committed value is range-checked.
The sub-proof attests that the message m_idx committed by the core proof for index `idx` (see (#core-proof)) satisfies `l <= m_idx < u`, taking as its input the Pedersen commitment `C_idx` to m_idx carried by the core proof.

The bounds MUST satisfy `l < u`, and implementations MUST reject `bp-range` sub-proofs whose width exceeds `u - l <= 2^64` unless a deployment profile explicitly permits a larger width. The `2^64` bound matches the natural Bulletproofs range for a single 64-bit limb decomposition and accommodates NumericDate temporal claims (Section 4.1 of [@!RFC7519]), whose maximum value is `2^63 - 1`. Both `l` and `u` are arbitrary-precision JSON integers; implementations MUST parse them as bigints rather than as IEEE-754 doubles.

The construction operates in G1 of BLS12-381 using the same commitment generators `(G, H)` as the core proof (see (#cipher-suite)), so the commitment carried by the core proof can be used directly as the Bulletproof input. Any additional generators, the transcript hash, and the Fiat-Shamir domain separation are derived from the cipher-suite identifier and are pinned by the concrete construction.

\[Editor's Note: TODO - select and describe concrete construction]

### Equality Proof Sub-Proof {#equality-proof}

Algorithm identifier:
: `schnorr-eq`

Inputs (in addition to the base sub-proof fields of (#sub-proofs)): the `i` field, which MUST be a single-element JSON array `[idx]` naming the message-vector index `idx` whose committed value is compared, and an external commitment `c_ext` (a base64url-encoded BLS12-381 G1 point).
The sub-proof attests that the commitment `C_idx` carried by the core proof for index `idx` and the external commitment `c_ext` are Pedersen commitments to the same scalar, under the same generators `(G, H)` of (#cipher-suite).


It uses the `pedersen_commitment_dleq` statement of [@!I-D.irtf-cfrg-sigma-protocols] (Appendix A.5), realized as a proof of knowledge of the preimage of a linear map and made non-interactive with the Fiat-Shamir transform of [@!I-D.irtf-cfrg-fiat-shamir]. The `proof` field carries the resulting serialized sigma-protocol proof.

This algorithm identifier is defined only for the case where `c_ext` is in the same group, and uses the same generators, as the core proof's Pedersen commitments. Cross-group equality (e.g., between a BLS12-381 G1 commitment and a commitment over a different elliptic curve) is out of scope.

The construction operates in G1 of BLS12-381 using the commitment generators `(G, H)` of (#cipher-suite) for both `C_idx` and `c_ext`, with `presentation_header_octets` (see (#sub-proofs)) absorbed into the Fiat-Shamir transcript. The protocol and instance identifiers (Sections 5 and 6 of [@!I-D.irtf-cfrg-sigma-protocols]) and any further domain separation are pinned by the concrete construction.

\[Editor's Note: TODO - pin protocol / instance identifiers and serialization]

The freshness of `C_idx` (see (#sub-proofs)) prevents replay of a stale `(C_idx, c_ext)` pair. Replay of a stale `c_ext` against a freshly committed `C_idx` is prevented only by the deployment's own binding of `c_ext` to the presentation context; Verifiers MUST therefore ensure that `c_ext` is associated with the current presentation (e.g., generated freshly per presentation, or delivered under a Verifier-supplied challenge bound to the presentation).

## Example Presentation {#example-presentation}

Continuing the example of (#example-issuer-header), a Verifier requests `family_name` and asks the Holder to prove the credential is unexpired without revealing `exp`. The Verifier supplies a fresh `nonce` and its own identifier as `aud`, which the Holder echoes in the Presentation Header:

~~~ json
{
  "nonce": "f4Oa3wT0r8m2Vn1pQ7sKdA",
  "aud": "https://verifier.example.com"
}
~~~

The Holder generates the core proof (see (#core-proof)) with this per-message disclosure map: index 1 (`family_name`) is `DISCLOSE`, index 13 (`exp`) is `COMMIT`, and all other indices are `HIDE`. The core proof therefore carries a fresh Pedersen commitment to m_13. The Holder attaches one `bp-range` sub-proof (see (#range-proof)) over index 13, proving `now <= exp < 2^63` for the Verifier-supplied current time `now` = 1779926400:

~~~ json
{
  "alg": "bp-range",
  "input": { "i": [13], "l": 1779926400, "u": 9223372036854775808 },
  "proof": "..."
}
~~~

In the Compact Serialization (Section 7.1 of [@!I-D.ietf-jose-json-web-proof]), the Presented Form concatenates, separated by `.`: the base64url-encoded Presentation Header, the base64url-encoded Issuer Header, the Presentation Payloads, and the Presentation Proof. Only the `family_name` payload (index 1) is disclosed; the other thirteen slots are omitted (empty), leaving a run of `~` separators with the single disclosed value in position 1. The Presentation Proof is the core proof followed by the sub-proof object, joined with `~`:

~~~
<base64url(Presentation Header)>
.
<base64url(Issuer Header)>
.
~TXVzdGVybWFubg~~~~~~~~~~~~
.
<core proof>~<bp-range sub-proof>
~~~

The Verifier verifies the core proof, recovers the commitment to m_13, recomputes `now` and the bounds, and checks the `bp-range` sub-proof against that commitment (see (#sub-proofs)). It learns `family_name` and that the credential is unexpired, but nothing else about the Holder's attributes, `iat`, or `exp`.

## Reconstructed JSON Payload {#reconstructed-payload}

After successfully verifying the core proof (see (#core-proof)) and any sub-proofs (see (#sub-proofs)), the Verifier MAY hand the application a JSON object reconstructed from the disclosed information, analogous to the Processed SD-JWT Payload of [@RFC9901].

The reconstructed payload is built as follows:

1. Start from an empty JSON object and add the `vct` from the Issuer Header.
1. Walk the `claims` Header Parameter (see (#claims-mapping)). For each leaf at index `i`:
    - If `i` is among the disclosed indices recovered from the verified core proof:
        - If the disclosed Presentation Payload at index `i` is byte-equal to the fixed decoy octets defined for the leaf's `scalar` flag (see (#decoys)), omit the leaf from the reconstructed object.
        - Otherwise, set the leaf's value in the reconstructed object to the value decoded from the corresponding Presentation Payload (per (#message-derivation)).
    - Otherwise, omit the leaf from the reconstructed object.
1. Preserve the nested object and array structure of the `claims` Header Parameter for the leaves that remain. For an array attribute, the reconstructed payload contains only the surviving entries, in the same relative order as their corresponding `claims` annotations; omitted entries are not represented, so reconstructed array indices do not in general match the index annotations of `claims`.

The reconstructed payload omits attributes that were hidden or committed but not disclosed; the Verifier MUST NOT infer values for these from outside the proof. Predicates established by sub-proofs over committed indices are not represented as concrete leaf values in this payload.

For the example of (#example-presentation), in which only `family_name` is disclosed, the reconstructed JSON Payload is:

~~~ json
{
  "vct": "https://credentials.example.com/identity_credential",
  "family_name": "Mustermann"
}
~~~

# Cipher Suite {#cipher-suite}

This document defines a single JPA cipher suite.

## Identifier

The JPA Algorithm JSON Label is:

~~~
BBS-MOD
~~~

denoting the cipher suite identifier:

~~~
BBS-MOD_BLS12381G1_XMD:SHA-256_SSWU_RO_BLIND_H2G_HM2S_
~~~

`BBS-MOD` is the JPA value carried in the `alg` Header Parameter (Section 5.2.1 of [@!I-D.ietf-jose-json-web-proof]) of the Issuer Header. The cipher suite identifier above is used internally as the BBS Interface identifier (the `api_id` for hash-to-scalar and generator derivation), and as the root of the domain separation tags consumed by sub-proofs (see (#sub-proofs)).

The cipher suite is distinct from:

- the base BBS JPA identifier (`BBS` in Section 9.1.2.4 of [@!I-D.ietf-jose-json-proof-algorithms], corresponding to the BBS cipher suite identifier `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_`), because this profile uses the blind BBS Interface of [@!I-D.irtf-cfrg-bbs-blind-signatures] rather than the base BBS Interface; and
- the base blind BBS Interface identifier `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_BLIND_H2G_HM2S_`, because this profile uses a profile-specific Interface identifier (with the `BBS-MOD_` prefix) so that BBS-layer hash-to-scalar and generator derivation are domain-separated from any other use of the blind BBS Interface under the same key.

The `BBS-MOD` algorithm signals that this profile uses the committed-message proof generation of [@!I-D.irtf-cfrg-bbs-blind-signatures] at presentation time, exposes per-message hash-to-scalar bypass via the `scalar` flag in `claims`, and reserves the sub-proof attachment mechanism of (#sub-proofs).

## Parameters

- Signature scheme: this profile invokes the *core* operations of the blind BBS Interface of [@!I-D.irtf-cfrg-bbs-blind-signatures] directly, rather than the `BlindSign`/`VerifyBlindSign` entry points, so that the per-leaf `scalar` flag of (#claims-mapping) is honored. The blind BBS Interface is instantiated over the base BBS ciphersuite `BLS12-381-SHA-256` (Section 7.2.2 of [@!I-D.irtf-cfrg-bbs-signatures]), whose ciphersuite identifier is `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_`. The Interface identifier used by this profile (the `api_id` for hash-to-scalar, generator derivation, and domain-separation tags) is the cipher suite identifier defined above, `BBS-MOD_BLS12381G1_XMD:SHA-256_SSWU_RO_BLIND_H2G_HM2S_`; the `BBS-MOD_` prefix domain-separates this profile from the base blind BBS Interface at the BBS layer.
- Elliptic curve: BLS12-381, G1 subgroup.
- Hash-to-curve: SHA-256 SSWU random oracle as in [@!RFC9380], with the cipher-suite-specific domain separation tag derived from the Interface identifier above.
- Hash-to-scalar: as defined for the BBS cipher suite, with domain separation tag derived from the Interface identifier above.
- Core proof: this profile invokes `CoreProofGen` and `CoreProofVerify` of [@!I-D.irtf-cfrg-bbs-blind-signatures] directly, with `commits_indexes` corresponding to the `COMMIT`-marked messages of the per-message disclosure map of (#core-proof). The resulting proof carries fresh Pedersen commitments to those messages, together with their proofs of correctness and their indices. Because `CoreProofGen` is not invoked as a subroutine of `BlindProofGen`, implementations MUST apply the `disclosed_indexes` and `commits_indexes` input validity checks called out in Section 7.1 of [@!I-D.irtf-cfrg-bbs-blind-signatures].
- Pedersen commitment generators: the commitments carried by the core proof for the `COMMIT`-marked indices, and consumed by sub-proofs (e.g., `bp-range` (#range-proof)), use the fixed commitment generator pair `(G, H) = (Y_1, Y_0)`, where `(Y_0, Y_1)` are the fixed points of G1 defined by `CoreProofGen` of [@!I-D.irtf-cfrg-bbs-blind-signatures] as `(Y_0, Y_1) = BBS.create_generators("COM_DIS_" || api_id)`, with `api_id` set to the cipher suite identifier above. For every committed index `i`, the commitment has the form `C_i = m_i * G + s_i * H`, equivalently `C_i = Y_0 * s_i + Y_1 * m_i`, where `s_i` is the per-commitment blinding scalar sampled inside `CoreProofGen`.
- Per-message hash-to-scalar bypass: each message slot's `scalar` flag, as declared in `claims` (see (#claims-mapping)), determines whether the corresponding message is derived via hash-to-scalar (`scalar` = false) or is supplied directly as a scalar (`scalar` = true).

# Security Considerations

## Hash-to-Scalar Bypass

\[Editor's Note: TODO - Check what exactly the attack scenarios are]

# Privacy Considerations

## Issuer Header Correlation {#anonymity}

The Issuer Header is presented in clear to the Verifier as part of the Presented Form (Section 6.2 of [@!I-D.ietf-jose-json-web-proof]). This can create a correlation factor unless the Header does not differ between different credentials of the same type.

Implementations SHOULD construct the Issuer Header so that it is identical across the entire population of credentials of the same `vct`, by:

- Using a fixed layout for `claims` of each credential type, including all optional attributes, all maximum-length array slots, and a constant serialization.
- Filling unused or absent attribute slots with decoys per (#decoys).
- Carrying any per-credential metadata (issuance time, expiry, identifiers) only as messages in the message vector rather than in the Issuer Header.

The byte-identicality requirement applies within a single JWP serialization. The `header_octets` bound by the BBS signature and the core proof are the Issuer Header octets as transmitted in that serialization (see (#issued-credential)), and Verifiers use the octets as received.

## Cipher Suite and Algorithm Identifiers

The `alg` Header Parameter in the Issuer Header narrows the anonymity set whenever it varies across Holders of the same credential type. Implementations SHOULD use a single cipher suite across all Holders of a credential type.

The `kb` Header Parameter has the same effect: presentations of device-bound and non-device-bound credentials of the same `vct` form separate anonymity sets, as do credentials using different `kb` values. Implementations SHOULD use a single `kb` value (or omit `kb` entirely) across the entire population of credentials of a given `vct`, and SHOULD NOT mix device-bound and non-device-bound credentials under the same `vct`.

# IANA Considerations {#iana}

This document requests the following registrations and registry creations.

## JPA `alg` Value

IANA is requested to register the following JSON Proof Algorithm in the "JSON Web Proof Algorithms" registry established by [@!I-D.ietf-jose-json-proof-algorithms]:

- Algorithm Name: BBS-MOD using SHA-256
- Algorithm JSON Label: `BBS-MOD`
- Algorithm CBOR Label: (to be assigned by IANA)
- Algorithm Description: Corresponds to a cipher suite identifier of `BBS-MOD_BLS12381G1_XMD:SHA-256_SSWU_RO_BLIND_H2G_HM2S_`. Uses the blind BBS Interface of [@!I-D.irtf-cfrg-bbs-blind-signatures] and extends the base BBS JPA with its committed-message proof generation, per-message hash-to-scalar bypass via the `scalar` flag, and the sub-proof attachment mechanism of (#sub-proofs).
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
- Header Parameter Description: Device public key encoding identifier for BBS-based device binding. Identifies both the public key type and the layout of its encoding into the BBS message vector.
- Header Parameter Usage Location(s): Issued, Presented
- Change Controller: IETF
- Specification Document(s): (#device-binding-header) of this document.

This document does not register `vct`; its registration is requested by [@!I-D.ietf-oauth-sd-jwt-vc].

## Sub-Proof Algorithms Registry

IANA is requested to create a new registry titled "Sub-Proof Algorithms" with the following structure and policy (TODO).

Allocation policy: Specification Required ([@!RFC8126]). The designated experts SHOULD verify that the specification pins the underlying group, generators, transcript hash, and Fiat-Shamir domain separation, and that the sub-proof is bound to a commitment attested by the core proof per (#sub-proofs).

Registry fields:

- Identifier: a string used as the value of the `alg` member of a sub-proof object (#sub-proofs).
- Description: short description.
- Reference: a stable specification.
- Change Controller.

Initial entries:

- Identifier: `ecdsa-p256-db`
- Description: ECDSA P-256 device-binding sub-proof.
- Reference: This document, (#ecdsa-db).
- Change Controller: IETF.

- Identifier: `bp-range`
- Description: Bulletproofs range proof over a committed scalar message
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

<reference anchor="BBBP18" target="https://doi.org/10.1109/SP.2018.00020">
  <front>
    <title>Bulletproofs: Short Proofs for Confidential Transactions and More</title>
    <author initials="B." surname="Bünz"/>
    <author initials="J." surname="Bootle"/>
    <author initials="D." surname="Boneh"/>
    <author initials="A." surname="Poelstra"/>
    <author initials="P." surname="Wuille"/>
    <author initials="G." surname="Maxwell"/>
    <date year="2018" month="May"/>
  </front>
  <seriesInfo name="DOI" value="10.1109/SP.2018.00020"/>
  <refcontent>Proceedings of the 2018 IEEE Symposium on Security and Privacy (S&amp;P), pp. 315-334. Full version: IACR ePrint 2017/1066, https://eprint.iacr.org/2017/1066.</refcontent>
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

# Acknowledgments

The technical foundation for this document is the work captured in [@TS14] by the EUDI Wallet expert group; the committed-message core proof builds on [@!I-D.irtf-cfrg-bbs-blind-signatures], and the modular committed-disclosure framework follows [@LSZ25].
