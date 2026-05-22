%%%
title = "JSON Web Proofs with BBS and Optional ECDSA Key Binding"
abbrev = "JWP-BBS"
ipr = "trust200902"
area = "Security"
workgroup = "JOSE Working Group"
keyword = [
  "zero-knowledge proofs",
  "multi-message signatures",
  "BBS",
  "JWP",
  "selective disclosure",
  "device binding"
]

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
+++

.# Abstract

This document specifies a digital credential format that combines JSON Web Proofs (JWP) with the BBS signature scheme and a modular sub-proof framework supporting committed disclosure.
The format supports selective disclosure of signed attributes, predicate sub-proofs (such as range, equality, and set-membership proofs) over undisclosed attributes, and optional device binding through a sub-proof of knowledge of an ECDSA P-256 signature under a device public key embedded in the BBS messages.

{mainmatter}

# Introduction
