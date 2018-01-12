---
layout: default
title: OpenPGP Profile (RFC 4880) for NeoPG
---
# OpenPGP Profile (RFC 4880) for NeoPG

The following profile of RFC 4880 is used to aid the implementation of
NeoPG.  It deprecates underspecified features of OpenPG, avoids
ill-designed features and in general simplifies things to a tolerable
level.

## First principles

The following first principles will guide this OpenPGP profile.  We
explain them here once and reference them in the rationale sections
below.

* __Security__: RFC 4880 allows some unsafe mechanisms.  We avoid
  these by forbidding their use.
* __Strictness__: OpenPGP allows too much flexibility in the packet
  composition.  This provides a larger attack vector.  We avoid this
  by being more strict in what we accept.
* __Enforced Deprecation__: OpenPGP has deprecated some bad practices in
  2007, but was never updated to enforce this deprecation.  We enforce
  deprecation even if the OpenPGP still allows or mandates
  compatibility.
* __Drop PGP 2.x__: RFC 4880 still allows for PGP 2.x compatibility,
  which comes at significant cost of complexity, and increases the
  attack vector.  We break PGP 2.x compatibilty to enable other
  improvements.

## 4. Packet Syntax

### 4.2. Packet Headers

* __output__: The new packet format MUST be used for all packets.
* __input__: The old packet format MUST be supported.

#### Rationale

The old packet format is still in use, but we are deprecating it here.

Principles: __Enforce Deprecation__, __Drop PGP 2.x__

#### 4.2.1. Old Format Packet Lengths

* Packets with indeterminate length MUST be rejected.

### 4.3. Packet Tags

FIXME

##### 5.2.3.18. Preferred Key Server

* Preferred Key Server Packets MUST not be generated.
* Preferred Key Server Packets MUST be ignored (even if critical).

###### Rationale

Preferred key servers have not seen wide adoption, and they can be
used to violate the privacy of the recipient.  The standard allows to
set multiple preferred key servers on multiple user ids, which is
ambiguous.  The meaning of the URI in the field is left open to
interpretation.  We are deprecating this subpacket here.

Principles: __Security__

###### References

* [RFC 4880, Section 5.2.3.18](https://tools.ietf.org/html/rfc4880#section-5.2.3.18)

### 5.6.  Compressed Data Packet

* __output__: A Compressed Data Packet MUST contain exactly one Literal Data Packet.
* __input__: Compressed Data Packets that contain anything else MUST be rejected.

#### Rationale

Arbitrary nesting of OpenPGP packets increases the attack surface.

Principles: __Security__, __Strictness__

#### References

* [CVE-2013-4402](https://nvd.nist.gov/vuln/detail/CVE-2013-4402)

### 5.7. Symmetrically Encrypted Data Packet

* __output__: Symmetrically Encrypted Data Packets MUST not be generated.
* __input__: Symmetrically Encrypted Data Packets MUST be rejected.

#### Rationale

Encryption without integrity protection is unsafe, and allows an
attacker to modify the plaintext without detection.

Principles: __Security__, __Enforced Deprecation__

#### References

* [RFC 4880, Section 5.7](https://tools.ietf.org/html/rfc4880#section-5.7)
* c.f. 5.13.

### 5.8. Marker Packet

* __output__: Marker Packets MUST NOT be generated.
* __input__: Marker Packets MUST be rejected.

#### Rationale

RFC 4880 mandates that marker packets "MUST be ignored when received."
We disagree, because according to the same standard, no released
version of PGP generated such packets.

Principles: __Strictness__, __Enforced Deprecation__, __Drop PGP 2.x__

#### References

* [RFC 4880, Section 5.8](https://tools.ietf.org/html/rfc4880#section-5.8)

### 5.9. Literal Data Packet

* Generated Literal Data Packets MUST have data type 'b' (binary).
* Generated Literal Data Packets MUST have a zero-length file name.
* Generated Literal Data Packets MUST have a timestamp of 0.
* All Literal Data Packets MUST be treated as if the data type is 'b' (binary).
* All Literal Data Packets MUST be treated as if the file name is zero-length.
* All Literal Data Packets MUST be treated as if the timestamp is 0.

### 5.10 Trust Packet

* __output__: Trust Packets MUST not be emitted.
* __input__: Trust Packets MUST be rejected.

#### Rationale

RFC 4880 mandates that trust packets are ignored when received, but it
also says they should not be emitted.  The content of these packets is
implementation defined.  Ignoring them provides a larger attack
vector, so we disagree with the standard here and require that they
are rejected.

Principles: __Strictness__

#### References

* [RFC 4880, Section 5.10](https://tools.ietf.org/html/rfc4880#section-5.10)

### 5.11 User ID Packet

* Generated User ID Packets MUST have a payload less than or equal to 2 KB.
* User ID Packets larger than 2 KB and their certificates MUST be rejected.

#### Rationale

RFC 4880 does not restrict the length or content of user ID packets,
so they can be up to 4 GB.  This provides a larger attack vector, so
we disagree with the standard here and require that large user IDs are
rejected.  GnuPG limits user ID packets to 2 KB.

Principles: __Strictness__, __Security__

#### References

* [RFC 4880, Section 5.11](https://tools.ietf.org/html/rfc4880#section-5.11)

#### Future Discussion

Keys require a user ID packet, because certain meta-data is attached
to user IDs only (and can not be attached to the key directly).

With the web of trust, self-signed user IDs were used to bootstrap the
key-signing process (making sure that everybody agreed on the same
user ID format).  However, with the decline of the web of trust,
unverified self-signed user IDs are of limited value.

User ID packets signed by some authority (which may be the local
user), even if they are not self-signed, will become more significant
in NeoPG in the future.

### 5.12 User Attribute Packet

* __output__: User Attribute Packets MUST NOT be generated.
* __input__: All User Attribute Packets and its certificates MUST be ignored.

#### Rationale

The only user attribute packet defined in RFC 4880 is the image for
photo id.  No other user attribute packets were defined or are in
widespread use, so we deprecate the fetaure here.

Principles: __Enforced Deprecation__

#### References

* [RFC 4880, Section 5.12](https://tools.ietf.org/html/rfc4880#section-5.12)

#### 5.12.1 Image Attribute Subpacket

See 5.12.

### 5.13.  Sym. Encrypted Integrity Protected Data Packet

* After decryption, the plaintext MUST contain exactly one Compressed
Data Packet or exactly one Literal Data Packet.

NOTE: If there are more possibilities, move the constrain to section
11 (Packet Composition).

## 6. Radix-64 Conversions

## 7. Cleartext Signature Framework

* Cleartext signatures MUST NOT be generated.
* Cleartext signatures MUST be ignored.

### Rationale

Use a detached signature instead.

## Further Requirements

### Limit the size of all packets

```
/* Maximum length of packets to avoid excessive memory allocation.  */
#define MAX_KEY_PACKET_LENGTH     (256 * 1024)
#define MAX_COMMENT_PACKET_LENGTH ( 64 * 1024)
#define MAX_ATTR_PACKET_LENGTH    ( 16 * 1024*1024)
```
