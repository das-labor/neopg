OpenPGP Profile (RFC 4880)
==========================

4.2. Packet Headers

* The old packet format MUST be supported for input.
* The new packet format MUST be used for output.
  Rational: Elevated recommendation.

4.2.1. Old Format Packet Lengths

* Packets with indeterminate length MUST be rejected.
  Rational: Interpretation is implementation defined.

4.3. Packet Tags

5.8. Marker Packet

* Marker Packets MUST NOT be generated.


* Limit the size of all packets

/* Maximum length of packets to avoid excessive memory allocation.  */
#define MAX_KEY_PACKET_LENGTH     (256 * 1024)
#define MAX_UID_PACKET_LENGTH     (  2 * 1024)
#define MAX_COMMENT_PACKET_LENGTH ( 64 * 1024)
#define MAX_ATTR_PACKET_LENGTH    ( 16 * 1024*1024)
