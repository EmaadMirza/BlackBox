# Stage 1 reference vectors

- `rfc8785_sort.json`: RFC 8785 §3.2.3 Unicode property-order example.
- `rfc8785_numbers.json`: all 26 IEEE-754 samples from RFC 8785 Appendix B.
  The existing rfc8785 engine must match the published outputs. BlackBox rejects
  all Python float inputs (including those with integral values) before JCS.
- `rfc6962.json`: eight prefix roots and two consistency proofs from Google's
  Certificate Transparency reference test suite. RFC 6962 itself provides tree
  definitions/diagrams, not a normative numeric test-vector corpus.

Sources:
- https://www.rfc-editor.org/rfc/rfc8785.html (§3.2.3, Appendix B; IETF Trust)
- https://www.rfc-editor.org/rfc/rfc6962.html (§2)
- https://github.com/google/certificate-transparency/blob/master/python/ct/crypto/merkle_test.py
  (Google Certificate Transparency project, Apache License 2.0;
  https://www.apache.org/licenses/LICENSE-2.0)

Only test data is transcribed; production Merkle code is independently implemented.
NFC is a BlackBox preprocessing step, not part of RFC JCS. Tests explicitly preserve
that distinction, including the NFC decomposition of U+FB33 in the sorting example.
G2 supplements reference vectors with an independent recursive implementation,
all inclusion proofs and all consistency-size pairs 1–200, and bit corruption.
