# Two real time stamps, for offline tests

Made on 2026-09-30 at 18:41 UTC by the chat that built the SealHour client's interim backend, one request
to each free provider the backend pins:

- `q.tsq`: the request, SHA-256 message imprint of the public test string
  `OpsContext interim stamp provider check 2026-09-30`
  (`8ae6b8a72075113dc6024f5d7ece1b3df484747b1997e241355b8318c3265012`), a nonce, certificate requested;
- `freetsa.tsr`: FreeTSA's reply (https://freetsa.org/tsr), time 2026-09-30 18:41:37 UTC;
- `digicert.tsr`: DigiCert's reply (http://timestamp.digicert.com), time 2026-09-30 18:41:38 UTC.

`tests/anchor-tsa.test.ts` reads them and checks them with OpenSSL against the roots pinned in
`src/anchor-tsa.ts`, at the stamps' own time, without any network. Nothing here is secret: a digest of a
public sentence and two signed replies.
