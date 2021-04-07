In response to https://github.com/w3c/did-imp-guide/pull/3

Proof that dropping `@context` in `application/did+json` breaks implementions of VCs using DIDs.

Why break compatibility for no benefit? `@context` is ignored by `did+json` production and consumption rules.
