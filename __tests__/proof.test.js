const {
  Ed25519KeyPair,
  Ed25519Signature2018,
} = require("@transmute/ed25519-signature-2018");

const vcjs = require("@transmute/vc.js").ld;
const documentLoader = require("../documentLoader");

let fixture = {};

let vc;

const didDocument = {
  "@context": ["https://www.w3.org/ns/did/v1"],
  id: "did:example:123",
  assertionMethod: [
    {
      id: "did:example:123#credential-issuance-key",
      type: "Ed25519VerificationKey2018",
      controller: "did:example:123",
      publicKeyBase58: "g9X6bPg6ZKWvc24zgqMhrXerMXoY878KqPxfBiEVLsJ",
    },
  ],
};

beforeAll(async () => {
  vc = await vcjs.issue({
    credential: {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      id: "http://example.gov/credentials/3732",
      type: ["VerifiableCredential", "UniversityDegreeCredential"],
      issuer: {
        id: "did:example:123",
      },
      issuanceDate: "2020-03-10T04:24:12.164Z",
      credentialSubject: {
        id: "did:example:456",
      },
    },
    suite: new Ed25519Signature2018({
      key: await Ed25519KeyPair.from({
        // 🚧 NOTE: credentials are ALWAYS issued from absolute DID URLs.
        id: "did:example:123#credential-issuance-key",
        type: "Ed25519VerificationKey2018",
        controller: "did:example:123",
        publicKeyBase58: "g9X6bPg6ZKWvc24zgqMhrXerMXoY878KqPxfBiEVLsJ",
        privateKeyBase58:
          "3tJ2TAfhFgq9hpRwhL3xuM56rNsDzrdDUcYCFcgQ6RbxYRdMQQkrD3yHdMo1E2opqHZcrDWgw23zc5SfMFcP86Hv",
      }),
    }),
    documentLoader,
  });
});

it("case 0 works with @context", async () => {
  const verification = await vcjs.verifyCredential({
    credential: vc,
    suite: new Ed25519Signature2018(),
    documentLoader: (uri) => {
      if (uri.includes("did:example:123")) {
        return {
          documentUrl: uri,
          document: didDocument,
        };
      }
      return documentLoader(uri);
    },
  });
  expect(verification.verified).toBe(true);
});

it("case 0 does not work without @context", async () => {
  const verification = await vcjs.verifyCredential({
    credential: vc,
    suite: new Ed25519Signature2018(),
    documentLoader: (uri) => {
      if (uri.includes("did:example:123")) {
        delete didDocument["@context"];
        return {
          documentUrl: uri,
          document: didDocument,
        };
      }
      return documentLoader(uri);
    },
  });
  expect(verification.verified).toBe(false);
});
