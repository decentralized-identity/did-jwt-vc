# did-jwt-vc

Create and verify W3C Verifiable Credentials and Presentations in JWT format

## Installation

```
npm install did-jwt-vc
```

## Usage

### Creating JWTs

#### Prerequisites

Create an `Issuer` object to sign JWTs using [ethr-did](https://github.com/uport-project/ethr-did):

```typescript
import * as EthrDID from 'ethr-did'
import { Issuer } from 'did-jwt-vc'

const issuer: Issuer = new EthrDID({
  address: '0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
  privateKey: 'd8b595680851765f38ea5405129244ba3cbad84467d190859f4c8b20c1ff6c75'
})
```

The `Issuer` object must contain a `did` attribute, as well as a `signer` function to generate the signature.

Currently, there is only support for `ethr-did` issuers to sign JWTs using the `ES256K-R` algorithm. Future versions of this library will enable support for alternative DID methods and signing algorithms.

#### Creating a Verifiable Credential

Specify a `payload` matching the `VerifiableCredentialPayload` interface. Create a JWT by signing it with the previously configured `issuer` using the `createVerifiableCredential` function:

```typescript
import { VerifiableCredentialPayload, createVerifiableCredential } from 'did-jwt-vc'

const vcPayload: VerifiableCredentialPayload = {
  sub: 'did:ethr:0x435df3eda57154cf8cf7926079881f2912f54db4',
  nbf: 1562950282,
  vc: {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential'],
    credentialSubject: {
      degree: {
        type: 'BachelorDegree',
        name: 'Baccalauréat en musiques numériques'
      }
    }
  }
}

const vcJwt = await createVerifiableCredential(vcPayload, issuer)
console.log(vcJwt)
// eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1ODI1NDc1OTMsInN1YiI6ImRpZDpldGhyOjB4NDM1ZGYzZWRhNTcxNTRjZjhjZjc5MjYwNzk4ODFmMjkxMmY1NGRiNCIsIm5iZiI6MTU2Mjk1MDI4MiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwibmFtZSI6IkJhY2NhbGF1csOpYXQgZW4gbXVzaXF1ZXMgbnVtw6lyaXF1ZXMifX19LCJpc3MiOiJkaWQ6ZXRocjoweGYxMjMyZjg0MGYzYWQ3ZDIzZmNkYWE4NGQ2YzY2ZGFjMjRlZmIxOTgifQ.ljTuUW6bcsoBQksMo5l8eFImVdOA-ew993B4ret_p9A8j2DLQ60CQmqB14NnN5XxD0d_glLRs1Myc_LBJjnuNwE
```

#### Creating a Verifiable Presentation

Specify a `payload` matching the `PresentationPayload` interface, including the VC JWTs to be presented in the `vp.verifiableCredential` array. Create a JWT by signing it with the previously configured `issuer` using the `createPresentation` function:

```typescript
import { PresentationPayload, createPresentation } from 'did-jwt-vc'

const vpPayload: PresentationPayload = {
  vp: {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiablePresentation'],
    verifiableCredential: [vcJwt]
  }
}

const vpJwt = await createPresentation(vpPayload, issuer)
console.log(vpJwt)
// eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1ODI1NDc1OTMsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6WyJleUowZVhBaU9pSktWMVFpTENKaGJHY2lPaUpGVXpJMU5rc3RVaUo5LmV5SnBZWFFpT2pFMU9ESTFORGMxT1RNc0luTjFZaUk2SW1ScFpEcGxkR2h5T2pCNE5ETTFaR1l6WldSaE5UY3hOVFJqWmpoalpqYzVNall3TnprNE9ERm1Namt4TW1ZMU5HUmlOQ0lzSW01aVppSTZNVFUyTWprMU1ESTRNaXdpZG1NaU9uc2lRR052Ym5SbGVIUWlPbHNpYUhSMGNITTZMeTkzZDNjdWR6TXViM0puTHpJd01UZ3ZZM0psWkdWdWRHbGhiSE12ZGpFaVhTd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0pkTENKamNtVmtaVzUwYVdGc1UzVmlhbVZqZENJNmV5SmtaV2R5WldVaU9uc2lkSGx3WlNJNklrSmhZMmhsYkc5eVJHVm5jbVZsSWl3aWJtRnRaU0k2SWtKaFkyTmhiR0YxY3NPcFlYUWdaVzRnYlhWemFYRjFaWE1nYm5WdHc2bHlhWEYxWlhNaWZYMTlMQ0pwYzNNaU9pSmthV1E2WlhSb2Nqb3dlR1l4TWpNeVpqZzBNR1l6WVdRM1pESXpabU5rWVdFNE5HUTJZelkyWkdGak1qUmxabUl4T1RnaWZRLmxqVHVVVzZiY3NvQlFrc01vNWw4ZUZJbVZkT0EtZXc5OTNCNHJldF9wOUE4ajJETFE2MENRbXFCMTRObk41WHhEMGRfZ2xMUnMxTXljX0xCSmpudU53RSJdfSwiaXNzIjoiZGlkOmV0aHI6MHhmMTIzMmY4NDBmM2FkN2QyM2ZjZGFhODRkNmM2NmRhYzI0ZWZiMTk4In0.cFyO-xPMdj0Hg1DaCkm30hzcVcYdnDdgyxXLZr9NAJNMUzZ6naacuWNGdZGuU0ZDwmgpUMUqIzMqFFRmge0R8QA
```

### Verifying JWTs

#### Prerequisites

Create a `Resolver` using [did-resolver](https://github.com/decentralized-identity/did-resolver) and register the [ethr-did-resolver](https://github.com/decentralized-identity/ethr-did-resolver). When verifying a JWT signed by a DID, it is necessary to resolve its DID Document to check for keys that can validate the signature.

```typescript
import { Resolver } from 'did-resolver'
import { getResolver } from 'ethr-did-resolver'

// see also https://github.com/decentralized-identity/ethr-did-resolver#multi-network-configuration
const providerConfig = {
  rpcUrl: 'https://mainnet.infura.io/v3/<YOUR Infura.io PROJECT ID>',
  registry: '0xdca7ef03e98e0dc2b855be647c39abe984fcf21b'
}
const resolver = new Resolver(getResolver(providerConfig))
```

#### Verifying a Verifiable Credential

Pass in a VC JWT along with the resolver to verify using the `verifyCredential` function:

```typescript
import { verifyCredential } from 'did-jwt-vc'

const verifiedVC = await verifyCredential(vcJwt, resolver)
console.log(verifiedVC)
/*
{
  payload: {
    iat: 1582547593,
    sub: 'did:ethr:0x435df3eda57154cf8cf7926079881f2912f54db4',
    nbf: 1562950282,
    vc: { '@context': [Array], type: [Array], credentialSubject: [Object] },
    iss: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198'
  },
  doc: {
    '@context': 'https://w3id.org/did/v1',
    id: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
    publicKey: [ [Object] ],
    authentication: [ [Object] ]
  },
  issuer: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
  signer: {
    id: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198#owner',
    type: 'Secp256k1VerificationKey2018',
    owner: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
    ethereumAddress: '0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198'
  },
  jwt: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1ODI1NDc1OTMsInN1YiI6ImRpZDpldGhyOjB4NDM1ZGYzZWRhNTcxNTRjZjhjZjc5MjYwNzk4ODFmMjkxMmY1NGRiNCIsIm5iZiI6MTU2Mjk1MDI4MiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwibmFtZSI6IkJhY2NhbGF1csOpYXQgZW4gbXVzaXF1ZXMgbnVtw6lyaXF1ZXMifX19LCJpc3MiOiJkaWQ6ZXRocjoweGYxMjMyZjg0MGYzYWQ3ZDIzZmNkYWE4NGQ2YzY2ZGFjMjRlZmIxOTgifQ.ljTuUW6bcsoBQksMo5l8eFImVdOA-ew993B4ret_p9A8j2DLQ60CQmqB14NnN5XxD0d_glLRs1Myc_LBJjnuNwE'
}
 */
```

#### Verifying a Verifiable Presentation

Pass in a VP JWT along with the resolver to verify using the `verifyPresentation` function:

```typescript
import { verifyPresentation } from 'did-jwt-vc'

const verifiedVP = await verifyPresentation(vpJwt, resolver)
console.log(verifiedVP)
/*
{
  payload: {
    iat: 1582547593,
    vp: {
      '@context': [Array],
      type: [Array],
      verifiableCredential: [Array]
    },
    iss: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198'
  },
  doc: {
    '@context': 'https://w3id.org/did/v1',
    id: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
    publicKey: [ [Object] ],
    authentication: [ [Object] ]
  },
  issuer: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
  signer: {
    id: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198#owner',
    type: 'Secp256k1VerificationKey2018',
    owner: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
    ethereumAddress: '0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198'
  },
  jwt: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1ODI1NDc1OTMsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6WyJleUowZVhBaU9pSktWMVFpTENKaGJHY2lPaUpGVXpJMU5rc3RVaUo5LmV5SnBZWFFpT2pFMU9ESTFORGMxT1RNc0luTjFZaUk2SW1ScFpEcGxkR2h5T2pCNE5ETTFaR1l6WldSaE5UY3hOVFJqWmpoalpqYzVNall3TnprNE9ERm1Namt4TW1ZMU5HUmlOQ0lzSW01aVppSTZNVFUyTWprMU1ESTRNaXdpZG1NaU9uc2lRR052Ym5SbGVIUWlPbHNpYUhSMGNITTZMeTkzZDNjdWR6TXViM0puTHpJd01UZ3ZZM0psWkdWdWRHbGhiSE12ZGpFaVhTd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0pkTENKamNtVmtaVzUwYVdGc1UzVmlhbVZqZENJNmV5SmtaV2R5WldVaU9uc2lkSGx3WlNJNklrSmhZMmhsYkc5eVJHVm5jbVZsSWl3aWJtRnRaU0k2SWtKaFkyTmhiR0YxY3NPcFlYUWdaVzRnYlhWemFYRjFaWE1nYm5WdHc2bHlhWEYxWlhNaWZYMTlMQ0pwYzNNaU9pSmthV1E2WlhSb2Nqb3dlR1l4TWpNeVpqZzBNR1l6WVdRM1pESXpabU5rWVdFNE5HUTJZelkyWkdGak1qUmxabUl4T1RnaWZRLmxqVHVVVzZiY3NvQlFrc01vNWw4ZUZJbVZkT0EtZXc5OTNCNHJldF9wOUE4ajJETFE2MENRbXFCMTRObk41WHhEMGRfZ2xMUnMxTXljX0xCSmpudU53RSJdfSwiaXNzIjoiZGlkOmV0aHI6MHhmMTIzMmY4NDBmM2FkN2QyM2ZjZGFhODRkNmM2NmRhYzI0ZWZiMTk4In0.cFyO-xPMdj0Hg1DaCkm30hzcVcYdnDdgyxXLZr9NAJNMUzZ6naacuWNGdZGuU0ZDwmgpUMUqIzMqFFRmge0R8QA'
}
 */
```
