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
import EthrDID from 'ethr-did'
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
// eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1Njk5NDg1NDUsInN1YiI6IjB4NDM1ZGYzZWRhNTcxNTRjZjhjZjc5MjYwNzk4ODFmMjkxMmY1NGRiNCIsIm5iZiI6MTU2Mjk1MDI4MiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwibmFtZSI6IkJhY2NhbGF1csOpYXQgZW4gbXVzaXF1ZXMgbnVtw6lyaXF1ZXMifX19LCJpc3MiOiJkaWQ6ZXRocjoweGYxMjMyZjg0MGYzYWQ3ZDIzZmNkYWE4NGQ2YzY2ZGFjMjRlZmIxOTgifQ.RynzSF4IqC85-DxRHwUyaagfxjDVV3_WnSl1sA2SYkYEvPLDrK6pgeXVkHCUDOdPiGlMuj2RDbt_yuIPtm1E7gE
```

#### Creating a Verifiable Presentation

Specify a `payload` matching the `PresentationPayload` interface, including the VC JWTs to be presented in the `vp.verifiableCredential` array. Create a JWT by signing it with the previously configured `issuer` using the `createPresentation` function:

```typescript
import { PresentationPayload, createPresentation } from 'did-jwt-vc'

const vpPayload: PresentationPayload = {
  vp: {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential'],
    verifiableCredential: [vcJwt]
  }
}

const vpJwt = await createPresentation(vpPayload, issuer)
console.log(vpJwt)
// eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1Njk5NDg1NDUsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKRlV6STFOa3N0VWlKOS5leUpwWVhRaU9qRTFOams1TkRnMU5EVXNJbk4xWWlJNklqQjRORE0xWkdZelpXUmhOVGN4TlRSalpqaGpaamM1TWpZd056azRPREZtTWpreE1tWTFOR1JpTkNJc0ltNWlaaUk2TVRVMk1qazFNREk0TWl3aWRtTWlPbnNpUUdOdmJuUmxlSFFpT2xzaWFIUjBjSE02THk5M2QzY3Vkek11YjNKbkx6SXdNVGd2WTNKbFpHVnVkR2xoYkhNdmRqRWlYU3dpZEhsd1pTSTZXeUpXWlhKcFptbGhZbXhsUTNKbFpHVnVkR2xoYkNKZExDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUprWldkeVpXVWlPbnNpZEhsd1pTSTZJa0poWTJobGJHOXlSR1ZuY21WbElpd2libUZ0WlNJNklrSmhZMk5oYkdGMWNzT3BZWFFnWlc0Z2JYVnphWEYxWlhNZ2JuVnR3Nmx5YVhGMVpYTWlmWDE5TENKcGMzTWlPaUprYVdRNlpYUm9jam93ZUdZeE1qTXlaamcwTUdZellXUTNaREl6Wm1Oa1lXRTROR1EyWXpZMlpHRmpNalJsWm1JeE9UZ2lmUS5SeW56U0Y0SXFDODUtRHhSSHdVeWFhZ2Z4akRWVjNfV25TbDFzQTJTWWtZRXZQTERySzZwZ2VYVmtIQ1VET2RQaUdsTXVqMlJEYnRfeXVJUHRtMUU3Z0UiXX0sImlzcyI6ImRpZDpldGhyOjB4ZjEyMzJmODQwZjNhZDdkMjNmY2RhYTg0ZDZjNjZkYWMyNGVmYjE5OCJ9.dB0xmcMFhiIGVZByd7Zz7Ocy0DU4XaDhIo-aUoC35Nff2ZwM_Y6qlW5cKs51nuf2Ogs0aMGgQ422L1Tzjm_WrgE
```

### Verifying JWTs

#### Prerequisites

Create a `Resolver` using [did-resolver](https://github.com/decentralized-identity/did-resolver) and register the [ethr-did-resolver](https://github.com/decentralized-identity/ethr-did-resolver). When verifying a JWT signed by a DID, it is necessary to resolve its DID Document to check for keys that can validate the signature.

```typescript
import { Resolver } from 'did-resolver'
import { getResolver } from 'ethr-did-resolver'

const resolver = new Resolver(getResolver())
```

#### Verifying a Verifiable Credential

Pass in a VC JWT along with the resolver to verify using the `verifyCredential` function:

```typescript
import { verifyCredential } from 'did-jwt-vc'

const verifiedVC = await verifyCredential(vcJwt, resolver)
console.log(verifiedVC)
/*
{ payload:
 { iat: 1569948545,
   sub: '0x435df3eda57154cf8cf7926079881f2912f54db4',
   nbf: 1562950282,
   vc:
    { '@context': [Array],
      type: [Array],
      credentialSubject: [Object] },
   iss: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198' },
doc:
 { '@context': 'https://w3id.org/did/v1',
   id: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
   publicKey: [ [Object] ],
   authentication: [ [Object] ] },
issuer: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
signer:
 { id: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198#owner',
   type: 'Secp256k1VerificationKey2018',
   owner: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
   ethereumAddress: '0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198' },
jwt:
 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1Njk5NDg1NDUsInN1YiI6IjB4NDM1ZGYzZWRhNTcxNTRjZjhjZjc5MjYwNzk4ODFmMjkxMmY1NGRiNCIsIm5iZiI6MTU2Mjk1MDI4MiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwibmFtZSI6IkJhY2NhbGF1csOpYXQgZW4gbXVzaXF1ZXMgbnVtw6lyaXF1ZXMifX19LCJpc3MiOiJkaWQ6ZXRocjoweGYxMjMyZjg0MGYzYWQ3ZDIzZmNkYWE4NGQ2YzY2ZGFjMjRlZmIxOTgifQ.RynzSF4IqC85-DxRHwUyaagfxjDVV3_WnSl1sA2SYkYEvPLDrK6pgeXVkHCUDOdPiGlMuj2RDbt_yuIPtm1E7gE' }
 */
```

#### Verifying a Verifiable Presentation

Pass in a VP JWT along with the resolver to verify using the `verifyPresentation` function:

```typescript
import { verifyPresentation } from 'did-jwt-vc'

const verifiedVP = await verifyPresentation(vpJwt, resolver)
console.log(verifiedVP)
/*
{ payload:
 { iat: 1569948545,
   vp:
    { '@context': [Array],
      type: [Array],
      verifiableCredential: [Array] },
   iss: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198' },
doc:
 { '@context': 'https://w3id.org/did/v1',
   id: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
   publicKey: [ [Object] ],
   authentication: [ [Object] ] },
issuer: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
signer:
 { id: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198#owner',
   type: 'Secp256k1VerificationKey2018',
   owner: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
   ethereumAddress: '0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198' },
jwt:
 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1Njk5NDg1NDUsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKRlV6STFOa3N0VWlKOS5leUpwWVhRaU9qRTFOams1TkRnMU5EVXNJbk4xWWlJNklqQjRORE0xWkdZelpXUmhOVGN4TlRSalpqaGpaamM1TWpZd056azRPREZtTWpreE1tWTFOR1JpTkNJc0ltNWlaaUk2TVRVMk1qazFNREk0TWl3aWRtTWlPbnNpUUdOdmJuUmxlSFFpT2xzaWFIUjBjSE02THk5M2QzY3Vkek11YjNKbkx6SXdNVGd2WTNKbFpHVnVkR2xoYkhNdmRqRWlYU3dpZEhsd1pTSTZXeUpXWlhKcFptbGhZbXhsUTNKbFpHVnVkR2xoYkNKZExDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUprWldkeVpXVWlPbnNpZEhsd1pTSTZJa0poWTJobGJHOXlSR1ZuY21WbElpd2libUZ0WlNJNklrSmhZMk5oYkdGMWNzT3BZWFFnWlc0Z2JYVnphWEYxWlhNZ2JuVnR3Nmx5YVhGMVpYTWlmWDE5TENKcGMzTWlPaUprYVdRNlpYUm9jam93ZUdZeE1qTXlaamcwTUdZellXUTNaREl6Wm1Oa1lXRTROR1EyWXpZMlpHRmpNalJsWm1JeE9UZ2lmUS5SeW56U0Y0SXFDODUtRHhSSHdVeWFhZ2Z4akRWVjNfV25TbDFzQTJTWWtZRXZQTERySzZwZ2VYVmtIQ1VET2RQaUdsTXVqMlJEYnRfeXVJUHRtMUU3Z0UiXX0sImlzcyI6ImRpZDpldGhyOjB4ZjEyMzJmODQwZjNhZDdkMjNmY2RhYTg0ZDZjNjZkYWMyNGVmYjE5OCJ9.dB0xmcMFhiIGVZByd7Zz7Ocy0DU4XaDhIo-aUoC35Nff2ZwM_Y6qlW5cKs51nuf2Ogs0aMGgQ422L1Tzjm_WrgE' }
 */
```
