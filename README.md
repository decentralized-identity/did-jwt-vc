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

Currently, there is only support for `ethr-did` issuers to sign JWTs using the `ES256K` algorithm. Future versions of
this library will enable support for alternative DID methods and signing algorithms.

#### Creating a Verifiable Credential

Specify a `payload` matching the `CredentialPayload` or `JwtCredentialPayload` interfaces. Create a JWT by signing it
with the previously configured `issuer` using the `createVerifiableCredentialJwt` function:

```typescript
import { VerifiableCredentialPayload, createVerifiableCredential } from 'did-jwt-vc'

const vcPayload: JwtCredentialPayload = {
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

const vcJwt = await createVerifiableCredentialJwt(vcPayload, issuer)
console.log(vcJwt)
// eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQi...0CQmqB14NnN5XxD0d_glLRs1Myc_LBJjnuNwE
```

#### Creating a Verifiable Presentation

Specify a `payload` matching the `PresentationPayload` or `JwtPresentationPayload` interfaces, including the VC JWTs to
be presented in the `vp.verifiableCredential` array. Create a JWT by signing it with the previously configured `issuer`
using the `createVerifiablePresentationJwt` function:

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
// eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1ODI1NDc...JNMUzZ6naacuWNGdZGuU0ZDwmgpUMUqIzMqFFRmge0R8QA
```

### Verifying JWTs

#### Prerequisites

Create a `Resolver` using [did-resolver](https://github.com/decentralized-identity/did-resolver) and register the
[ethr-did-resolver](https://github.com/decentralized-identity/ethr-did-resolver). When verifying a JWT signed by a DID,
it is necessary to resolve its DID Document to check for keys that can validate the signature.

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
  "payload": {
    // the original payload of the signed credential
  },
  "doc": {
    // the DID document of the credential issuer (as returned by the `resolver`)
  },
  "issuer": "did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198", //the credential issuer
  "signer": {
    //the publicKey entry of the `doc` that has signed the credential
  },
  "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1NjY...Sx3Y2IdWaUpatJQA", // the original credential
  "verifiableCredential": {
    "@context": [Array],
    "type": [ "VerifiableCredential", "UniversityDegreeCredential" ],
    "issuer": {
      "id": "did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198"
    },
    "issuanceDate": "2019-07-12T16:51:22.000Z",
    "credentialSubject": {
      "id": "did:ethr:0x435df3eda57154cf8cf7926079881f2912f54db4"
      "degree": {
        "type": "BachelorDegree",
        "name": "Baccalauréat en musiques numériques"
      },
    },
    "proof": {
      "type": "JwtProof2020",
      "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1NjY...Sx3Y2IdWaUpatJQA"
    }
  }
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
    iat: 1568045263,
    vp: {
      '@context': [Array],
      type: ['VerifiablePresentation'],
      verifiableCredential: [
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1NjY5...lpNm51cqSx3Y2IdWaUpatJQA'
      ]
    },
    iss: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198'
  },
  
  doc: {
    '@context': 'https://w3id.org/did/v1',
    id: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
    publicKey: [
      {
        id: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198#owner',
        type: 'Secp256k1VerificationKey2018',
        ethereumAddress: '0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
        owner: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198'
      }
    ]
  },
  
  issuer: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
  
  signer: {
    id: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198#owner',
    type: 'Secp256k1VerificationKey2018',
    ethereumAddress: '0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
    owner: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198'
  },

  jwt: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1NjgwNDUyNjMsInZwIjp7...ViNNCvoTQ-swSHwbELW7-EGPAcHLOMiIwE',

  verifiablePresentation: {
    verifiableCredential: [
      {
        iat: 1566923269,
        credentialSubject: {
          degree: { type: 'BachelorDegree', name: 'Baccalauréat en musiques numériques' },
          id: 'did:ethr:0x435df3eda57154cf8cf7926079881f2912f54db4'
        },
        issuer: { id: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198' },
        type: ['VerifiableCredential', 'UniversityDegreeCredential'],
        '@context': [Array],
        issuanceDate: '2019-07-12T16:51:22.000Z',
        proof: {
          type: 'JwtProof2020',
          jwt: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1NjY5...lpNm51cqSx3Y2IdWaUpatJQA'
        }
      }
    ],
    holder: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
    type: ['VerifiablePresentation'],
    '@context': [Array],
    issuanceDate: '2019-09-09T16:07:43.000Z',
    proof: {
      type: 'JwtProof2020',
      jwt: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1NjgwNDUyNjMsInZwI...ViNNCvoTQ-swSHwbELW7-EGPAcHLOMiIwE'
    }
  }
}
*/
```
