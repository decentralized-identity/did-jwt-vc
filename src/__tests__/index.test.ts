import { EthrDID } from 'ethr-did'
import {
  createVerifiableCredentialJwt,
  createVerifiablePresentationJwt,
  Issuer,
  JwtCredentialPayload,
  verifyCredential,
  verifyPresentation,
  verifyPresentationPayloadOptions,
} from '../index'
import { decodeJWT, ES256KSigner, hexToBytes } from 'did-jwt'
import { Resolvable } from 'did-resolver'
import {
  CreatePresentationOptions,
  DEFAULT_CONTEXT,
  DEFAULT_VC_TYPE,
  DEFAULT_VP_TYPE,
  VerifyPresentationOptions,
} from '../types'
import {
  validateContext,
  validateCredentialSubject,
  validateJwtFormat,
  validateTimestamp,
  validateVcType,
  validateVpType,
} from '../validators'
import elliptic from 'elliptic'
import * as u8a from 'uint8arrays'

const secp256k1 = new elliptic.ec('secp256k1')

jest.mock('../validators')

const mockValidateJwtFormat = <jest.Mock<typeof validateJwtFormat>>validateJwtFormat
const mockValidateTimestamp = <jest.Mock<typeof validateTimestamp>>validateTimestamp

const mockValidateContext = <jest.Mock<typeof validateContext>>validateContext
const mockValidateVcType = <jest.Mock<typeof validateVcType>>validateVcType
const mockValidateVpType = <jest.Mock<typeof validateVpType>>validateVpType
const mockValidateCredentialSubject = <jest.Mock<typeof validateCredentialSubject>>validateCredentialSubject

const DID_B = 'did:ethr:0x435df3eda57154cf8cf7926079881f2912f54db4'
const EXTRA_CONTEXT_A = 'https://www.w3.org/2018/credentials/examples/v1'
const EXTRA_TYPE_A = 'UniversityDegreeCredential'
const VC_JWT =
  // tslint:disable-next-line: max-line-length
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1NjY5MjMyNjksInN1YiI6ImRpZDpldGhyOjB4NDM1ZGYzZWRhNTcxNTRjZjhjZjc5MjYwNzk4ODFmMjkxMmY1NGRiNCIsIm5iZiI6MTU2Mjk1MDI4MiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy9leGFtcGxlcy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVW5pdmVyc2l0eURlZ3JlZUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiZGVncmVlIjp7InR5cGUiOiJCYWNoZWxvckRlZ3JlZSIsIm5hbWUiOiJCYWNjYWxhdXLDqWF0IGVuIG11c2lxdWVzIG51bcOpcmlxdWVzIn19fSwiaXNzIjoiZGlkOmV0aHI6MHhmMTIzMmY4NDBmM2FkN2QyM2ZjZGFhODRkNmM2NmRhYzI0ZWZiMTk4In0.rFRZUCw3Gu0E_I5ZJbrbpuHV1JNAwpXaiFZuJ59iJ-TNqufr4cuGCBEECFbgQF-lpNm51cqSx3Y2IdWaUpatJQA'
const PRESENTATION_JWT =
  // tslint:disable-next-line: max-line-length
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1NjgwNDUyNjMsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6WyJleUowZVhBaU9pSktWMVFpTENKaGJHY2lPaUpGVXpJMU5rc3RVaUo5LmV5SnBZWFFpT2pFMU5qWTVNak15Tmprc0luTjFZaUk2SW1ScFpEcGxkR2h5T2pCNE5ETTFaR1l6WldSaE5UY3hOVFJqWmpoalpqYzVNall3TnprNE9ERm1Namt4TW1ZMU5HUmlOQ0lzSW01aVppSTZNVFUyTWprMU1ESTRNaXdpZG1NaU9uc2lRR052Ym5SbGVIUWlPbHNpYUhSMGNITTZMeTkzZDNjdWR6TXViM0puTHpJd01UZ3ZZM0psWkdWdWRHbGhiSE12ZGpFaUxDSm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3ZNakF4T0M5amNtVmtaVzUwYVdGc2N5OWxlR0Z0Y0d4bGN5OTJNU0pkTENKMGVYQmxJanBiSWxabGNtbG1hV0ZpYkdWRGNtVmtaVzUwYVdGc0lpd2lWVzVwZG1WeWMybDBlVVJsWjNKbFpVTnlaV1JsYm5ScFlXd2lYU3dpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaVpHVm5jbVZsSWpwN0luUjVjR1VpT2lKQ1lXTm9aV3h2Y2tSbFozSmxaU0lzSW01aGJXVWlPaUpDWVdOallXeGhkWExEcVdGMElHVnVJRzExYzJseGRXVnpJRzUxYmNPcGNtbHhkV1Z6SW4xOWZTd2lhWE56SWpvaVpHbGtPbVYwYUhJNk1IaG1NVEl6TW1ZNE5EQm1NMkZrTjJReU0yWmpaR0ZoT0RSa05tTTJObVJoWXpJMFpXWmlNVGs0SW4wLnJGUlpVQ3czR3UwRV9JNVpKYnJicHVIVjFKTkF3cFhhaUZadUo1OWlKLVROcXVmcjRjdUdDQkVFQ0ZiZ1FGLWxwTm01MWNxU3gzWTJJZFdhVXBhdEpRQSJdfSwiaXNzIjoiZGlkOmV0aHI6MHhmMTIzMmY4NDBmM2FkN2QyM2ZjZGFhODRkNmM2NmRhYzI0ZWZiMTk4In0.bWZyEpLsx0u6v-UIcQf9TVMde1gTFsn091BY-TViUuRoUNsNQFzN-ViNNCvoTQ-swSHwbELW7-EGPAcHLOMiIwE'

const ethrDidIssuer = new EthrDID({
  identifier: '0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
  privateKey: 'd8b595680851765f38ea5405129244ba3cbad84467d190859f4c8b20c1ff6c75',
}) as Issuer

const verifiableCredentialPayload = {
  sub: DID_B,
  nbf: 1562950282,
  vc: {
    '@context': [DEFAULT_CONTEXT, EXTRA_CONTEXT_A],
    type: [DEFAULT_VC_TYPE, EXTRA_TYPE_A],
    credentialSubject: {
      degree: {
        type: 'BachelorDegree',
        name: 'Baccalauréat en musiques numériques',
      },
    },
  },
}
const presentationPayload = {
  vp: {
    '@context': [DEFAULT_CONTEXT, EXTRA_CONTEXT_A],
    type: [DEFAULT_VP_TYPE],
    verifiableCredential: [VC_JWT],
  },
}
const resolver: Resolvable = {
  resolve: (did: string) =>
    Promise.resolve({
      didDocument: {
        '@context': 'https://w3id.org/did/v1',
        id: `${did}`,
        publicKey: [
          {
            id: `${did}#owner`,
            type: 'EcdsaSecp256k1RecoveryMethod2020',
            ethereumAddress: `${did.substring(9)}`,
            controller: did,
          },
        ],
      },
      didDocumentMetadata: {},
      didResolutionMetadata: {},
    }),
}

beforeEach(() => {
  jest.resetAllMocks()
})

describe('createVerifiableCredential', () => {
  const issuer = ethrDidIssuer
  it('creates a valid Verifiable Credential JWT with required fields', async () => {
    expect.assertions(1)
    const vcJwt = await createVerifiableCredentialJwt(verifiableCredentialPayload, issuer)
    const decodedVc = await decodeJWT(vcJwt)
    const { iat, ...payload } = decodedVc.payload
    expect(payload).toMatchSnapshot()
  })
  it('creates a valid Verifiable Credential JWT with extra optional fields', async () => {
    expect.assertions(1)
    const vcJwt = await createVerifiableCredentialJwt({ ...verifiableCredentialPayload, extra: 42 }, issuer)
    const decodedVc = await decodeJWT(vcJwt)
    const { iat, ...payload } = decodedVc.payload
    expect(payload).toMatchSnapshot()
  })
  it('creates a Verifiable Credential JWT with custom JWT alg', async () => {
    expect.assertions(1)
    const customIssuer = { ...issuer, alg: 'ES256K-R' }
    const vcJwt = await createVerifiableCredentialJwt({ ...verifiableCredentialPayload, extra: 42 }, customIssuer)
    const decodedVc = await decodeJWT(vcJwt)
    expect(decodedVc.header).toEqual({ alg: 'ES256K-R', typ: 'JWT' })
  })
  it('creates a Verifiable Credential JWT with custom JWT header fields', async () => {
    expect.assertions(1)
    const vcJwt = await createVerifiableCredentialJwt({ ...verifiableCredentialPayload, extra: 42 }, issuer, {
      header: { alg: 'ES256K-R', custom: 'field' },
    })
    const decodedVc = await decodeJWT(vcJwt)
    expect(decodedVc.header).toEqual({ alg: 'ES256K-R', custom: 'field', typ: 'JWT' })
  })
  it('creates a Verifiable Credential JWT with exp field using expiresIn of did-jwt', async () => {
    expect.assertions(1)
    const nbf = Math.floor(Date.now() / 1000)
    const expiresIn = 86400
    const vcJwt = await createVerifiableCredentialJwt({ ...verifiableCredentialPayload, nbf }, issuer, {
      expiresIn,
      header: { alg: 'ES256K-R' },
    })
    const decodedVc = await decodeJWT(vcJwt)
    expect(decodedVc.payload.exp).toEqual(nbf + expiresIn)
  })
  it('calls functions to validate required fields', async () => {
    expect.assertions(4)
    await createVerifiableCredentialJwt(verifiableCredentialPayload, issuer)
    expect(mockValidateTimestamp).toHaveBeenCalledWith(verifiableCredentialPayload.nbf)
    expect(mockValidateContext).toHaveBeenCalledWith(verifiableCredentialPayload.vc['@context'])
    expect(mockValidateVcType).toHaveBeenCalledWith(verifiableCredentialPayload.vc.type)
    expect(mockValidateCredentialSubject).toHaveBeenCalledWith(verifiableCredentialPayload.vc.credentialSubject)
  })
  it('calls functions to validate optional fields if they are present', async () => {
    expect.assertions(1)
    const timestamp = Math.floor(new Date().getTime())
    await createVerifiableCredentialJwt({ ...verifiableCredentialPayload, exp: timestamp }, issuer)
    expect(mockValidateTimestamp).toHaveBeenCalledWith(timestamp)
  })
})

describe('createPresentation', () => {
  const holder = ethrDidIssuer

  it('creates a valid Presentation JWT with required fields', async () => {
    expect.assertions(1)
    const presentationJwt = await createVerifiablePresentationJwt(presentationPayload, holder)
    const decodedPresentation = await decodeJWT(presentationJwt)
    const { iat, ...payload } = decodedPresentation.payload
    expect(payload).toMatchSnapshot()
  })

  it('creates a valid Presentation JWT with extra optional fields', async () => {
    expect.assertions(2)
    const presentationJwt = await createVerifiablePresentationJwt({ ...presentationPayload, extra: 42 }, holder)
    const decodedPresentation = await decodeJWT(presentationJwt)
    const { iat, ...payload } = decodedPresentation.payload
    expect(payload).toMatchSnapshot()
    expect(payload.extra).toBe(42)
  })

  it('creates a valid Presentation JWT with domain option', async () => {
    expect.assertions(4)
    const options: CreatePresentationOptions = {
      domain: 'TEST_DOMAIN',
    }

    const presentationJwt = await createVerifiablePresentationJwt(
      { ...presentationPayload, extra: 42 },
      holder,
      options
    )
    const decodedPresentation = await decodeJWT(presentationJwt)
    const { iat, ...payload } = decodedPresentation.payload
    expect(payload).toMatchSnapshot()
    expect(payload).toHaveProperty('aud', ['TEST_DOMAIN'])
    expect(payload).toHaveProperty('extra', 42)
    expect(payload).not.toHaveProperty('nonce')
  })

  it('creates a valid Presentation JWT with domain option and existing aud', async () => {
    expect.assertions(3)
    const options: CreatePresentationOptions = {
      domain: 'TEST_DOMAIN',
    }

    const presentationJwt = await createVerifiablePresentationJwt(
      { ...presentationPayload, aud: ['EXISTING_AUD'] },
      holder,
      options
    )
    const decodedPresentation = await decodeJWT(presentationJwt)
    const { iat, ...payload } = decodedPresentation.payload
    expect(payload).toMatchSnapshot()
    expect(payload).toHaveProperty('aud', ['TEST_DOMAIN', 'EXISTING_AUD'])
    expect(payload).not.toHaveProperty('nonce')
  })

  it('creates a valid Presentation JWT with challenge option', async () => {
    expect.assertions(4)
    const options: CreatePresentationOptions = {
      challenge: 'TEST_CHALLENGE',
    }

    const presentationJwt = await createVerifiablePresentationJwt(
      { ...presentationPayload, extra: 42 },
      holder,
      options
    )
    const decodedPresentation = await decodeJWT(presentationJwt)
    const { iat, ...payload } = decodedPresentation.payload
    expect(payload).toMatchSnapshot()
    expect(payload).not.toHaveProperty('aud')
    expect(payload).toHaveProperty('nonce', 'TEST_CHALLENGE')
    expect(payload).toHaveProperty('extra', 42)
  })

  it('creates a Presentation JWT with custom holder alg', async () => {
    const customHolder = { ...holder, alg: 'ES256K-R' }
    expect.assertions(1)
    const presentationJwt = await createVerifiablePresentationJwt({ ...presentationPayload, extra: 42 }, customHolder)
    const decodedPresentation = await decodeJWT(presentationJwt)
    expect(decodedPresentation.header).toEqual({ alg: 'ES256K-R', typ: 'JWT' })
  })

  it('creates a Presentation JWT with custom header options', async () => {
    expect.assertions(1)
    const options: CreatePresentationOptions = {
      header: {
        alg: 'ES256K-R',
        custom: 'field',
      },
    }

    const presentationJwt = await createVerifiablePresentationJwt(
      { ...presentationPayload, extra: 42 },
      holder,
      options
    )
    const decodedPresentation = await decodeJWT(presentationJwt)
    expect(decodedPresentation.header).toEqual({
      alg: 'ES256K-R',
      custom: 'field',
      typ: 'JWT',
    })
  })

  it('creates a valid Presentation JWT and does not overwrite an existing nonce property', async () => {
    expect.assertions(3)
    const options: CreatePresentationOptions = {
      challenge: 'TEST_CHALLENGE',
    }

    const presentationJwt = await createVerifiablePresentationJwt(
      { ...presentationPayload, nonce: 'EXISTING_NONCE' },
      holder,
      options
    )
    const decodedPresentation = await decodeJWT(presentationJwt)
    const { iat, ...payload } = decodedPresentation.payload
    expect(payload).toMatchSnapshot()
    expect(payload).not.toHaveProperty('aud')
    expect(payload).toHaveProperty('nonce', 'EXISTING_NONCE')
  })

  it('calls functions to validate required fields', async () => {
    expect.assertions(2 + presentationPayload.vp.verifiableCredential.length)
    await createVerifiablePresentationJwt(presentationPayload, holder)
    expect(mockValidateContext).toHaveBeenCalledWith(presentationPayload.vp['@context'])
    expect(mockValidateVpType).toHaveBeenCalledWith(presentationPayload.vp.type)
    for (const vc of presentationPayload.vp.verifiableCredential) {
      expect(mockValidateJwtFormat).toHaveBeenCalledWith(vc)
    }
  })
  it('creates a valid Presentation JWT if there are no credentials', async () => {
    expect.assertions(1)
    const presentationJwt = await createVerifiablePresentationJwt(
      {
        ...presentationPayload,
        vp: {
          '@context': presentationPayload.vp['@context'],
          type: presentationPayload.vp.type,
        },
      },
      holder
    )
    const decodedPresentation = await decodeJWT(presentationJwt)
    const { iat, ...payload } = decodedPresentation.payload
    expect(payload).toMatchSnapshot()
  })
  it('calls functions to validate optional fields if they are present', async () => {
    expect.assertions(1)
    const timestamp = Math.floor(new Date().getTime())
    await createVerifiablePresentationJwt(
      {
        ...presentationPayload,
        exp: timestamp,
      },
      holder
    )
    expect(mockValidateTimestamp).toHaveBeenCalledWith(timestamp)
  })
})

describe('verifyCredential', () => {
  it('verifies a valid Verifiable Credential', async () => {
    expect.assertions(2)
    const verified = await verifyCredential(VC_JWT, resolver)
    expect(verified.payload.vc).toBeDefined()
    expect(verified.verifiableCredential).toBeDefined()
  })

  it('verifies and converts a legacy format attestation into a Verifiable Credential', async () => {
    expect.assertions(1)
    // tslint:disable-next-line: max-line-length
    const LEGACY_FORMAT_ATTESTATION =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1NjM4MjQ4MDksImV4cCI6OTk2Mjk1MDI4Miwic3ViIjoiZGlkOmV0aHI6MHhmMTIzMmY4NDBmM2FkN2QyM2ZjZGFhODRkNmM2NmRhYzI0ZWZiMTk4IiwiY2xhaW0iOnsiZGVncmVlIjp7InR5cGUiOiJCYWNoZWxvckRlZ3JlZSIsIm5hbWUiOiJCYWNjYWxhdXLDqWF0IGVuIG11c2lxdWVzIG51bcOpcmlxdWVzIn19LCJpc3MiOiJkaWQ6ZXRocjoweGYzYmVhYzMwYzQ5OGQ5ZTI2ODY1ZjM0ZmNhYTU3ZGJiOTM1YjBkNzQifQ.OsKmaxoA2pt3_ixWK61BaMDc072g2PymBX_CCUSo-irvtIRUP5qBCcerhpASe5hOcTg5nNpNg0XYXnqyF9I4XwE'
    const verified = await verifyCredential(LEGACY_FORMAT_ATTESTATION, resolver)
    // expect(verified.payload.vc).toBeDefined()
    expect(verified.verifiableCredential).toBeDefined()
  })

  it('rejects an invalid JWT', () => {
    expect(verifyCredential('not a jwt', resolver)).rejects.toThrow()
  })
})

describe('verifyPresentation', () => {
  it('verifies a valid Presentation', async () => {
    expect.assertions(2)
    const verified = await verifyPresentation(PRESENTATION_JWT, resolver)
    expect(verified.payload.vp).toBeDefined()
    expect(verified.verifiablePresentation).toBeDefined()
  })

  it('rejects a Presentation without matching challenge', () => {
    const options: VerifyPresentationOptions = {
      challenge: 'TEST_CHALLENGE',
    }
    expect(verifyPresentation(PRESENTATION_JWT, resolver, options)).rejects.toThrow(
      'Presentation does not contain the mandatory challenge (JWT: nonce) for : TEST_CHALLENGE'
    )
  })

  it('rejects a Presentation without matching domain', () => {
    const options: VerifyPresentationOptions = {
      domain: 'TEST_DOMAIN',
    }
    expect(verifyPresentation(PRESENTATION_JWT, resolver, options)).rejects.toThrow(
      'Presentation does not contain the mandatory domain (JWT: aud) for : TEST_DOMAIN'
    )
  })

  it('rejects an invalid JWT', () => {
    expect(verifyPresentation('not a jwt', resolver)).rejects.toThrow()
  })
})

describe('verifyPresentationPayloadOptions', () => {
  it('verifies a payload with no options present', () => {
    expect(() => verifyPresentationPayloadOptions(presentationPayload, {})).not.toThrow()
  })

  it('verifies a payload with challenge options present', () => {
    const options: VerifyPresentationOptions = {
      challenge: 'TEST_CHALLENGE',
    }

    const payload = { nonce: 'TEST_CHALLENGE', ...presentationPayload }

    expect(() => verifyPresentationPayloadOptions(payload, options)).not.toThrow()
  })

  it('verifies a payload with domain options present (single aud)', () => {
    const options: VerifyPresentationOptions = {
      domain: 'TEST_DOMAIN',
    }

    const payload = { aud: 'TEST_DOMAIN', ...presentationPayload }

    expect(() => verifyPresentationPayloadOptions(payload, options)).not.toThrow()
  })

  it('verifies a payload with domain options present (array aud)', () => {
    const options: VerifyPresentationOptions = {
      domain: 'TEST_DOMAIN',
    }

    const payload = { aud: ['OTHER_AUD', 'TEST_DOMAIN'], ...presentationPayload }

    expect(() => verifyPresentationPayloadOptions(payload, options)).not.toThrow()
  })

  it('throws if payload is missing challenge', () => {
    const options: VerifyPresentationOptions = {
      challenge: 'TEST_CHALLENGE',
    }
    expect(() => verifyPresentationPayloadOptions(presentationPayload, options)).toThrow(
      'Presentation does not contain the mandatory challenge (JWT: nonce) for : TEST_CHALLENGE'
    )
  })

  it('throws if payload is missing domain', () => {
    const options: VerifyPresentationOptions = {
      domain: 'TEST_DOMAIN',
    }
    expect(() => verifyPresentationPayloadOptions(presentationPayload, options)).toThrow(
      'Presentation does not contain the mandatory domain (JWT: aud) for : TEST_DOMAIN'
    )
  })
})

describe('github #98', () => {
  it('verifies a JWT issued by a DID with publicKeyJwk', async () => {
    const did = `did:ion:long-form-mock`
    const privateKeyHex = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
    const pubKey = secp256k1.keyFromPrivate(privateKeyHex, 'hex').getPublic()
    const publicKeyJwk = {
      kty: 'EC',
      crv: 'secp256k1',
      x: u8a.toString(pubKey.getX().toBuffer(), 'base64url'),
      y: u8a.toString(pubKey.getY().toBuffer(), 'base64url'),
    }

    const localResolver: Resolvable = {
      resolve: (did: string) =>
        Promise.resolve({
          '@context': 'https://w3id.org/did-resolution/v1',
          didDocument: {
            id: did,
            '@context': ['https://www.w3.org/ns/did/v1'],
            verificationMethod: [
              {
                id: '#key-1',
                controller: '',
                type: 'EcdsaSecp256k1VerificationKey2019',
                publicKeyJwk,
              },
            ],
            authentication: ['#key-1'],
          },
          didDocumentMetadata: {},
          didResolutionMetadata: {},
        }),
    }

    const issuer: Issuer = {
      did,
      signer: ES256KSigner(hexToBytes(privateKeyHex), false),
      alg: 'ES256K',
    }

    const vcPayload: JwtCredentialPayload = {
      nbf: 1562950282,
      vc: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential'],
        credentialSubject: {
          degree: {
            type: 'Stemgerechtigd',
            name: 'Je mag stemmen',
          },
        },
      },
    }

    const vcJwt = await createVerifiableCredentialJwt(vcPayload, issuer, { header: { alg: 'ES256K' } })

    const verifiedVC = await verifyCredential(vcJwt, localResolver, { header: { alg: 'ES256K' } })
    expect(verifiedVC.issuer).toEqual('did:ion:long-form-mock')
  })
})
