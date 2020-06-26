import EthrDID from 'ethr-did'
import {
  createVerifiableCredentialJwt,
  verifyCredential,
  verifyPresentation,
  createVerifiablePresentationJwt
} from '../index'
import { decodeJWT } from 'did-jwt'
import { DEFAULT_VC_TYPE, DEFAULT_VP_TYPE, DEFAULT_CONTEXT } from '../constants'
import {
  validateContext,
  validateJwtFormat,
  validateTimestamp,
  validateVcType,
  validateVpType,
  validateCredentialSubject
} from '../validators'
import { DIDDocument } from 'did-resolver'

jest.mock('../validators')

const mockValidateJwtFormat = <jest.Mock<typeof validateJwtFormat>>validateJwtFormat
const mockValidateTimestamp = <jest.Mock<typeof validateTimestamp>>validateTimestamp

const mockValidateContext = <jest.Mock<typeof validateContext>>validateContext
const mockValidateVcType = <jest.Mock<typeof validateVcType>>validateVcType
const mockValidateVpType = <jest.Mock<typeof validateVpType>>validateVpType
const mockValidateCredentialSubject = <jest.Mock<typeof validateCredentialSubject>>validateCredentialSubject

const DID_A = 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198'
const DID_B = 'did:ethr:0x435df3eda57154cf8cf7926079881f2912f54db4'
const EXTRA_CONTEXT_A = 'https://www.w3.org/2018/credentials/examples/v1'
const EXTRA_TYPE_A = 'UniversityDegreeCredential'
const VC_JWT =
  // tslint:disable-next-line: max-line-length
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1NjY5MjMyNjksInN1YiI6ImRpZDpldGhyOjB4NDM1ZGYzZWRhNTcxNTRjZjhjZjc5MjYwNzk4ODFmMjkxMmY1NGRiNCIsIm5iZiI6MTU2Mjk1MDI4MiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy9leGFtcGxlcy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVW5pdmVyc2l0eURlZ3JlZUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiZGVncmVlIjp7InR5cGUiOiJCYWNoZWxvckRlZ3JlZSIsIm5hbWUiOiJCYWNjYWxhdXLDqWF0IGVuIG11c2lxdWVzIG51bcOpcmlxdWVzIn19fSwiaXNzIjoiZGlkOmV0aHI6MHhmMTIzMmY4NDBmM2FkN2QyM2ZjZGFhODRkNmM2NmRhYzI0ZWZiMTk4In0.rFRZUCw3Gu0E_I5ZJbrbpuHV1JNAwpXaiFZuJ59iJ-TNqufr4cuGCBEECFbgQF-lpNm51cqSx3Y2IdWaUpatJQA'
const BASIC_JWT =
  // tslint:disable-next-line: max-line-length
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1NjcwMjQ5NzQsIm5hbWUiOiJib2IiLCJpc3MiOiJkaWQ6ZXRocjoweGYzYmVhYzMwYzQ5OGQ5ZTI2ODY1ZjM0ZmNhYTU3ZGJiOTM1YjBkNzQifQ.2lP3YDOBj9pirxmPAJojQ-q6Rp7w4wA59ZLm19HdqC2leuxlZEQ5w8y0tzpH8n2I25aQ0vVB6j6TimCNLFasqQE'
const PRESENTATION_JWT =
  // tslint:disable-next-line: max-line-length
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1NjgwNDUyNjMsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6WyJleUowZVhBaU9pSktWMVFpTENKaGJHY2lPaUpGVXpJMU5rc3RVaUo5LmV5SnBZWFFpT2pFMU5qWTVNak15Tmprc0luTjFZaUk2SW1ScFpEcGxkR2h5T2pCNE5ETTFaR1l6WldSaE5UY3hOVFJqWmpoalpqYzVNall3TnprNE9ERm1Namt4TW1ZMU5HUmlOQ0lzSW01aVppSTZNVFUyTWprMU1ESTRNaXdpZG1NaU9uc2lRR052Ym5SbGVIUWlPbHNpYUhSMGNITTZMeTkzZDNjdWR6TXViM0puTHpJd01UZ3ZZM0psWkdWdWRHbGhiSE12ZGpFaUxDSm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3ZNakF4T0M5amNtVmtaVzUwYVdGc2N5OWxlR0Z0Y0d4bGN5OTJNU0pkTENKMGVYQmxJanBiSWxabGNtbG1hV0ZpYkdWRGNtVmtaVzUwYVdGc0lpd2lWVzVwZG1WeWMybDBlVVJsWjNKbFpVTnlaV1JsYm5ScFlXd2lYU3dpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaVpHVm5jbVZsSWpwN0luUjVjR1VpT2lKQ1lXTm9aV3h2Y2tSbFozSmxaU0lzSW01aGJXVWlPaUpDWVdOallXeGhkWExEcVdGMElHVnVJRzExYzJseGRXVnpJRzUxYmNPcGNtbHhkV1Z6SW4xOWZTd2lhWE56SWpvaVpHbGtPbVYwYUhJNk1IaG1NVEl6TW1ZNE5EQm1NMkZrTjJReU0yWmpaR0ZoT0RSa05tTTJObVJoWXpJMFpXWmlNVGs0SW4wLnJGUlpVQ3czR3UwRV9JNVpKYnJicHVIVjFKTkF3cFhhaUZadUo1OWlKLVROcXVmcjRjdUdDQkVFQ0ZiZ1FGLWxwTm01MWNxU3gzWTJJZFdhVXBhdEpRQSJdfSwiaXNzIjoiZGlkOmV0aHI6MHhmMTIzMmY4NDBmM2FkN2QyM2ZjZGFhODRkNmM2NmRhYzI0ZWZiMTk4In0.bWZyEpLsx0u6v-UIcQf9TVMde1gTFsn091BY-TViUuRoUNsNQFzN-ViNNCvoTQ-swSHwbELW7-EGPAcHLOMiIwE'

const did = new EthrDID({
  did: DID_A,
  address: '0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
  privateKey: 'd8b595680851765f38ea5405129244ba3cbad84467d190859f4c8b20c1ff6c75'
})
const verifiableCredentialPayload = {
  sub: DID_B,
  nbf: 1562950282,
  vc: {
    '@context': [DEFAULT_CONTEXT, EXTRA_CONTEXT_A],
    type: [DEFAULT_VC_TYPE, EXTRA_TYPE_A],
    credentialSubject: {
      degree: {
        type: 'BachelorDegree',
        name: 'Baccalauréat en musiques numériques'
      }
    }
  }
}
const presentationPayload = {
  vp: {
    '@context': [DEFAULT_CONTEXT, EXTRA_CONTEXT_A],
    type: [DEFAULT_VP_TYPE],
    verifiableCredential: [VC_JWT]
  }
}
const resolver = {
  resolve: (did: string) =>
    Promise.resolve({
      '@context': 'https://w3id.org/did/v1',
      id: `${did}`,
      publicKey: [
        {
          id: `${did}#owner`,
          type: 'Secp256k1VerificationKey2018',
          ethereumAddress: `${did.substring(9)}`,
          owner: did
        }
      ]
    } as DIDDocument)
}

beforeEach(() => {
  jest.resetAllMocks()
})

describe('createVerifiableCredential', () => {
  it('creates a valid Verifiable Credential JWT with required fields', async () => {
    const vcJwt = await createVerifiableCredentialJwt(verifiableCredentialPayload, did)
    const decodedVc = await decodeJWT(vcJwt)
    const { iat, ...payload } = decodedVc.payload
    expect(payload).toMatchSnapshot()
  })
  it('creates a valid Verifiable Credential JWT with extra optional fields', async () => {
    const vcJwt = await createVerifiableCredentialJwt({ ...verifiableCredentialPayload, extra: 42 }, did)
    const decodedVc = await decodeJWT(vcJwt)
    const { iat, ...payload } = decodedVc.payload
    expect(payload).toMatchSnapshot()
  })
  it('calls functions to validate required fields', async () => {
    await createVerifiableCredentialJwt(verifiableCredentialPayload, did)
    expect(mockValidateTimestamp).toHaveBeenCalledWith(verifiableCredentialPayload.nbf)
    expect(mockValidateContext).toHaveBeenCalledWith(verifiableCredentialPayload.vc['@context'])
    expect(mockValidateVcType).toHaveBeenCalledWith(verifiableCredentialPayload.vc.type)
    expect(mockValidateCredentialSubject).toHaveBeenCalledWith(verifiableCredentialPayload.vc.credentialSubject)
  })
  it('calls functions to validate optional fields if they are present', async () => {
    const timestamp = Math.floor(new Date().getTime())
    await createVerifiableCredentialJwt({ ...verifiableCredentialPayload, exp: timestamp }, did)
    expect(mockValidateTimestamp).toHaveBeenCalledWith(timestamp)
  })
})

describe('createPresentation', () => {
  it('creates a valid Presentation JWT with required fields', async () => {
    const presentationJwt = await createVerifiablePresentationJwt(presentationPayload, did)
    const decodedPresentation = await decodeJWT(presentationJwt)
    const { iat, ...payload } = decodedPresentation.payload
    expect(payload).toMatchSnapshot()
  })
  it('creates a valid Presentation JWT with extra optional fields', async () => {
    const presentationJwt = await createVerifiablePresentationJwt({ ...presentationPayload, extra: 42 }, did)
    const decodedPresentation = await decodeJWT(presentationJwt)
    const { iat, ...payload } = decodedPresentation.payload
    expect(payload).toMatchSnapshot()
  })
  it('calls functions to validate required fields', async () => {
    await createVerifiablePresentationJwt(presentationPayload, did)
    expect(mockValidateContext).toHaveBeenCalledWith(presentationPayload.vp['@context'])
    expect(mockValidateVpType).toHaveBeenCalledWith(presentationPayload.vp.type)
    for (const vc of presentationPayload.vp.verifiableCredential) {
      expect(mockValidateJwtFormat).toHaveBeenCalledWith(vc)
    }
  })
  it('throws a TypeError if vp.verifiableCredential is empty', async () => {
    await expect(
      createVerifiablePresentationJwt(
        {
          ...presentationPayload,
          vp: {
            '@context': presentationPayload.vp['@context'],
            type: presentationPayload.vp.type,
            verifiableCredential: []
          }
        },
        did
      )
    ).rejects.toThrow(TypeError)
  })
  it('calls functions to validate optional fields if they are present', async () => {
    const timestamp = Math.floor(new Date().getTime())
    await createVerifiablePresentationJwt(
      {
        ...presentationPayload,
        exp: timestamp
      },
      did
    )
    expect(mockValidateTimestamp).toHaveBeenCalledWith(timestamp)
  })
})

describe('verifyCredential', () => {
  it('verifies a valid Verifiable Credential', async () => {
    const verified = await verifyCredential(VC_JWT, resolver)
    expect(verified.payload.vc).toBeDefined()
    expect(verified.verifiableCredential).toBeDefined()
  })

  it('verifies and converts a legacy format attestation into a Verifiable Credential', async () => {
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
    const verified = await verifyPresentation(PRESENTATION_JWT, resolver)
    expect(verified.payload.vp).toBeDefined()
    expect(verified.verifiablePresentation).toBeDefined()
  })

  it('rejects an invalid JWT', () => {
    expect(verifyPresentation('not a jwt', resolver)).rejects.toThrow()
  })

  it('rejects a valid JWT that is missing VP attributes', () => {
    expect(verifyPresentation(BASIC_JWT, resolver)).rejects.toThrow()
  })
})
