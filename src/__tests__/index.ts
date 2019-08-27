import EthrDID from 'ethr-did'
import { createVerifiableCredential, createPresentation } from '../index'
import { decodeJWT } from 'did-jwt'
import { DEFAULT_TYPE, DEFAULT_CONTEXT } from '../constants'
import {
  validateDidFormat,
  validateContext,
  validateJwtFormat,
  validateTimestamp,
  validateType,
  validateCredentialSubject
} from '../validators'
jest.mock('../validators')

const mockValidateDidFormat = <jest.Mock<typeof validateDidFormat>>(
  validateDidFormat
)
const mockValidateJwtFormat = <jest.Mock<typeof validateJwtFormat>>(
  validateJwtFormat
)
const mockValidateTimestamp = <jest.Mock<typeof validateTimestamp>>(
  validateTimestamp
)

const mockValidateContext = <jest.Mock<typeof validateContext>>validateContext
const mockValidateType = <jest.Mock<typeof validateType>>validateType
const mockValidateCredentialSubject = <jest.Mock<typeof validateCredentialSubject>>validateCredentialSubject

const DID_A = 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198'
const DID_B = 'did:ethr:0x435df3eda57154cf8cf7926079881f2912f54db4'
const INVALID_DID = 'this is not a valid did'
const EXTRA_CONTEXT_A = 'https://www.w3.org/2018/credentials/examples/v1'
const EXTRA_TYPE_A = 'UniversityDegreeCredential'
const VC_JWT =
  // tslint:disable-next-line: max-line-length
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1NjY5MjMyNjksInN1YiI6ImRpZDpldGhyOjB4NDM1ZGYzZWRhNTcxNTRjZjhjZjc5MjYwNzk4ODFmMjkxMmY1NGRiNCIsIm5iZiI6MTU2Mjk1MDI4MiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy9leGFtcGxlcy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVW5pdmVyc2l0eURlZ3JlZUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiZGVncmVlIjp7InR5cGUiOiJCYWNoZWxvckRlZ3JlZSIsIm5hbWUiOiJCYWNjYWxhdXLDqWF0IGVuIG11c2lxdWVzIG51bcOpcmlxdWVzIn19fSwiaXNzIjoiZGlkOmV0aHI6MHhmMTIzMmY4NDBmM2FkN2QyM2ZjZGFhODRkNmM2NmRhYzI0ZWZiMTk4In0.rFRZUCw3Gu0E_I5ZJbrbpuHV1JNAwpXaiFZuJ59iJ-TNqufr4cuGCBEECFbgQF-lpNm51cqSx3Y2IdWaUpatJQA'

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
    type: [DEFAULT_TYPE, EXTRA_TYPE_A],
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
    type: [DEFAULT_TYPE],
    verifiableCredential: [VC_JWT]
  }
}

beforeEach(() => {
  jest.resetAllMocks()
})

describe('createVerifiableCredential', () => {
  it('creates a valid Verifiable Credential JWT with required fields', async () => {
    const vcJwt = await createVerifiableCredential(
      verifiableCredentialPayload,
      did
    )
    const decodedVc = await decodeJWT(vcJwt)
    const { iat, ...payload } = decodedVc.payload
    expect(payload).toMatchSnapshot()
  })
  it('creates a valid Verifiable Credential JWT with extra optional fields', async () => {
    const vcJwt = await createVerifiableCredential(
      { ...verifiableCredentialPayload, extra: 42 },
      did
    )
    const decodedVc = await decodeJWT(vcJwt)
    const { iat, ...payload } = decodedVc.payload
    expect(payload).toMatchSnapshot()
  })
  it('calls functions to validate required fields', async () => {
    await createVerifiableCredential(verifiableCredentialPayload, did)
    expect(mockValidateDidFormat).toHaveBeenCalledWith(
      verifiableCredentialPayload.sub
    )
    expect(mockValidateDidFormat).toHaveBeenCalledWith(did.did)
    expect(mockValidateTimestamp).toHaveBeenCalledWith(
      verifiableCredentialPayload.nbf
    )
    expect(mockValidateContext).toHaveBeenCalledWith(
      verifiableCredentialPayload.vc['@context']
    )
    expect(mockValidateType).toHaveBeenCalledWith(
      verifiableCredentialPayload.vc.type
    )
    expect(mockValidateCredentialSubject).toHaveBeenCalledWith(verifiableCredentialPayload.vc.credentialSubject)
  })
  it('calls functions to validate optional fields if they are present', async () => {
    const timestamp = Math.floor(new Date().getTime())
    await createVerifiableCredential(
      { ...verifiableCredentialPayload, exp: timestamp },
      did
    )
    expect(mockValidateTimestamp).toHaveBeenCalledWith(timestamp)
  })
})

describe('createPresentation', () => {
  it('creates a valid Presentation JWT with required fields', async () => {
    const presentationJwt = await createPresentation(presentationPayload, did)
    const decodedPresentation = await decodeJWT(presentationJwt)
    const { iat, ...payload } = decodedPresentation.payload
    expect(payload).toMatchSnapshot()
  })
  it('creates a valid Presentation JWT with extra optional fields', async () => {
    const presentationJwt = await createPresentation(
      { ...presentationPayload, extra: 42 },
      did
    )
    const decodedPresentation = await decodeJWT(presentationJwt)
    const { iat, ...payload } = decodedPresentation.payload
    expect(payload).toMatchSnapshot()
  })
  it('calls functions to validate required fields', async () => {
    await createPresentation(presentationPayload, did)
    expect(mockValidateDidFormat).toHaveBeenCalledWith(did.did)
    expect(mockValidateContext).toHaveBeenCalledWith(
      presentationPayload.vp['@context']
    )
    expect(mockValidateType).toHaveBeenCalledWith(presentationPayload.vp.type)
    for (const vc of presentationPayload.vp.verifiableCredential) {
      expect(mockValidateJwtFormat).toHaveBeenCalledWith(vc)
    }
  })
  it('throws a TypeError if vp.verifiableCredential is empty', async () => {
    await expect(
      createPresentation(
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
    const aud = INVALID_DID
    const timestamp = Math.floor(new Date().getTime())
    await createPresentation(
      {
        ...presentationPayload,
        aud: INVALID_DID,
        exp: timestamp
      },
      did
    )
    expect(mockValidateDidFormat).toHaveBeenCalledWith(aud)
    expect(mockValidateTimestamp).toHaveBeenCalledWith(timestamp)
  })
})
