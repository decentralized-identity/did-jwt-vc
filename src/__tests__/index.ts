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

export const DID_A = 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198'
export const DID_B = 'did:ethr:0x435df3eda57154cf8cf7926079881f2912f54db4'
export const INVALID_DID = 'this is not a valid did'
export const INVALID_TIMESTAMP = 1563905309015
export const EXTRA_CONTEXT_A = 'https://www.w3.org/2018/credentials/examples/v1'
export const EXTRA_CONTEXT_B = 'custom vc context'
export const EXTRA_TYPE_A = 'UniversityDegreeCredential'
export const EXTRA_TYPE_B = 'custom vc type'
export const VC_JWT =
  // tslint:disable-next-line: max-line-length
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1NjM4MjQ4MDksInN1YiI6ImRpZDpldGhyOjB4MTIzNDU2NzgiLCJuYmYiOjE1NjI5NTAyODI4MDEsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImRlZ3JlZSI6eyJ0eXBlIjoiQmFjaGVsb3JEZWdyZWUiLCJuYW1lIjoiQmFjY2FsYXVyw6lhdCBlbiBtdXNpcXVlcyBudW3DqXJpcXVlcyJ9fX0sImlzcyI6ImRpZDpldGhyOjB4ZjEyMzJmODQwZjNhZDdkMjNmY2RhYTg0ZDZjNjZkYWMyNGVmYjE5OCJ9.uYSRgDNmZnz0k5rORCBIIzEahVask5eQ2PFZI2_JAatvrpZ2t_3iTvPmBy6Kzt2W20fw5jUJ7GoZXJqoba4UVQA'

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
