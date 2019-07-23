import EthrDID from 'ethr-did'
import { createVerifiableCredential, createPresentation } from '../index'
import { decodeJWT } from 'did-jwt'

const issuerIdentity = {
  did: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
  address: '0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
  privateKey: 'd8b595680851765f38ea5405129244ba3cbad84467d190859f4c8b20c1ff6c75'
}

const did = new EthrDID(issuerIdentity)

const exampleVcJwt =
  `eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1NjM4MjQ4MDksInN1YiI6ImRp
  ZDpldGhyOjB4MTIzNDU2NzgiLCJuYmYiOjE1NjI5NTAyODI4MDEsInZjIjp7IkBjb250ZXh0IjpbIm
  h0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93d3cudzMub3Jn
  LzIwMTgvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudG
  lhbCIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImRl
  Z3JlZSI6eyJ0eXBlIjoiQmFjaGVsb3JEZWdyZWUiLCJuYW1lIjoiQmFjY2FsYXVyw6lhdCBlbiBtdX
  NpcXVlcyBudW3DqXJpcXVlcyJ9fX0sImlzcyI6ImRpZDpldGhyOjB4ZjEyMzJmODQwZjNhZDdkMjNm
  Y2RhYTg0ZDZjNjZkYWMyNGVmYjE5OCJ9.uYSRgDNmZnz0k5rORCBIIzEahVask5eQ2PFZI2_JAatvr
  pZ2t_3iTvPmBy6Kzt2W20fw5jUJ7GoZXJqoba4UVQA`

describe('createVerifiableCredential', () => {
  it('creates a valid Verifiable Credential JWT with required fields', async () => {
    const vcJwt = await createVerifiableCredential(
      {
        sub: 'did:ethr:0x435df3eda57154cf8cf7926079881f2912f54db4',
        nbf: 1562950282,
        vc: {
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://www.w3.org/2018/credentials/examples/v1'
          ],
          type: ['VerifiableCredential', 'UniversityDegreeCredential'],
          credentialSubject: {
            degree: {
              type: 'BachelorDegree',
              name: 'Baccalauréat en musiques numériques'
            }
          }
        }
      },
      did
    )
    const decodedVc = await decodeJWT(vcJwt)
    const { iat, ...payload } = decodedVc.payload
    expect(payload).toMatchSnapshot()
  })
})

describe('createPresentation', () => {
  it('creates a valid Presentation JWT with required fields', async () => {
    const presentationJwt = await createPresentation(
      {
        vp: {
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://www.w3.org/2018/credentials/examples/v1'
          ],
          type: ['VerifiableCredential'],
          verifiableCredential: [exampleVcJwt]
        }
      },
      did
    )
    const decodedPresentation = await decodeJWT(presentationJwt)
    const { iat, ...payload } = decodedPresentation.payload
    expect(payload).toMatchSnapshot()
  })
})
