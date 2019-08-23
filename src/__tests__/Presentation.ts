jest.mock('../index')
import { createPresentation } from '../index'
import { PresentationBuilder } from '../Presentation'
import { DEFAULT_CONTEXT, DEFAULT_TYPE } from '../constants'
import { Signer } from 'did-jwt'
import faker = require('faker')

const mockedCreatePresentation = (createPresentation as unknown) as jest.Mock<
  typeof createPresentation
>
const DID_A = 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198'
const DID_B = 'did:ethr:0x435df3eda57154cf8cf7926079881f2912f54db4'
const VC_JWT =
  // tslint:disable-next-line: max-line-length
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1NjM4MjQ4MDksInN1YiI6ImRpZDpldGhyOjB4MTIzNDU2NzgiLCJuYmYiOjE1NjI5NTAyODI4MDEsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImRlZ3JlZSI6eyJ0eXBlIjoiQmFjaGVsb3JEZWdyZWUiLCJuYW1lIjoiQmFjY2FsYXVyw6lhdCBlbiBtdXNpcXVlcyBudW3DqXJpcXVlcyJ9fX0sImlzcyI6ImRpZDpldGhyOjB4ZjEyMzJmODQwZjNhZDdkMjNmY2RhYTg0ZDZjNjZkYWMyNGVmYjE5OCJ9.uYSRgDNmZnz0k5rORCBIIzEahVask5eQ2PFZI2_JAatvrpZ2t_3iTvPmBy6Kzt2W20fw5jUJ7GoZXJqoba4UVQA'
const SIGNER: Signer = async (data: string) => 'signature'
const now = () => Math.floor(Date.now() / 1000)

describe('Presentation', () => {
  let p: PresentationBuilder

  beforeEach(() => {
    jest.resetAllMocks()
    p = new PresentationBuilder()
  })

  describe('constructor', () => {
    it('returns something', () => {
      expect(p).toBeTruthy()
    })
    it('sets a default context', () => {
      expect(p.context).toEqual([DEFAULT_CONTEXT])
    })
    it('sets a default type', () => {
      expect(p.type).toEqual([DEFAULT_TYPE])
    })
  })

  describe('build', () => {
    describe('when required attributes have been set', () => {
      beforeEach(() => {
        p.setSigner(SIGNER)
          .setHolder(DID_A)
          .addVerifiableCredential(VC_JWT)
      })
      it('calls createPresentation with required JWT payload', () => {
        p.build()
        expect(mockedCreatePresentation).toHaveBeenCalledWith(
          expect.objectContaining({
            vp: expect.objectContaining({
              '@context': [DEFAULT_CONTEXT],
              type: [DEFAULT_TYPE],
              verifiableCredential: [VC_JWT]
            })
          }),
          {
            did: DID_A,
            signer: SIGNER
          }
        )
      })
      it('calls createPresentation with aud in the payload if audience has been set', () => {
        p.setAudience(DID_B).build()
        expect(mockedCreatePresentation).toHaveBeenCalledWith(
          expect.objectContaining({
            aud: DID_B
          }),
          expect.anything()
        )
      })
      it('calls createPresentation with nbf in the payload if validFrom has been set', () => {
        const timestamp = now()
        p.setValidFrom(timestamp).build()
        expect(mockedCreatePresentation).toHaveBeenCalledWith(
          expect.objectContaining({
            nbf: timestamp
          }),
          expect.anything()
        )
      })
      it('calls createPresentation with exp in the payload if validUntil has been set', () => {
        const timestamp = now()
        p.setValidUntil(timestamp).build()
        expect(mockedCreatePresentation).toHaveBeenCalledWith(
          expect.objectContaining({
            exp: timestamp
          }),
          expect.anything()
        )
      })
      it('calls createPresentation with jti in the payload if id has been set', () => {
        const id = faker.random.word()
        p.setId(id).build()
        expect(mockedCreatePresentation).toHaveBeenCalledWith(
          expect.objectContaining({
            jti: id
          }),
          expect.anything()
        )
      })
      it('calculates exp using validFrom and expiresIn if validUntil has not been set', () => {
        const timestamp = now()
        const interval = 60000
        p.setValidFrom(timestamp)
          .expiresIn(interval)
          .build()
        expect(mockedCreatePresentation).toHaveBeenCalledWith(
          expect.objectContaining({
            nbf: timestamp,
            exp: timestamp + interval
          }),
          expect.anything()
        )
      })
      it('does not set exp if expiresIn has been set but validFrom has not', () => {
        p.expiresIn(100).build()
        const args = mockedCreatePresentation.mock.calls[0]
        expect(args[0]).not.toHaveProperty('nbf')
        expect(args[0]).not.toHaveProperty('exp')
      })
      it('sets exp to validUntil over calculating it from expiresIn', () => {
        const timestamp = now()
        const validUntil = timestamp + 2000
        p.setValidUntil(validUntil)
          .setValidFrom(timestamp)
          .expiresIn(1000)
          .build()
        expect(mockedCreatePresentation).toHaveBeenCalledWith(
          expect.objectContaining({
            nbf: timestamp,
            exp: validUntil
          }),
          expect.anything()
        )
      })
    })
    it('rejects with an error if signer has not been set', () => {
      return expect(
        p
          .setHolder(DID_A)
          .addVerifiableCredential(VC_JWT)
          .build()
      ).rejects.toThrowErrorMatchingSnapshot()
    })
    it('rejects with an error if issuer has not been set', () => {
      return expect(
        p
          .setSigner(SIGNER)
          .addVerifiableCredential(VC_JWT)
          .build()
      ).rejects.toThrowErrorMatchingSnapshot()
    })
    it('rejects with an error if no verifiableCredentials have been added', () => {
      return expect(
        p
          .setHolder(DID_A)
          .setSigner(SIGNER)
          .build()
      ).rejects.toThrowErrorMatchingSnapshot()
    })
  })

  describe('setSigner', () => {
    it('sets the signer of the presentation', () => {
      expect(p.setSigner(SIGNER).signer).toEqual(SIGNER)
    })
  })

  describe('setAudience', () => {
    it('sets the audience of the presentation', () => {
      expect(p.setAudience(DID_A).audience).toEqual(DID_A)
    })
  })

  describe('setIssuer', () => {
    it('sets the issuer of the presentation', () => {
      expect(p.setHolder(DID_A).holder).toEqual(DID_A)
    })
  })

  describe('addVerifiableCredential', () => {
    it('adds a verifiableCredential to the presentation', () => {
      const value = faker.random.word()
      const n = p.verifiableCredentials.length
      p.addVerifiableCredential(value)
      expect(p.verifiableCredentials.length).toEqual(n + 1)
      expect(p.verifiableCredentials.includes(value)).toBeTruthy()
    })
  })

  describe('addContext', () => {
    it('adds a context to the presentation', () => {
      const value = faker.random.word()
      const n = p.context.length
      p.addContext(value)
      expect(p.context.length).toEqual(n + 1)
      expect(p.context.includes(value)).toBeTruthy()
    })
  })

  describe('addType', () => {
    it('adds a type to the presentation', () => {
      const value = faker.random.word()
      const n = p.context.length
      p.addType(value)
      expect(p.type.length).toEqual(n + 1)
      expect(p.type.includes(value)).toBeTruthy()
    })
  })

  describe('setValidFrom', () => {
    it('sets the validFrom timestamp of the presentation', () => {
      const value = faker.random.number()
      expect(p.setValidFrom(value).validFrom).toEqual(value)
    })
  })

  describe('setValidUntil', () => {
    it('sets the validUntil timestamp of the presentation', () => {
      const value = faker.random.number()
      expect(p.setValidUntil(value).validUntil).toEqual(value)
    })
  })

  describe('setId', () => {
    it('it sets the id of the presentation', () => {
      const value = faker.random.word()
      expect(p.setId(value).id).toEqual(value)
    })
  })
})
