import faker from 'faker'

jest.mock('../index')
import { VerifiableCredentialBuilder } from '../VerifiableCredential'
import { createVerifiableCredential } from '../index'
import { Signer } from 'did-jwt'
import { DEFAULT_CONTEXT, DEFAULT_TYPE } from '../constants'
import { CredentialSubject } from '../types'

const mockedCreateVerifiableCredential = (createVerifiableCredential as unknown) as jest.Mock<
  typeof createVerifiableCredential
>

const DID_A = 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198'
const DID_B = 'did:ethr:0x435df3eda57154cf8cf7926079881f2912f54db4'
const SIGNER: Signer = async (data: string) => 'signature'
const CREDENTIAL_SUBJECT: CredentialSubject = { name: 'test' }
const now = () => Math.floor(Date.now() / 1000)

describe('VerifiableCredential', () => {
  let vc: VerifiableCredentialBuilder

  beforeEach(() => {
    jest.resetAllMocks()
    vc = new VerifiableCredentialBuilder()
  })

  describe('constructor', () => {
    it('returns something', () => {
      expect(vc).toBeTruthy()
    })
    it('sets a default context', () => {
      expect(vc.context).toEqual(['https://www.w3.org/2018/credentials/v1'])
    })
    it('sets a default type', () => {
      expect(vc.type).toEqual(['VerifiableCredential'])
    })
  })

  describe('build', () => {
    describe('when required attributes have been set', () => {
      beforeEach(() => {
        vc.setSigner(SIGNER)
          .setIssuer(DID_A)
          .setSubject(DID_B)
          .setCredentialSubject(CREDENTIAL_SUBJECT)
      })
      it('calls createVerifiableCredential with required JWT payload', () => {
        vc.build()
        expect(mockedCreateVerifiableCredential).toHaveBeenCalledWith(
          expect.objectContaining({
            sub: DID_B,
            vc: expect.objectContaining({
              '@context': [DEFAULT_CONTEXT],
              type: [DEFAULT_TYPE],
              credentialSubject: CREDENTIAL_SUBJECT
            })
          }),
          {
            did: DID_A,
            signer: SIGNER
          }
        )
      })
      it('calls createVerifiableCredential with nbf in the payload if validFrom has been set', () => {
        const timestamp = now()
        vc.setValidFrom(timestamp).build()
        expect(mockedCreateVerifiableCredential).toHaveBeenCalledWith(
          expect.objectContaining({
            nbf: timestamp
          }),
          expect.anything()
        )
      })
      it('calls createVerifiableCredential with exp in the payload if validUntil has been set', () => {
        const timestamp = now()
        vc.setValidUntil(timestamp).build()
        expect(mockedCreateVerifiableCredential).toHaveBeenCalledWith(
          expect.objectContaining({
            exp: timestamp
          }),
          expect.anything()
        )
      })
      it('calls createVerifiableCredential with jti in the payload if id has been set', () => {
        const id = faker.random.word()
        vc.setId(id).build()
        expect(mockedCreateVerifiableCredential).toHaveBeenCalledWith(
          expect.objectContaining({
            jti: id
          }),
          expect.anything()
        )
      })
      it('calculates exp using validFrom and expiresIn if validUntil has not been set', () => {
        const timestamp = now()
        const interval = 60000
        vc.setValidFrom(timestamp)
          .expiresIn(interval)
          .build()
        expect(mockedCreateVerifiableCredential).toHaveBeenCalledWith(
          expect.objectContaining({
            nbf: timestamp,
            exp: timestamp + interval
          }),
          expect.anything()
        )
      })
      it('does not set exp if expiresIn has been set but validFrom has not', () => {
        vc.expiresIn(100).build()
        const args = mockedCreateVerifiableCredential.mock.calls[0]
        expect(args[0]).not.toHaveProperty('nbf')
        expect(args[0]).not.toHaveProperty('exp')
      })
      it('sets exp to validUntil over calculating it from expiresIn', () => {
        const timestamp = now()
        const validUntil = timestamp + 2000
        vc.setValidUntil(validUntil)
          .setValidFrom(timestamp)
          .expiresIn(1000)
          .build()
        expect(mockedCreateVerifiableCredential).toHaveBeenCalledWith(
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
        vc
          .setIssuer(DID_A)
          .setSubject(DID_B)
          .setCredentialSubject(CREDENTIAL_SUBJECT)
          .build()
      ).rejects.toThrowErrorMatchingSnapshot()
    })
    it('rejects with an error if issuer has not been set', () => {
      return expect(
        vc
          .setSigner(SIGNER)
          .setSubject(DID_B)
          .setCredentialSubject(CREDENTIAL_SUBJECT)
          .build()
      ).rejects.toThrowErrorMatchingSnapshot()
    })
    it('rejects with an error if subject has not been set', () => {
      return expect(
        vc
          .setSigner(SIGNER)
          .setIssuer(DID_A)
          .setCredentialSubject(CREDENTIAL_SUBJECT)
          .build()
      ).rejects.toThrowErrorMatchingSnapshot()
    })
    it('rejects with an error if credentialSubject has not been set', () => {
      return expect(
        vc
          .setSigner(SIGNER)
          .setIssuer(DID_A)
          .setSubject(DID_B)
          .build()
      ).rejects.toThrowErrorMatchingSnapshot()
    })
  })

  describe('setSigner', () => {
    it('sets the signer of the vc', () => {
      expect(vc.setSigner(SIGNER).signer).toEqual(SIGNER)
    })
  })

  describe('setSubject', () => {
    it('sets the subject of the vc', () => {
      expect(vc.setSubject(DID_A).subject).toEqual(DID_A)
    })
  })

  describe('setIssuer', () => {
    it('sets the issuer of the vc', () => {
      expect(vc.setIssuer(DID_A).issuer).toEqual(DID_A)
    })
  })

  describe('setCredentialSubject', () => {
    it('sets the credential subject of the vc', () => {
      const value = { [faker.random.word()]: faker.random.word() }
      expect(vc.setCredentialSubject(value).credentialSubject).toEqual(value)
    })
  })

  describe('addContext', () => {
    it('adds a context to the vc', () => {
      const value = faker.random.word()
      const n = vc.context.length
      vc.addContext(value)
      expect(vc.context.length).toEqual(n + 1)
      expect(vc.context.includes(value)).toBeTruthy()
    })
  })

  describe('addType', () => {
    it('adds a type to the vc', () => {
      const value = faker.random.word()
      const n = vc.context.length
      vc.addType(value)
      expect(vc.type.length).toEqual(n + 1)
      expect(vc.type.includes(value)).toBeTruthy()
    })
  })

  describe('setValidFrom', () => {
    it('sets the validFrom timestamp of the vc', () => {
      const value = faker.random.number()
      expect(vc.setValidFrom(value).validFrom).toEqual(value)
    })
  })

  describe('setValidUntil', () => {
    it('sets the validUntil timestamp of the vc', () => {
      const value = faker.random.number()
      expect(vc.setValidUntil(value).validUntil).toEqual(value)
    })
  })

  describe('setId', () => {
    it('it sets the id of the vc', () => {
      const value = faker.random.word()
      expect(vc.setId(value).id).toEqual(value)
    })
  })
})
