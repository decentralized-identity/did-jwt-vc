import faker from 'faker'

jest.mock('../validators')
jest.mock('../index')
import { VerifiableCredentialBuilder } from '../VerifiableCredential'
import {
  validateDidFormat,
  validateCredentialSubject,
  validateTimestamp
} from '../validators'
import { createVerifiableCredential } from '../index'
import { Signer } from 'did-jwt'
import { DEFAULT_CONTEXT, DEFAULT_TYPE } from '../constants'
import { CredentialSubject } from '../types'

const mockedValidateDidFormat = validateDidFormat as jest.Mock<
  typeof validateDidFormat
>
const mockedValidateCredentialSubject = validateCredentialSubject as jest.Mock<
  typeof validateCredentialSubject
>
const mockedValidateTimestamp = validateTimestamp as jest.Mock<
  typeof validateTimestamp
>
const mockedCreateVerifiableCredential = (createVerifiableCredential as unknown) as jest.Mock<
  typeof createVerifiableCredential
>

const DID_A = 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198'
const DID_B = 'did:ethr:0x435df3eda57154cf8cf7926079881f2912f54db4'
const SIGNER: Signer = async (data: string) => 'signature'
const CREDENTIAL_SUBJECT: CredentialSubject = { name: 'test' }

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
        const timestamp = Math.floor(new Date().getTime() / 1000)
        vc.setValidFrom(timestamp).build()
        expect(mockedCreateVerifiableCredential).toHaveBeenCalledWith(
          expect.objectContaining({
            nbf: timestamp
          }),
          expect.anything()
        )
      })
      it('calls createVerifiableCredential with exp in the payload if expires has been set', () => {
        const timestamp = Math.floor(new Date().getTime() / 1000)
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
    it('calls did format validator', () => {
      const value = faker.random.alphaNumeric(20)
      vc.setSubject(value)
      expect(mockedValidateDidFormat).toHaveBeenCalledWith(value)
    })
    it('sets the subject of the vc', () => {
      expect(vc.setSubject(DID_A).subject).toEqual(DID_A)
    })
  })

  describe('setIssuer', () => {
    it('calls did format validator', () => {
      const value = faker.random.alphaNumeric(20)
      vc.setIssuer(value)
      expect(mockedValidateDidFormat).toHaveBeenCalledWith(value)
    })
    it('sets the issuer of the vc', () => {
      expect(vc.setIssuer(DID_A).issuer).toEqual(DID_A)
    })
  })

  describe('setCredentialSubject', () => {
    it('calls credential subject validator', () => {
      const value = {}
      vc.setCredentialSubject(value)
      expect(mockedValidateCredentialSubject).toHaveBeenCalledWith(value)
    })
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
    it('calls timestamp validator', () => {
      const value = faker.random.number()
      vc.setValidFrom(value)
      expect(mockedValidateTimestamp).toHaveBeenCalledWith(value)
    })
    it('sets the validFrom timestamp of the vc', () => {
      const value = faker.random.number()
      expect(vc.setValidFrom(value).validFrom).toEqual(value)
    })
  })

  describe('setValidUntil', () => {
    it('calls timestamp validator', () => {
      const value = faker.random.number()
      vc.setValidUntil(value)
      expect(mockedValidateTimestamp).toHaveBeenCalledWith(value)
    })
    it('sets the expires timestamp of the vc', () => {
      const value = faker.random.number()
      expect(vc.setValidUntil(value).validUntil).toEqual(value)
    })
  })

  describe('expiresIn', () => {
    it('throws an error if validFrom has not been set', () => {
      expect(() => vc.expiresIn(faker.random.number())).toThrow()
    })

    it('sets the expires timestamp of the vc to validFrom + duration provided', () => {
      const timestamp = Math.floor(new Date().getTime() / 1000)
      const validFor = 60000
      expect(vc.setValidFrom(timestamp).expiresIn(validFor).validUntil).toEqual(
        timestamp + validFor
      )
    })
  })

  describe('setId', () => {
    it('it sets the id of the vc', () => {
      const value = faker.random.word()
      expect(vc.setId(value).id).toEqual(value)
    })
  })
})
