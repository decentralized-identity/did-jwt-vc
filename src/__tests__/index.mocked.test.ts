import { DEFAULT_CONTEXT, DEFAULT_VC_TYPE, DEFAULT_VP_TYPE } from '../types.js'
import type { Issuer } from '../index.js'
import { EthrDID } from 'ethr-did'

import { jest } from '@jest/globals'

import * as actualValidators from '../validators.js'

jest.unstable_mockModule('../validators.js', async () => {
  return {
    ...actualValidators,
    validateTimestamp: jest.fn(),
    validateVcType: jest.fn(),
    validateVpType: jest.fn(),
    validateContext: jest.fn(),
    validateJwtFormat: jest.fn(),
    validateCredentialSubject: jest.fn(),
  }
})

const {
  validateTimestamp,
  validateVcType,
  validateVpType,
  validateContext,
  validateJwtFormat,
  validateCredentialSubject,
} = await import('../validators.js')

// must be done after the unstable_mockModule call to use the mocked version
const { createVerifiableCredentialJwt, createVerifiablePresentationJwt } = await import('../index.js')

const DID_B = 'did:ethr:0x435df3eda57154cf8cf7926079881f2912f54db4'
const EXTRA_CONTEXT_A = 'https://www.w3.org/2018/credentials/examples/v1'
const EXTRA_TYPE_A = 'UniversityDegreeCredential'
const VC_JWT =
  // tslint:disable-next-line: max-line-length
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1NjY5MjMyNjksInN1YiI6ImRpZDpldGhyOjB4NDM1ZGYzZWRhNTcxNTRjZjhjZjc5MjYwNzk4ODFmMjkxMmY1NGRiNCIsIm5iZiI6MTU2Mjk1MDI4MiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy9leGFtcGxlcy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVW5pdmVyc2l0eURlZ3JlZUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiZGVncmVlIjp7InR5cGUiOiJCYWNoZWxvckRlZ3JlZSIsIm5hbWUiOiJCYWNjYWxhdXLDqWF0IGVuIG11c2lxdWVzIG51bcOpcmlxdWVzIn19fSwiaXNzIjoiZGlkOmV0aHI6MHhmMTIzMmY4NDBmM2FkN2QyM2ZjZGFhODRkNmM2NmRhYzI0ZWZiMTk4In0.rFRZUCw3Gu0E_I5ZJbrbpuHV1JNAwpXaiFZuJ59iJ-TNqufr4cuGCBEECFbgQF-lpNm51cqSx3Y2IdWaUpatJQA'

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
describe('createVerifiableCredential', () => {
  const issuer = ethrDidIssuer

  it('calls functions to validate required fields', async () => {
    expect.assertions(4)
    await createVerifiableCredentialJwt(verifiableCredentialPayload, issuer)
    expect(validateTimestamp).toHaveBeenCalledWith(verifiableCredentialPayload.nbf)
    expect(validateContext).toHaveBeenCalledWith(verifiableCredentialPayload.vc['@context'])
    expect(validateVcType).toHaveBeenCalledWith(verifiableCredentialPayload.vc.type)
    expect(validateCredentialSubject).toHaveBeenCalledWith(verifiableCredentialPayload.vc.credentialSubject)
  })
  it('calls functions to validate optional fields if they are present', async () => {
    expect.assertions(1)

    const timestamp = Math.floor(new Date().getTime())
    await createVerifiableCredentialJwt({ ...verifiableCredentialPayload, exp: timestamp }, issuer)
    expect(validateTimestamp).toHaveBeenCalledWith(timestamp)
  })
})

describe('createPresentation', () => {
  const holder = ethrDidIssuer

  it('calls functions to validate required fields', async () => {
    expect.assertions(2 + presentationPayload.vp.verifiableCredential.length)

    await createVerifiablePresentationJwt(presentationPayload, holder)
    expect(validateContext).toHaveBeenCalledWith(presentationPayload.vp['@context'])
    expect(validateVpType).toHaveBeenCalledWith(presentationPayload.vp.type)
    for (const vc of presentationPayload.vp.verifiableCredential) {
      expect(validateJwtFormat).toHaveBeenCalledWith(vc)
    }
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
    expect(validateTimestamp).toHaveBeenCalledWith(timestamp)
  })
})
