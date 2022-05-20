import * as validators from '../validators'
import { DEFAULT_CONTEXT, DEFAULT_VC_TYPE, DEFAULT_VP_TYPE } from '../types'

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
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1NjY5MjMyNjksInN1YiI6ImRpZDpldGhyOjB4NDM1ZGYzZWRhNTcxNTRjZjhjZjc5MjYwNzk4ODFmMjkxMmY1NGRiNCIsIm5iZiI6MTU2Mjk1MDI4MiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy9leGFtcGxlcy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVW5pdmVyc2l0eURlZ3JlZUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiZGVncmVlIjp7InR5cGUiOiJCYWNoZWxvckRlZ3JlZSIsIm5hbWUiOiJCYWNjYWxhdXLDqWF0IGVuIG11c2lxdWVzIG51bcOpcmlxdWVzIn19fSwiaXNzIjoiZGlkOmV0aHI6MHhmMTIzMmY4NDBmM2FkN2QyM2ZjZGFhODRkNmM2NmRhYzI0ZWZiMTk4In0.rFRZUCw3Gu0E_I5ZJbrbpuHV1JNAwpXaiFZuJ59iJ-TNqufr4cuGCBEECFbgQF-lpNm51cqSx3Y2IdWaUpatJQA'

describe('validators', () => {
  describe('validateTimestamp', () => {
    it('does not throw if the value is a valid unix timestamp in seconds', () => {
      expect(() => validators.validateTimestamp(Math.floor(new Date().getTime() / 1000))).not.toThrow()
    })
    it('throws a TypeError if the value is a millisecond timestamp', () => {
      expect(() => validators.validateTimestamp(new Date().getTime())).toThrow(TypeError)
    })
    it('throws a TypeError if the value is not an integer', () => {
      expect(() => validators.validateTimestamp(1653060380105 / 1000)).toThrow(TypeError)
    })
  })

  describe('validateContext', () => {
    it('does not throw if the value contains only the default context', () => {
      expect(() => validators.validateContext([DEFAULT_CONTEXT])).not.toThrow()
    })
    it('does not throw if the value contains the default context and some user-defined ones', () => {
      expect(() => validators.validateContext([DEFAULT_CONTEXT, EXTRA_CONTEXT_A, EXTRA_CONTEXT_B])).not.toThrow()
    })
    it('throws a TypeError the value contains no contexts', () => {
      expect(() => validators.validateContext([])).toThrow(TypeError)
    })
    it('throws a TypeError the value is missing the default context', () => {
      expect(() => validators.validateContext([EXTRA_CONTEXT_A, EXTRA_CONTEXT_B])).toThrow(TypeError)
    })
  })

  describe('validateVcType', () => {
    it('does not throw if the value contains only the default type', () => {
      expect(() => validators.validateVcType([DEFAULT_VC_TYPE])).not.toThrow()
    })
    it('does not throw if the value contains the default type and some user-defined ones', () => {
      expect(() => validators.validateVcType([DEFAULT_VC_TYPE, EXTRA_TYPE_A, EXTRA_TYPE_B])).not.toThrow()
    })
    it('throws a TypeError the value contains no types', () => {
      expect(() => validators.validateVcType([])).toThrow(TypeError)
    })
    it('throws a TypeError the value is missing the default type', () => {
      expect(() => validators.validateVcType([EXTRA_TYPE_A, EXTRA_TYPE_B])).toThrow(TypeError)
    })
  })

  describe('validateVpType', () => {
    it('does not throw if the value contains only the default type', () => {
      expect(() => validators.validateVpType([DEFAULT_VP_TYPE])).not.toThrow()
    })
    it('does not throw if the value contains the default type and some user-defined ones', () => {
      expect(() => validators.validateVpType([DEFAULT_VP_TYPE, EXTRA_TYPE_A, EXTRA_TYPE_B])).not.toThrow()
    })
    it('throws a TypeError the value contains no types', () => {
      expect(() => validators.validateVpType([])).toThrow(TypeError)
    })
    it('throws a TypeError the value is missing the default type', () => {
      expect(() => validators.validateVpType([EXTRA_TYPE_A, EXTRA_TYPE_B])).toThrow(TypeError)
    })
  })

  describe('validateJwtFormat', () => {
    it('does not throw if the value is a valid JWT format', () => {
      expect(() => validators.validateJwtFormat(VC_JWT)).not.toThrow()
    })
    it('throws a TypeError if the value is not a valid JWT format', () => {
      expect(() => validators.validateJwtFormat('not a jwt')).toThrow(TypeError)
    })
  })

  describe('validateCredentialSubject', () => {
    it('does not throw if the value is an object with at least one attribute', () => {
      expect(() => validators.validateCredentialSubject({ name: 'test' })).not.toThrow()
    })
    it('throws a TypeError if the value is an object with no attributes', () => {
      expect(() => validators.validateCredentialSubject({})).toThrow(TypeError)
    })
  })
})
