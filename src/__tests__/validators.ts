import * as validators from '../validators'
import {
  DID_A,
  INVALID_DID,
  EXTRA_CONTEXT_A,
  EXTRA_CONTEXT_B,
  EXTRA_TYPE_A,
  EXTRA_TYPE_B,
  VC_JWT
} from '.'
import { DEFAULT_CONTEXT, DEFAULT_TYPE } from '../constants'

describe('validators', () => {
  describe('validateDidFormat', () => {
    it('does not throw if the value is a valid did format', () => {
      expect(() => validators.validateDidFormat(DID_A)).not.toThrow()
    })
    it('throws a TypeError if the value is not a valid did format', () => {
      expect(() => validators.validateDidFormat(INVALID_DID)).toThrow(TypeError)
    })
  })

  describe('validateTimestamp', () => {
    it('does not throw if the value is a valid unix timestamp in seconds', () => {
      expect(() =>
        validators.validateTimestamp(Math.floor(new Date().getTime() / 1000))
      ).not.toThrow()
    })
    it('throws a TypeError if the value is a millisecond timestamp', () => {
      expect(() => validators.validateTimestamp(new Date().getTime())).toThrow(
        TypeError
      )
    })
    it('throws a TypeError if the value is not an integer', () => {
      expect(() =>
        validators.validateTimestamp(new Date().getTime() / 1000)
      ).toThrow(TypeError)
    })
  })

  describe('validateContext', () => {
    it('does not throw if the value contains only the default context', () => {
      expect(() => validators.validateContext([DEFAULT_CONTEXT])).not.toThrow()
    })
    it('does not throw if the value contains the default context and some user-defined ones', () => {
      expect(() =>
        validators.validateContext([
          DEFAULT_CONTEXT,
          EXTRA_CONTEXT_A,
          EXTRA_CONTEXT_B
        ])
      ).not.toThrow()
    })
    it('throws a TypeError the value contains no contexts', () => {
      expect(() => validators.validateContext([])).toThrow(TypeError)
    })
    it('throws a TypeError the value is missing the default context', () => {
      expect(() =>
        validators.validateContext([EXTRA_CONTEXT_A, EXTRA_CONTEXT_B])
      ).toThrow(TypeError)
    })
  })

  describe('validateType', () => {
    it('does not throw if the value contains only the default type', () => {
      expect(() => validators.validateType([DEFAULT_TYPE])).not.toThrow()
    })
    it('does not throw if the value contains the default type and some user-defined ones', () => {
      expect(() =>
        validators.validateType([DEFAULT_TYPE, EXTRA_TYPE_A, EXTRA_TYPE_B])
      ).not.toThrow()
    })
    it('throws a TypeError the value contains no types', () => {
      expect(() => validators.validateType([])).toThrow(TypeError)
    })
    it('throws a TypeError the value is missing the default type', () => {
      expect(() =>
        validators.validateType([EXTRA_TYPE_A, EXTRA_TYPE_B])
      ).toThrow(TypeError)
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
})
