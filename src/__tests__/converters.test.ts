import { normalizeCredential } from '../converters'
import { DEFAULT_JWT_PROOF_TYPE } from '../constants'

describe('credential', () => {
  describe('transform payload to W3C', () => {
    it('passes through empty payload', () => {
      const result = normalizeCredential({})
      expect(result).toMatchObject({})
    })

    it('passes through app specific properties', () => {
      const result = normalizeCredential({ foo: 'bar' })
      expect(result).toMatchObject({ foo: 'bar' })
    })

    describe('credentialSubject', () => {
      it('keeps credentialSubject object', () => {
        const result = normalizeCredential({ credentialSubject: { foo: 'bar' } })
        expect(result).toMatchObject({ credentialSubject: { foo: 'bar' } })
      })

      it('interprets JWT sub as credential subject id', () => {
        const result = normalizeCredential({ sub: 'example.com' })
        expect(result).toMatchObject({ credentialSubject: { id: 'example.com' } })
        expect(result).not.toHaveProperty('sub')
      })

      it('interprets JWT sub as credential subject id without overwriting existing', () => {
        const result = normalizeCredential({ sub: 'foo', credentialSubject: { id: 'bar' } })
        expect(result).toMatchObject({ sub: 'foo', credentialSubject: { id: 'bar' } })
      })

      it('merges credentialSubject objects', () => {
        const result = normalizeCredential({
          credentialSubject: { foo: 'bar' },
          vc: { credentialSubject: { bar: 'baz' } }
        })
        expect(result).toMatchObject({ credentialSubject: { foo: 'bar', bar: 'baz' } })
      })

      it('merges credentialSubject objects with JWT precedence', () => {
        const result = normalizeCredential({
          credentialSubject: { foo: 'bar' },
          vc: { credentialSubject: { foo: 'bazzz' } }
        })
        expect(result).toMatchObject({ credentialSubject: { foo: 'bazzz' } })
      })
    })

    describe('issuer', () => {
      it('accepts null issuer', () => {
        const result = normalizeCredential({
          issuer: null
        })
        expect(result).toMatchObject({})
      })

      it('parses iss as issuer id', () => {
        const result = normalizeCredential({
          iss: 'foo'
        })
        expect(result).toMatchObject({ issuer: { id: 'foo' } })
        expect(result).not.toHaveProperty('iss')
      })

      it('keeps iss if issuer already has id', () => {
        const result = normalizeCredential({
          iss: 'foo',
          issuer: {
            id: 'bar'
          }
        })
        expect(result).toMatchObject({ iss: 'foo', issuer: { id: 'bar' } })
      })

      it('keeps issuer claims', () => {
        const result = normalizeCredential({
          iss: 'foo',
          issuer: {
            bar: 'baz'
          }
        })
        expect(result).toMatchObject({ issuer: { id: 'foo', bar: 'baz' } })
        expect(result).not.toHaveProperty('iss')
      })

      it('keeps issuer if it is not an object', () => {
        const result = normalizeCredential({
          iss: 'foo',
          issuer: 'baz'
        })
        expect(result).toMatchObject({ issuer: 'baz', iss: 'foo' })
      })
    })

    describe('jti', () => {
      it('transforms jti to id', () => {
        const result = normalizeCredential({ jti: 'foo' })
        expect(result).toMatchObject({ id: 'foo' })
        expect(result).not.toHaveProperty('jti')
      })

      it('transforms jti to id if it is not present', () => {
        const result = normalizeCredential({ jti: 'foo', id: 'bar' })
        expect(result).toMatchObject({ id: 'bar', jti: 'foo' })
      })
    })

    describe('type', () => {
      it('uses type from vc', () => {
        const result = normalizeCredential({ vc: { type: ['foo'] } })
        expect(result).toMatchObject({ type: ['foo'] })
      })

      it('merges type arrays', () => {
        const result = normalizeCredential({ type: ['bar'], vc: { type: ['foo'] } })
        expect(result).toMatchObject({ type: ['bar', 'foo'] })
      })

      it('merges type as arrays for single items', () => {
        const result = normalizeCredential({ type: 'bar', vc: { type: 'foo' } })
        expect(result).toMatchObject({ type: ['bar', 'foo'] })
      })

      it('merges type as arrays uniquely', () => {
        const result = normalizeCredential({ type: 'foo', vc: { type: 'foo' } })
        expect(result).toMatchObject({ type: ['foo'] })
        expect(result).not.toHaveProperty('vc')
      })
    })

    describe('context', () => {
      it('uses @context from vc', () => {
        const result = normalizeCredential({ vc: { '@context': ['foo'] } })
        expect(result).toMatchObject({ '@context': ['foo'] })
      })

      it('merges @context arrays', () => {
        const result = normalizeCredential({ context: ['baz'], '@context': ['bar'], vc: { '@context': ['foo'] } })
        expect(result).toMatchObject({ '@context': ['baz', 'bar', 'foo'] })
      })

      it('merges @context as arrays for single items', () => {
        const result = normalizeCredential({ context: 'baz', '@context': 'bar', vc: { '@context': 'foo' } })
        expect(result).toMatchObject({ '@context': ['baz', 'bar', 'foo'] })
      })

      it('merges @context as arrays uniquely', () => {
        const result = normalizeCredential({
          context: 'baz',
          '@context': ['bar'],
          vc: { '@context': ['foo', 'baz', 'bar'] }
        })
        expect(result).toMatchObject({ '@context': ['baz', 'bar', 'foo'] })
        expect(result).not.toHaveProperty('vc')
      })
    })

    describe('issuanceDate', () => {
      it('keeps issuanceDate property when present', () => {
        const result = normalizeCredential({ issuanceDate: 'yesterday', nbf: 1234567890, iat: 1111111111 })
        expect(result).toMatchObject({ issuanceDate: 'yesterday', nbf: 1234567890, iat: 1111111111 })
      })

      it('uses nbf as issuanceDate when present', () => {
        const result = normalizeCredential({ nbf: 1234567890, iat: 1111111111 })
        expect(result).toMatchObject({ issuanceDate: '2009-02-13T23:31:30.000Z', iat: 1111111111 })
        expect(result).not.toHaveProperty('nbf')
      })

      it('uses iat as issuanceDate when no nbf and no issuanceDate present', () => {
        const result = normalizeCredential({ iat: 1111111111 })
        expect(result).toMatchObject({ issuanceDate: '2005-03-18T01:58:31.000Z' })
        expect(result).not.toHaveProperty('iat')
      })
    })

    describe('expirationDate', () => {
      it('keeps expirationDate property when present', () => {
        const result = normalizeCredential({ expirationDate: 'tomorrow', exp: 1222222222 })
        expect(result).toMatchObject({ expirationDate: 'tomorrow', exp: 1222222222 })
      })

      it('uses exp as issuanceDate when present', () => {
        const result = normalizeCredential({ exp: 1222222222 })
        expect(result).toMatchObject({ expirationDate: '2008-09-24T02:10:22.000Z' })
        expect(result).not.toHaveProperty('exp')
      })
    })

    describe('JWT payload', () => {
      it('rejects unknown JSON string payload', () => {
        expect(() => {
          normalizeCredential('aaa')
        }).toThrowError(/unknown credential format/)
      })

      it('rejects malformed JWT string payload 1', () => {
        expect(() => {
          normalizeCredential('a.b.c')
        }).toThrowError(/unknown credential format/)
      })

      it('rejects malformed JWT string payload 2', () => {
        expect(() => {
          normalizeCredential('aaa.b.c')
        }).toThrowError(/unknown credential format/)
      })

      const complexInput = {
        context: 'top context',
        '@context': ['also top'],
        type: ['A'],
        issuer: {
          claim: 'issuer claim'
        },
        iss: 'foo',
        sub: 'bar',
        vc: {
          '@context': ['vc context'],
          type: ['B'],
          credentialSubject: {
            something: 'nothing'
          },
          appSpecific: 'some app specific field'
        },
        nbf: 1234567890,
        iat: 1111111111,
        exp: 1231231231,
        appSpecific: 'another app specific field'
      }

      const expectedComplexOutput = {
        '@context': ['top context', 'also top', 'vc context'],
        type: ['A', 'B'],
        issuer: {
          id: 'foo',
          claim: 'issuer claim'
        },
        credentialSubject: {
          id: 'bar',
          something: 'nothing'
        },
        issuanceDate: '2009-02-13T23:31:30.000Z',
        expirationDate: '2009-01-06T08:40:31.000Z',
        iat: 1111111111,
        vc: {
          appSpecific: 'some app specific field'
        },
        appSpecific: 'another app specific field'
      }

      it('accepts VerifiableCredential as string', () => {
        const credential = JSON.stringify(complexInput)

        const result = normalizeCredential(credential)

        expect(result).toMatchObject(expectedComplexOutput)

        expect(result).not.toHaveProperty('nbf')
        expect(result).not.toHaveProperty('exp')
        expect(result).not.toHaveProperty('sub')
        expect(result).not.toHaveProperty('context')
        expect(result.vc).not.toHaveProperty('@context')
        expect(result.vc).not.toHaveProperty('type')
        expect(result.vc).not.toHaveProperty('credentialSubject')
      })

      function encodeBase64Url(input: string): string {
        return Buffer.from(input, 'utf-8').toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
      }

      it('accepts VerifiableCredential as JWT', () => {
        const payload = JSON.stringify(complexInput)
        const header = '{}'

        const credential = `${encodeBase64Url(header)}.${encodeBase64Url(payload)}.signature`

        const result = normalizeCredential(credential)

        expect(result).toMatchObject(expectedComplexOutput)
        expect(result).toHaveProperty('proof', { type: DEFAULT_JWT_PROOF_TYPE, jwt: credential })

        expect(result).not.toHaveProperty('nbf')
        expect(result).not.toHaveProperty('exp')
        expect(result).not.toHaveProperty('sub')
        expect(result).not.toHaveProperty('context')
        expect(result.vc).not.toHaveProperty('@context')
        expect(result.vc).not.toHaveProperty('type')
        expect(result.vc).not.toHaveProperty('credentialSubject')
      })
    })
  })
})

describe('presentation', () => {})
