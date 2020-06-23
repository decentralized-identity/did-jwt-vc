import {
  normalizeCredential,
  transformCredentialInput,
  normalizePresentation,
  transformPresentationInput
} from '../converters'
import { DEFAULT_JWT_PROOF_TYPE } from '../constants'

function encodeBase64Url(input: string): string {
  return Buffer.from(input, 'utf-8').toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

describe('credential', () => {
  describe('transform W3C/JWT VC => W3C VC', () => {
    it('passes through empty payload', () => {
      const result = normalizeCredential({})
      expect(result).toMatchObject({})
    })

    it('passes through app specific properties', () => {
      const result = normalizeCredential({ foo: 'bar' })
      expect(result).toMatchObject({ foo: 'bar' })
    })

    it('clears empty vc property', () => {
      const result = normalizeCredential({ foo: 'bar', vc: {} })
      expect(result).toMatchObject({ foo: 'bar' })
      expect(result).not.toHaveProperty('vc')
    })

    it('passes through app specific properties in vc', () => {
      const result = normalizeCredential({ foo: 'bar', vc: { bar: 'baz' } })
      expect(result).toMatchObject({ foo: 'bar', vc: { bar: 'baz' } })
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
          vc: { credentialSubject: { bar: 'baz' }, '@context': [], type: [] }
        })
        expect(result).toMatchObject({ credentialSubject: { foo: 'bar', bar: 'baz' } })
      })

      it('merges credentialSubject objects with JWT precedence', () => {
        const result = normalizeCredential({
          credentialSubject: { foo: 'bar' },
          vc: { credentialSubject: { foo: 'bazzz' }, '@context': [], type: [] }
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
        const result = normalizeCredential({ type: 'bar', vc: { type: 'foo', '@context': [], credentialSubject: {} } })
        expect(result).toMatchObject({ type: ['bar', 'foo'] })
      })

      it('merges type as arrays uniquely', () => {
        const result = normalizeCredential({ type: 'foo', vc: { type: 'foo', '@context': [], credentialSubject: {} } })
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
        const result = normalizeCredential({
          context: 'baz',
          '@context': 'bar',
          vc: { '@context': 'foo', type: [], credentialSubject: {} }
        })
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

  describe('transform W3C/JWT VC => JWT payload', () => {
    it('passes through empty payload with empty vc field', () => {
      const result = transformCredentialInput({})
      expect(result).toMatchObject({ vc: {} })
    })

    it('passes through app specific properties', () => {
      const result = transformCredentialInput({ foo: 'bar' })
      expect(result).toMatchObject({ foo: 'bar' })
    })

    it('passes through app specific vc properties', () => {
      const result = transformCredentialInput({ vc: { foo: 'bar' } })
      expect(result).toMatchObject({ vc: { foo: 'bar' } })
    })

    describe('credentialSubject', () => {
      it('uses credentialSubject.id as sub', () => {
        const result = transformCredentialInput({ credentialSubject: { id: 'foo' } })
        expect(result).toMatchObject({ sub: 'foo', vc: { credentialSubject: {} } })
        expect(result.vc.credentialSubject).not.toHaveProperty('id')
      })

      it('preserves existing sub property if present', () => {
        const result = transformCredentialInput({ sub: 'bar', credentialSubject: { id: 'foo' } })
        expect(result).toMatchObject({ sub: 'bar', vc: { credentialSubject: { id: 'foo' } } })
      })

      it('merges credentialSubject properties', () => {
        const result = transformCredentialInput({
          vc: { credentialSubject: { foo: 'bar' } },
          credentialSubject: { bar: 'baz' }
        })
        expect(result).toMatchObject({ vc: { credentialSubject: { foo: 'bar', bar: 'baz' } } })
      })
    })

    describe('context', () => {
      it('merges @context fields', () => {
        const result = transformCredentialInput({ context: ['AA'], '@context': ['BB'], vc: { '@context': ['CC'] } })
        expect(result).toMatchObject({ vc: { '@context': ['AA', 'BB', 'CC'] } })
        expect(result).not.toHaveProperty('context')
        expect(result).not.toHaveProperty('@context')
      })

      it('merges @context fields when not array types', () => {
        const result = transformCredentialInput({ context: 'AA', '@context': 'BB', vc: { '@context': ['CC'] } })
        expect(result).toMatchObject({ vc: { '@context': ['AA', 'BB', 'CC'] } })
        expect(result).not.toHaveProperty('context')
        expect(result).not.toHaveProperty('@context')
      })

      it('keeps only unique entries in vc.@context', () => {
        const result = transformCredentialInput({
          context: ['AA', 'BB'],
          '@context': ['BB', 'CC'],
          vc: { '@context': ['CC', 'DD'] }
        })
        expect(result).toMatchObject({ vc: { '@context': ['AA', 'BB', 'CC', 'DD'] } })
        expect(result).not.toHaveProperty('context')
        expect(result).not.toHaveProperty('@context')
      })

      it('removes undefined entries from @context', () => {
        const result = transformCredentialInput({})
        expect(result.vc['@context'].length).toBe(0)
      })
    })

    describe('type', () => {
      it('merges type fields', () => {
        const result = transformCredentialInput({ type: ['AA'], vc: { type: ['BB'] } })
        expect(result).toMatchObject({ vc: { type: ['AA', 'BB'] } })
        expect(result).not.toHaveProperty('type')
      })

      it('merges type fields when not array types', () => {
        const result = transformCredentialInput({ type: 'AA', vc: { type: ['BB'] } })
        expect(result).toMatchObject({ vc: { type: ['AA', 'BB'] } })
        expect(result).not.toHaveProperty('type')
      })

      it('keeps only unique entries in vc.type', () => {
        const result = transformCredentialInput({ type: ['AA', 'BB'], vc: { type: ['BB', 'CC'] } })
        expect(result).toMatchObject({ vc: { type: ['AA', 'BB', 'CC'] } })
      })

      it('removes undefined entries from vc.type', () => {
        const result = transformCredentialInput({})
        expect(result.vc.type.length).toBe(0)
      })
    })

    describe('jti', () => {
      it('uses the id property as jti', () => {
        const result = transformCredentialInput({ id: 'foo' })
        expect(result).toMatchObject({ jti: 'foo' })
        expect(result).not.toHaveProperty('id')
      })

      it('preserves jti entry if present', () => {
        const result = transformCredentialInput({ jti: 'bar', id: 'foo' })
        expect(result).toMatchObject({ jti: 'bar', id: 'foo' })
      })
    })

    describe('issuanceDate', () => {
      it('transforms the issuanceDate property to nbf', () => {
        const result = transformCredentialInput({ issuanceDate: '2009-02-13T23:31:30.000Z' })
        expect(result).toMatchObject({ nbf: 1234567890 })
        expect(result).not.toHaveProperty('issuanceDate')
      })

      it('preserves the issuanceDate property if it fails to be parsed as a Date', () => {
        const result = transformCredentialInput({ issuanceDate: 'tomorrow' })
        expect(result).toMatchObject({ issuanceDate: 'tomorrow' })
      })

      it('preserves nbf entry if present', () => {
        const result = transformCredentialInput({ nbf: 123, issuanceDate: '2009-02-13T23:31:30.000Z' })
        expect(result).toMatchObject({ nbf: 123, issuanceDate: '2009-02-13T23:31:30.000Z' })
      })

      it('preserves nbf entry if explicitly undefined', () => {
        const result = transformCredentialInput({ nbf: undefined, issuanceDate: '2009-02-13T23:31:30.000Z' })
        expect(result).toMatchObject({ nbf: undefined, issuanceDate: '2009-02-13T23:31:30.000Z' })
      })
    })

    describe('expirationDate', () => {
      it('transforms the expirationDate property to exp', () => {
        const result = transformCredentialInput({ expirationDate: '2009-02-13T23:31:30.000Z' })
        expect(result).toMatchObject({ exp: 1234567890 })
        expect(result).not.toHaveProperty('expirationDate')
      })

      it('preserves the expirationDate property if it fails to be parsed as a Date', () => {
        const result = transformCredentialInput({ expirationDate: 'tomorrow' })
        expect(result).toMatchObject({ expirationDate: 'tomorrow' })
      })

      it('preserves exp entry if present', () => {
        const result = transformCredentialInput({ exp: 123, expirationDate: '2009-02-13T23:31:30.000Z' })
        expect(result).toMatchObject({ exp: 123, expirationDate: '2009-02-13T23:31:30.000Z' })
      })

      it('preserves exp entry if explicitly undefined', () => {
        const result = transformCredentialInput({ exp: undefined, expirationDate: '2009-02-13T23:31:30.000Z' })
        expect(result).toMatchObject({ exp: undefined, expirationDate: '2009-02-13T23:31:30.000Z' })
      })
    })

    describe('issuer', () => {
      it('uses issuer.id as iss', () => {
        const result = transformCredentialInput({ issuer: { id: 'foo' } })
        expect(result).toMatchObject({ iss: 'foo' })
        expect(result).not.toHaveProperty('issuer')
      })

      it('uses issuer as iss when of type string', () => {
        const result = transformCredentialInput({ issuer: 'foo' })
        expect(result).toMatchObject({ iss: 'foo' })
        expect(result).not.toHaveProperty('issuer')
      })

      it('ignores issuer property if neither string or object', () => {
        const result = transformCredentialInput({ issuer: 12 })
        expect(result).toMatchObject({ issuer: 12 })
      })

      it('ignores issuer property if iss is present', () => {
        const result = transformCredentialInput({ iss: 'foo', issuer: 'bar' })
        expect(result).toMatchObject({ iss: 'foo', issuer: 'bar' })
      })

      it('ignores issuer.id property if iss is present', () => {
        const result = transformCredentialInput({ iss: 'foo', issuer: { id: 'bar' } })
        expect(result).toMatchObject({ iss: 'foo', issuer: { id: 'bar' } })
      })

      it('preserves issuer claims if present', () => {
        const result = transformCredentialInput({ issuer: { id: 'foo', bar: 'baz' } })
        expect(result).toMatchObject({ iss: 'foo', issuer: { bar: 'baz' } })
        expect(result.issuer).not.toHaveProperty('id')
      })
    })
  })
})

describe('presentation', () => {
  describe('transform JWT/W3C VP => W3C VP', () => {
    it('passes through empty payload', () => {
      const result = normalizePresentation({})
      expect(result).toMatchObject({})
    })

    it('passes through app specific properties', () => {
      const result = normalizePresentation({ foo: 'bar' })
      expect(result).toMatchObject({ foo: 'bar' })
    })

    it('clear vp prop if empty', () => {
      const result = normalizePresentation({ foo: 'bar', vp: {} })
      expect(result).toMatchObject({ foo: 'bar' })
      expect(result).not.toHaveProperty('vp')
    })

    it('preserves app specific props in vp', () => {
      const result = normalizePresentation({ foo: 'bar', vp: { bar: 'baz' } })
      expect(result).toMatchObject({ foo: 'bar', vp: { bar: 'baz' } })
    })

    describe('verifiableCredential', () => {
      it('merges the verifiableCredential fields as an array', () => {
        const result = normalizePresentation({
          verifiableCredential: { foo: 'bar' },
          vp: { verifiableCredential: [{ foo: 'baz' }] }
        } as any)
        expect(result).toMatchObject({
          verifiableCredential: [{ foo: 'bar' }, { foo: 'baz' }]
        })
      })

      it('parses the underlying credentials', () => {
        const result = normalizePresentation({
          vp: {
            verifiableCredential: [
              'e30.eyJjb250ZXh0IjoidG9wIGNvbnRleHQiLCJAY29udGV4dCI6WyJhbHNvIHRvcCJdLCJ0eXBlIjpbIkEiXSwiaXNzdWVyIjp7ImNsYWltIjoiaXNzdWVyIGNsYWltIn0sImlzcyI6ImZvbyIsInN1YiI6ImJhciIsInZjIjp7IkBjb250ZXh0IjpbInZjIGNvbnRleHQiXSwidHlwZSI6WyJCIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7InNvbWV0aGluZyI6Im5vdGhpbmcifSwiYXBwU3BlY2lmaWMiOiJzb21lIGFwcCBzcGVjaWZpYyBmaWVsZCJ9LCJuYmYiOjEyMzQ1Njc4OTAsImlhdCI6MTExMTExMTExMSwiZXhwIjoxMjMxMjMxMjMxLCJhcHBTcGVjaWZpYyI6ImFub3RoZXIgYXBwIHNwZWNpZmljIGZpZWxkIn0.signature'
            ]
          }
        })
        expect(result).toMatchObject({
          verifiableCredential: [
            {
              '@context': ['top context', 'also top', 'vc context'],
              type: ['A', 'B'],
              issuer: { id: 'foo', claim: 'issuer claim' },
              vc: { appSpecific: 'some app specific field' },
              iat: 1111111111,
              appSpecific: 'another app specific field',
              credentialSubject: { something: 'nothing', id: 'bar' },
              issuanceDate: '2009-02-13T23:31:30.000Z',
              expirationDate: '2009-01-06T08:40:31.000Z',
              proof: {
                type: 'JwtProof2020',
                jwt:
                  'e30.eyJjb250ZXh0IjoidG9wIGNvbnRleHQiLCJAY29udGV4dCI6WyJhbHNvIHRvcCJdLCJ0eXBlIjpbIkEiXSwiaXNzdWVyIjp7ImNsYWltIjoiaXNzdWVyIGNsYWltIn0sImlzcyI6ImZvbyIsInN1YiI6ImJhciIsInZjIjp7IkBjb250ZXh0IjpbInZjIGNvbnRleHQiXSwidHlwZSI6WyJCIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7InNvbWV0aGluZyI6Im5vdGhpbmcifSwiYXBwU3BlY2lmaWMiOiJzb21lIGFwcCBzcGVjaWZpYyBmaWVsZCJ9LCJuYmYiOjEyMzQ1Njc4OTAsImlhdCI6MTExMTExMTExMSwiZXhwIjoxMjMxMjMxMjMxLCJhcHBTcGVjaWZpYyI6ImFub3RoZXIgYXBwIHNwZWNpZmljIGZpZWxkIn0.signature'
              }
            }
          ]
        })
      })
    })

    describe('holder', () => {
      it('uses the iss property as holder', () => {
        const result = normalizePresentation({ iss: 'foo' })
        expect(result).toMatchObject({ holder: 'foo' })
        expect(result).not.toHaveProperty('iss')
      })

      it('preserves the holder property if present', () => {
        const result = normalizePresentation({ iss: 'foo', holder: 'bar' })
        expect(result).toMatchObject({ holder: 'bar', iss: 'foo' })
      })
    })

    describe('verifier', () => {
      it('merges the verifier and aud properties', () => {
        const result = normalizePresentation({ verifier: ['foo'], aud: ['bar'] })
        expect(result).toMatchObject({ verifier: ['foo', 'bar'] })
        expect(result).not.toHaveProperty('aud')
      })

      it('merges the verifier and aud as arrays', () => {
        const result = normalizePresentation({ verifier: 'foo', aud: 'bar' })
        expect(result).toMatchObject({ verifier: ['foo', 'bar'] })
        expect(result).not.toHaveProperty('aud')
      })

      it('unique entries in the verifier array', () => {
        const result = normalizePresentation({ verifier: ['foo', 'bar'], aud: ['bar', 'baz'] })
        expect(result).toMatchObject({ verifier: ['foo', 'bar', 'baz'] })
        expect(result).not.toHaveProperty('aud')
      })

      it('preserves the holder property if present', () => {
        const result = normalizePresentation({ iss: 'foo', holder: 'bar' })
        expect(result).toMatchObject({ holder: 'bar', iss: 'foo' })
      })
    })

    describe('id', () => {
      it('uses jti property as id', () => {
        const result = normalizePresentation({ jti: 'foo' })
        expect(result).toMatchObject({ id: 'foo' })
        expect(result).not.toHaveProperty('jti')
      })

      it('preserves id property if present', () => {
        const result = normalizePresentation({ jti: 'foo', id: 'bar' })
        expect(result).toMatchObject({ jti: 'foo', id: 'bar' })
      })
    })

    describe('type', () => {
      it('merges type arrays', () => {
        const result = normalizePresentation({ type: ['foo'], vp: { type: ['bar'] } })
        expect(result).toMatchObject({ type: ['foo', 'bar'] })
        expect(result).not.toHaveProperty('vp')
      })

      it('merges type arrays for non-array types', () => {
        const result = normalizePresentation({ type: 'foo', vp: { type: 'bar' } } as any)
        expect(result).toMatchObject({ type: ['foo', 'bar'] })
        expect(result).not.toHaveProperty('vp')
      })

      it('unique entries in type array', () => {
        const result = normalizePresentation({ type: ['foo', 'bar'], vp: { type: ['bar', 'baz'] } })
        expect(result).toMatchObject({ type: ['foo', 'bar', 'baz'] })
      })
    })

    describe('@context', () => {
      it('merges @context arrays', () => {
        const result = normalizePresentation({ context: ['foo'], '@context': ['bar'], vp: { '@context': ['baz'] } })
        expect(result).toMatchObject({ '@context': ['foo', 'bar', 'baz'] })
        expect(result).not.toHaveProperty('vp')
        expect(result).not.toHaveProperty('context')
      })

      it('merges @context arrays for non-array contexts', () => {
        const result = normalizePresentation({ '@context': 'foo', context: 'bar', vp: { '@context': 'baz' } } as any)
        expect(result).toMatchObject({ '@context': ['bar', 'foo', 'baz'] })
        expect(result).not.toHaveProperty('vp')
        expect(result).not.toHaveProperty('context')
      })

      it('unique entries in @context array', () => {
        const result = normalizePresentation({
          '@context': ['foo', 'bar'],
          context: ['bar', 'baz', undefined, null],
          vp: { '@context': ['bar', 'baz', 'bak'], type: [], verifiableCredential: [] }
        })
        expect(result).toMatchObject({ '@context': ['bar', 'baz', 'foo', 'bak'] })
      })
    })

    describe('issuanceDate', () => {
      it('keeps issuanceDate property when present', () => {
        const result = normalizePresentation({ issuanceDate: 'yesterday', nbf: 1234567890, iat: 1111111111 })
        expect(result).toMatchObject({ issuanceDate: 'yesterday', nbf: 1234567890, iat: 1111111111 })
      })

      it('uses nbf as issuanceDate when present', () => {
        const result = normalizePresentation({ nbf: 1234567890, iat: 1111111111 })
        expect(result).toMatchObject({ issuanceDate: '2009-02-13T23:31:30.000Z', iat: 1111111111 })
        expect(result).not.toHaveProperty('nbf')
      })

      it('uses iat as issuanceDate when no nbf and no issuanceDate present', () => {
        const result = normalizePresentation({ iat: 1111111111 })
        expect(result).toMatchObject({ issuanceDate: '2005-03-18T01:58:31.000Z' })
        expect(result).not.toHaveProperty('iat')
      })
    })

    describe('expirationDate', () => {
      it('keeps expirationDate property when present', () => {
        const result = normalizePresentation({ expirationDate: 'tomorrow', exp: 1222222222 })
        expect(result).toMatchObject({ expirationDate: 'tomorrow', exp: 1222222222 })
      })

      it('uses exp as issuanceDate when present', () => {
        const result = normalizePresentation({ exp: 1222222222 })
        expect(result).toMatchObject({ expirationDate: '2008-09-24T02:10:22.000Z' })
        expect(result).not.toHaveProperty('exp')
      })
    })

    describe('JWT payload', () => {
      it('rejects unknown JSON string payload', () => {
        expect(() => {
          normalizePresentation('aaa')
        }).toThrowError(/unknown presentation format/)
      })

      it('rejects malformed JWT string payload 1', () => {
        expect(() => {
          normalizePresentation('a.b.c')
        }).toThrowError(/unknown presentation format/)
      })

      it('rejects malformed JWT string payload 2', () => {
        expect(() => {
          normalizePresentation('aaa.b.c')
        }).toThrowError(/unknown presentation format/)
      })
    })
  })

  describe('transform W3C/JWT VP => JWT payload', () => {
    it('passes through empty payload with empty vp field', () => {
      const result = transformPresentationInput({})
      expect(result).toMatchObject({ vp: {} })
    })

    it('passes through app specific properties', () => {
      const result = transformPresentationInput({ foo: 'bar' })
      expect(result).toMatchObject({ foo: 'bar' })
    })

    it('passes through app specific vp properties', () => {
      const result = transformPresentationInput({ vp: { foo: 'bar' } })
      expect(result).toMatchObject({ vp: { foo: 'bar' } })
    })

    describe('verifiableCredential', () => {
      it('merges verifiableCredentials arrays', () => {
        const result = transformPresentationInput({
          verifiableCredential: [{ id: 'foo' }],
          vp: { verifiableCredential: [{ foo: 'bar' }, 'header.payload.signature'] }
        } as any)
        expect(result).toMatchObject({
          vp: { verifiableCredential: [{ id: 'foo' }, { foo: 'bar' }, 'header.payload.signature'] }
        })
        expect(result).not.toHaveProperty('verifiableCredential')
      })

      it('merges verifiableCredential arrays when not array types', () => {
        const result = transformPresentationInput({
          verifiableCredential: { id: 'foo' },
          vp: { verifiableCredential: { foo: 'bar' } }
        } as any)
        expect(result).toMatchObject({ vp: { verifiableCredential: [{ id: 'foo' }, { foo: 'bar' }] } })
        expect(result).not.toHaveProperty('verifiableCredential')
      })

      it('condenses JWT credentials', () => {
        const result = transformPresentationInput({
          verifiableCredential: { id: 'foo', proof: { jwt: 'header.payload1.signature' } },
          vp: { verifiableCredential: [{ foo: 'bar' }, 'header.payload2.signature'] }
        } as any)
        expect(result).toMatchObject({
          vp: { verifiableCredential: ['header.payload1.signature', { foo: 'bar' }, 'header.payload2.signature'] }
        })
        expect(result).not.toHaveProperty('verifiableCredential')
      })

      it('filters empty credentials', () => {
        const result = transformPresentationInput({
          verifiableCredential: undefined,
          vp: { verifiableCredential: [null, { foo: 'bar' }, 'header.payload2.signature'] }
        } as any)
        expect(result).toMatchObject({ vp: { verifiableCredential: [{ foo: 'bar' }, 'header.payload2.signature'] } })
        expect(result).not.toHaveProperty('verifiableCredential')
      })
    })

    describe('context', () => {
      it('merges @context fields', () => {
        const result = transformPresentationInput({ context: ['AA'], '@context': ['BB'], vp: { '@context': ['CC'] } })
        expect(result).toMatchObject({ vp: { '@context': ['AA', 'BB', 'CC'] } })
        expect(result).not.toHaveProperty('context')
        expect(result).not.toHaveProperty('@context')
      })

      it('merges @context fields when not array types', () => {
        const result = transformPresentationInput({
          context: 'AA',
          '@context': 'BB',
          vp: { '@context': ['CC'] }
        } as any)
        expect(result).toMatchObject({ vp: { '@context': ['AA', 'BB', 'CC'] } })
        expect(result).not.toHaveProperty('context')
        expect(result).not.toHaveProperty('@context')
      })

      it('keeps only unique entries in vp.@context', () => {
        const result = transformPresentationInput({
          context: ['AA', 'BB'],
          '@context': ['BB', 'CC'],
          vp: { '@context': ['CC', 'DD'] }
        })
        expect(result).toMatchObject({ vp: { '@context': ['AA', 'BB', 'CC', 'DD'] } })
        expect(result).not.toHaveProperty('context')
        expect(result).not.toHaveProperty('@context')
      })

      it('removes undefined entries from @context', () => {
        const result = transformPresentationInput({})
        expect(result.vp['@context'].length).toBe(0)
      })
    })

    describe('type', () => {
      it('merges type fields', () => {
        const result = transformPresentationInput({ type: ['AA'], vp: { type: ['BB'] } })
        expect(result).toMatchObject({ vp: { type: ['AA', 'BB'] } })
        expect(result).not.toHaveProperty('type')
      })

      it('merges type fields when not array types', () => {
        const result = transformPresentationInput({ type: 'AA', vp: { type: ['BB'] } } as any)
        expect(result).toMatchObject({ vp: { type: ['AA', 'BB'] } })
        expect(result).not.toHaveProperty('type')
      })

      it('keeps only unique entries in vc.type', () => {
        const result = transformPresentationInput({ type: ['AA', 'BB'], vp: { type: ['BB', 'CC'] } })
        expect(result).toMatchObject({ vp: { type: ['AA', 'BB', 'CC'] } })
      })

      it('removes undefined entries from vc.type', () => {
        const result = transformPresentationInput({})
        expect(result.vp.type.length).toBe(0)
      })
    })

    describe('jti', () => {
      it('uses the id property as jti', () => {
        const result = transformPresentationInput({ id: 'foo' })
        expect(result).toMatchObject({ jti: 'foo' })
        expect(result).not.toHaveProperty('id')
      })

      it('preserves jti entry if present', () => {
        const result = transformPresentationInput({ jti: 'bar', id: 'foo' })
        expect(result).toMatchObject({ jti: 'bar', id: 'foo' })
      })
    })

    describe('issuanceDate', () => {
      it('transforms the issuanceDate property to nbf', () => {
        const result = transformPresentationInput({ issuanceDate: '2009-02-13T23:31:30.000Z' })
        expect(result).toMatchObject({ nbf: 1234567890 })
        expect(result).not.toHaveProperty('issuanceDate')
      })

      it('preserves the issuanceDate property if it fails to be parsed as a Date', () => {
        const result = transformPresentationInput({ issuanceDate: 'tomorrow' })
        expect(result).toMatchObject({ issuanceDate: 'tomorrow' })
      })

      it('preserves nbf entry if present', () => {
        const result = transformPresentationInput({ nbf: 123, issuanceDate: '2009-02-13T23:31:30.000Z' })
        expect(result).toMatchObject({ nbf: 123, issuanceDate: '2009-02-13T23:31:30.000Z' })
      })

      it('preserves nbf entry if explicitly undefined', () => {
        const result = transformPresentationInput({ nbf: undefined, issuanceDate: '2009-02-13T23:31:30.000Z' })
        expect(result).toMatchObject({ nbf: undefined, issuanceDate: '2009-02-13T23:31:30.000Z' })
      })
    })

    describe('expirationDate', () => {
      it('transforms the expirationDate property to exp', () => {
        const result = transformPresentationInput({ expirationDate: '2009-02-13T23:31:30.000Z' })
        expect(result).toMatchObject({ exp: 1234567890 })
        expect(result).not.toHaveProperty('expirationDate')
      })

      it('preserves the expirationDate property if it fails to be parsed as a Date', () => {
        const result = transformPresentationInput({ expirationDate: 'tomorrow' })
        expect(result).toMatchObject({ expirationDate: 'tomorrow' })
      })

      it('preserves exp entry if present', () => {
        const result = transformPresentationInput({ exp: 123, expirationDate: '2009-02-13T23:31:30.000Z' })
        expect(result).toMatchObject({ exp: 123, expirationDate: '2009-02-13T23:31:30.000Z' })
      })

      it('preserves exp entry if explicitly undefined', () => {
        const result = transformPresentationInput({ exp: undefined, expirationDate: '2009-02-13T23:31:30.000Z' })
        expect(result).toMatchObject({ exp: undefined, expirationDate: '2009-02-13T23:31:30.000Z' })
      })
    })

    describe('holder', () => {
      it('uses holder as iss when of type string', () => {
        const result = transformPresentationInput({ holder: 'foo' })
        expect(result).toMatchObject({ iss: 'foo' })
        expect(result).not.toHaveProperty('holder')
      })

      it('preserves holder property if not string type', () => {
        const result = transformPresentationInput({ holder: 12 })
        expect(result).toMatchObject({ holder: 12 })
      })

      it('preserves holder property if iss is present', () => {
        const result = transformPresentationInput({ iss: 'foo', holder: 'bar' })
        expect(result).toMatchObject({ iss: 'foo', holder: 'bar' })
      })
    })

    describe('verifier', () => {
      it('merges verifier and aud props into aud array', () => {
        const result = transformPresentationInput({ verifier: ['foo'], aud: ['bar'] })
        expect(result).toMatchObject({ aud: ['foo', 'bar'] })
        expect(result).not.toHaveProperty('verifier')
      })

      it('merges verifier and aud props into aud array when different types', () => {
        const result = transformPresentationInput({ verifier: 'foo', aud: 'bar' })
        expect(result).toMatchObject({ aud: ['foo', 'bar'] })
      })

      it('filters null or undefined values in aud', () => {
        const result = transformPresentationInput({ verifier: ['foo', null], aud: ['bar', undefined] })
        expect(result).toMatchObject({ aud: ['foo', 'bar'] })
      })

      it('unique values in aud', () => {
        const result = transformPresentationInput({ verifier: ['foo', 'bar'], aud: ['bar', 'baz'] })
        expect(result).toMatchObject({ aud: ['foo', 'bar', 'baz'] })
      })
    })
  })
})
