import {
  VerifiableCredential,
  JWT,
  JwtPresentationPayload,
  JwtCredentialPayload,
  JWT_FORMAT,
  DEFAULT_JWT_PROOF_TYPE,
  DEFAULT_CONTEXT,
  DEFAULT_VC_TYPE,
  CredentialPayload,
  W3CCredential,
  Verifiable,
  PresentationPayload,
  W3CPresentation,
} from './types'
import { decodeJWT } from 'did-jwt'

/*
 * Additional W3C VC fields:
 * These are defined as optional top-level properties in the W3C spec but are not mapped to top-level JWT names,
 * so they should be moved inside the "vc" object when transforming to a JWT.
 * Conversely, they should be moved out of the "vc" object when transforming from a JWT to W3C JSON.
 */
const additionalPropNames = ['evidence', 'termsOfUse', 'refreshService', 'credentialSchema', 'credentialStatus']

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function asArray(arg: any | any[]): any[] {
  return Array.isArray(arg) ? arg : [arg]
}

function deepCopy<T>(source: T): T {
  return Array.isArray(source)
    ? source.map((item) => deepCopy(item))
    : source instanceof Date
    ? new Date(source.getTime())
    : source && typeof source === 'object'
    ? Object.getOwnPropertyNames(source).reduce((o, prop) => {
        Object.defineProperty(o, prop, Object.getOwnPropertyDescriptor(source, prop) as NonNullable<PropertyDescriptor>)
        o[prop] = deepCopy(source[prop as keyof T])
        return o
      }, Object.create(Object.getPrototypeOf(source)))
    : (source as T)
}

export function notEmpty<TValue>(value: TValue | null | undefined): value is TValue {
  return value !== null && value !== undefined
}

function cleanUndefined<T>(input: T): T {
  if (typeof input !== 'object') {
    return input
  }
  const obj = { ...input }
  Object.keys(obj).forEach((key) => obj[key as keyof T] === undefined && delete obj[key as keyof T])
  return obj
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function isLegacyAttestationFormat(payload: Record<string, any>): boolean {
  // payload is an object and has all the required fields of old attestation format
  return typeof payload === 'object' && payload.sub && payload.iss && payload.claim && payload.iat
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function attestationToVcFormat(payload: Record<string, any>): JwtCredentialPayload {
  const { iat, nbf, claim, vc, ...rest } = payload
  const result: JwtCredentialPayload = {
    ...rest,
    nbf: nbf ? nbf : iat,
    vc: {
      '@context': [DEFAULT_CONTEXT],
      type: [DEFAULT_VC_TYPE],
      credentialSubject: claim,
    },
  }
  if (vc) payload.issVc = vc
  return result
}

function normalizeJwtCredentialPayload(
  input: Partial<JwtCredentialPayload>,
  removeOriginalFields = true
): W3CCredential {
  let result: Partial<CredentialPayload> = deepCopy(input)

  if (isLegacyAttestationFormat(input)) {
    result = attestationToVcFormat(input)
  }

  // FIXME: handle case when credentialSubject(s) are not object types
  result.credentialSubject = { ...input.credentialSubject, ...input.vc?.credentialSubject }
  if (input.sub && !input.credentialSubject?.id && result.credentialSubject) {
    result.credentialSubject.id = input.sub
    if (removeOriginalFields) {
      delete result.sub
    }
  }
  if (removeOriginalFields) {
    delete result.vc?.credentialSubject
  }

  if (typeof input.issuer === 'undefined' || typeof input.issuer === 'object') {
    result.issuer = cleanUndefined({ id: input.iss, ...input.issuer })
    if (removeOriginalFields && !input.issuer?.id) {
      delete result.iss
    }
  }

  if (!input.id && input.jti) {
    result.id = result.id || result.jti
    if (removeOriginalFields) {
      delete result.jti
    }
  }

  const types = [...asArray(result.type), ...asArray(result.vc?.type)].filter(notEmpty)
  result.type = [...new Set(types)]
  if (removeOriginalFields) {
    delete result.vc?.type
  }

  for (const prop of additionalPropNames) {
    if (input.vc && input.vc[prop]) {
      if (!result[prop]) {
        result[prop] = input.vc[prop]
      }
      if (removeOriginalFields) {
        delete result.vc[prop]
      }
    }
  }

  const contextArray: string[] = [
    ...asArray(input.context),
    ...asArray(input['@context']),
    ...asArray(input.vc?.['@context']),
  ].filter(notEmpty)
  result['@context'] = [...new Set(contextArray)]
  if (removeOriginalFields) {
    delete result.context
    delete result.vc?.['@context']
  }

  if (!input.issuanceDate && (input.iat || input.nbf)) {
    result.issuanceDate = new Date((input.nbf || input.iat) * 1000).toISOString()
    if (removeOriginalFields) {
      if (input.nbf) {
        delete result.nbf
      } else {
        delete result.iat
      }
    }
  }

  if (!input.expirationDate && input.exp) {
    result.expirationDate = new Date(input.exp * 1000).toISOString()
    if (removeOriginalFields) {
      delete result.exp
    }
  }

  if (removeOriginalFields) {
    if (result.vc && Object.keys(result.vc).length === 0) {
      delete result.vc
    }
  }

  // FIXME: interpret `aud` property as `verifier`

  return result as W3CCredential
}

function normalizeJwtCredential(input: JWT, removeOriginalFields = true): Verifiable<W3CCredential> {
  let decoded
  try {
    decoded = decodeJWT(input)
  } catch (e) {
    throw new TypeError('unknown credential format')
  }
  return {
    ...normalizeJwtCredentialPayload(decoded.payload, removeOriginalFields),
    proof: {
      type: DEFAULT_JWT_PROOF_TYPE,
      jwt: input,
    },
  }
}

/**
 * Normalizes a credential payload into an unambiguous W3C credential data type
 * In case of conflict, Existing W3C Credential specific properties take precedence,
 * except for arrays and object types which get merged.
 * @param input either a JWT or JWT payload, or a VerifiableCredential
 */
export function normalizeCredential(
  input: Partial<VerifiableCredential> | Partial<JwtCredentialPayload>,
  removeOriginalFields = true
): Verifiable<W3CCredential> {
  if (typeof input === 'string') {
    if (JWT_FORMAT.test(input)) {
      return normalizeJwtCredential(input, removeOriginalFields)
    } else {
      let parsed: Record<string, unknown>
      try {
        parsed = JSON.parse(input)
      } catch (e) {
        throw new TypeError('unknown credential format')
      }
      return normalizeCredential(parsed, removeOriginalFields)
    }
  } else if (input.proof?.jwt) {
    // TODO: test that it correctly propagates app specific proof properties
    return deepCopy({ ...normalizeJwtCredential(input.proof.jwt, removeOriginalFields), proof: input.proof })
  } else {
    // TODO: test that it accepts JWT payload, CredentialPayload, VerifiableCredential
    // TODO: test that it correctly propagates proof, if any
    return { proof: {}, ...normalizeJwtCredentialPayload(input, removeOriginalFields) }
  }
}

/**
 * type used to signal a very loose input is accepted
 */
type DeepPartial<T> = T extends Record<string, unknown> ? { [K in keyof T]?: DeepPartial<T[K]> } : T

/**
 * Transforms a W3C Credential payload into a JWT compatible encoding.
 * The method accepts app specific fields and in case of collision, existing JWT properties will take precedence.
 * Also, `nbf`, `exp` and `jti` properties can be explicitly set to `undefined` and they will be kept intact.
 * @param input either a JWT payload or a CredentialPayloadInput
 */
export function transformCredentialInput(
  input: Partial<CredentialPayload> | DeepPartial<JwtCredentialPayload>,
  removeOriginalFields = true
): JwtCredentialPayload {
  if (Array.isArray(input.credentialSubject)) throw Error('credentialSubject of type array not supported')

  const result: Partial<JwtCredentialPayload> = deepCopy({
    vc: { ...input.vc },
    ...input,
  }) as Partial<JwtCredentialPayload>
  result.vc = result.vc as NonNullable<typeof result.vc>

  const credentialSubject = { ...input.credentialSubject, ...input.vc?.credentialSubject }
  if (!input.sub) {
    result.sub = input.credentialSubject?.id
    if (removeOriginalFields) {
      delete credentialSubject.id
    }
  }

  const contextEntries = [
    ...asArray(input.context),
    ...asArray(input['@context']),
    ...asArray(input.vc?.['@context']),
  ].filter(notEmpty)
  result.vc['@context'] = [...new Set(contextEntries)]
  if (removeOriginalFields) {
    delete result.context
    delete result['@context']
  }

  const types = [...asArray(input.type), ...asArray(input.vc?.type)].filter(notEmpty)
  result.vc.type = [...new Set(types)]
  if (removeOriginalFields) {
    delete result.type
  }

  if (input.id && Object.getOwnPropertyNames(input).indexOf('jti') === -1) {
    result.jti = input.id
    if (removeOriginalFields) {
      delete result.id
    }
  }

  if (input.issuanceDate && Object.getOwnPropertyNames(input).indexOf('nbf') === -1) {
    const converted = Date.parse(input.issuanceDate)
    if (!isNaN(converted)) {
      result.nbf = Math.floor(converted / 1000)
      if (removeOriginalFields) {
        delete result.issuanceDate
      }
    }
  }

  if (input.expirationDate && Object.getOwnPropertyNames(input).indexOf('exp') === -1) {
    const converted = Date.parse(input.expirationDate)
    if (!isNaN(converted)) {
      result.exp = Math.floor(converted / 1000)
      if (removeOriginalFields) {
        delete result.expirationDate
      }
    }
  }

  if (input.issuer && Object.getOwnPropertyNames(input).indexOf('iss') === -1) {
    if (typeof input.issuer === 'object') {
      result.iss = input.issuer?.id
      if (removeOriginalFields) {
        delete result.issuer.id
        if (Object.keys(result.issuer).length === 0) {
          delete result.issuer
        }
      }
    } else if (typeof input.issuer === 'string') {
      result.iss = input.iss || '' + input.issuer
      if (removeOriginalFields) {
        delete result.issuer
      }
    } else {
      // nop
    }
  }

  result.vc.credentialSubject = credentialSubject
  if (removeOriginalFields) {
    delete result.credentialSubject
  }

  for (const prop of additionalPropNames) {
    if (input[prop]) {
      if (!result.vc[prop]) {
        result.vc[prop] = input[prop]
      }
      if (removeOriginalFields) {
        delete result[prop]
      }
    }
  }

  return result as JwtCredentialPayload
}

function normalizeJwtPresentationPayload(
  input: DeepPartial<JwtPresentationPayload>,
  removeOriginalFields = true
): W3CPresentation {
  const result: Partial<PresentationPayload> = deepCopy(input)

  result.verifiableCredential = [
    ...asArray(input.verifiableCredential),
    ...asArray(input.vp?.verifiableCredential),
  ].filter(notEmpty)
  result.verifiableCredential = result.verifiableCredential.map((cred) => {
    return normalizeCredential(cred, removeOriginalFields)
  })
  if (removeOriginalFields) {
    delete result.vp?.verifiableCredential
  }

  if (input.iss && !input.holder) {
    result.holder = input.iss
    if (removeOriginalFields) {
      delete result.iss
    }
  }

  if (input.aud) {
    result.verifier = [...asArray(input.verifier), ...asArray(input.aud)].filter(notEmpty)
    result.verifier = [...new Set(result.verifier)]
    if (removeOriginalFields) {
      delete result.aud
    }
  }

  if (input.jti && Object.getOwnPropertyNames(input).indexOf('id') === -1) {
    result.id = input.id || input.jti
    if (removeOriginalFields) {
      delete result.jti
    }
  }

  const types = [...asArray(input.type), ...asArray(input.vp?.type)].filter(notEmpty)
  result.type = [...new Set(types)]
  if (removeOriginalFields) {
    delete result.vp?.type
  }

  const contexts = [
    ...asArray(input.context),
    ...asArray(input['@context']),
    ...asArray(input.vp?.['@context']),
  ].filter(notEmpty)
  result['@context'] = [...new Set(contexts)]
  if (removeOriginalFields) {
    delete result.context
    delete result.vp?.['@context']
  }

  if (!input.issuanceDate && (input.iat || input.nbf)) {
    result.issuanceDate = new Date((input.nbf || input.iat) * 1000).toISOString()
    if (removeOriginalFields) {
      if (input.nbf) {
        delete result.nbf
      } else {
        delete result.iat
      }
    }
  }

  if (!input.expirationDate && input.exp) {
    result.expirationDate = new Date(input.exp * 1000).toISOString()
    if (removeOriginalFields) {
      delete result.exp
    }
  }

  if (result.vp && Object.keys(result.vp).length === 0) {
    if (removeOriginalFields) {
      delete result.vp
    }
  }

  return result as W3CPresentation
}

function normalizeJwtPresentation(input: JWT, removeOriginalFields = true): Verifiable<W3CPresentation> {
  let decoded
  try {
    decoded = decodeJWT(input)
  } catch (e) {
    throw new TypeError('unknown presentation format')
  }
  return {
    ...normalizeJwtPresentationPayload(decoded.payload, removeOriginalFields),
    proof: {
      type: DEFAULT_JWT_PROOF_TYPE,
      jwt: input,
    },
  }
}

/**
 * Normalizes a presentation payload into an unambiguous W3C Presentation data type
 * @param input either a JWT or JWT payload, or a VerifiablePresentation
 */
export function normalizePresentation(
  input: Partial<PresentationPayload> | DeepPartial<JwtPresentationPayload> | JWT,
  removeOriginalFields = true
): Verifiable<W3CPresentation> {
  if (typeof input === 'string') {
    if (JWT_FORMAT.test(input)) {
      return normalizeJwtPresentation(input, removeOriginalFields)
    } else {
      let parsed: Record<string, unknown>
      try {
        parsed = JSON.parse(input)
      } catch (e) {
        throw new TypeError('unknown presentation format')
      }
      return normalizePresentation(parsed, removeOriginalFields)
    }
  } else if (input.proof?.jwt) {
    // TODO: test that it correctly propagates app specific proof properties
    return { ...normalizeJwtPresentation(input.proof.jwt, removeOriginalFields), proof: input.proof }
  } else {
    // TODO: test that it accepts JWT payload, PresentationPayload, VerifiablePresentation
    // TODO: test that it correctly propagates proof, if any
    return { proof: {}, ...normalizeJwtPresentationPayload(input, removeOriginalFields) }
  }
}

/**
 * Transforms a W3C Presentation payload into a JWT compatible encoding.
 * The method accepts app specific fields and in case of collision, existing JWT properties will take precedence.
 * Also, `nbf`, `exp` and `jti` properties can be explicitly set to `undefined` and they will be kept intact.
 * @param input either a JWT payload or a CredentialPayloadInput
 */
export function transformPresentationInput(
  input: Partial<PresentationPayload> | DeepPartial<JwtPresentationPayload>,
  removeOriginalFields = true
): JwtPresentationPayload {
  const result: Partial<JwtPresentationPayload> = deepCopy({
    vp: { ...input.vp },
    ...input,
  }) as Partial<JwtPresentationPayload>
  result.vp = result.vp as NonNullable<typeof result.vp>

  const contextEntries = [
    ...asArray(input.context),
    ...asArray(input['@context']),
    ...asArray(input.vp?.['@context']),
  ].filter(notEmpty)
  result.vp['@context'] = [...new Set(contextEntries)]
  if (removeOriginalFields) {
    delete result.context
    delete result['@context']
  }

  const types = [...asArray(input.type), ...asArray(input.vp?.type)].filter(notEmpty)
  result.vp.type = [...new Set(types)]
  if (removeOriginalFields) {
    delete result.type
  }

  if (input.id && Object.getOwnPropertyNames(input).indexOf('jti') === -1) {
    result.jti = input.id
    if (removeOriginalFields) {
      delete result.id
    }
  }

  if (input.issuanceDate && Object.getOwnPropertyNames(input).indexOf('nbf') === -1) {
    const converted = Date.parse(input.issuanceDate)
    if (!isNaN(converted)) {
      result.nbf = Math.floor(converted / 1000)
      if (removeOriginalFields) {
        delete result.issuanceDate
      }
    }
  }

  if (input.expirationDate && Object.getOwnPropertyNames(input).indexOf('exp') === -1) {
    const converted = Date.parse(input.expirationDate)
    if (!isNaN(converted)) {
      result.exp = Math.floor(converted / 1000)
      if (removeOriginalFields) {
        delete result.expirationDate
      }
    }
  }

  if (result.verifiableCredential || result.vp?.verifiableCredential) {
    result.vp.verifiableCredential = [
      ...asArray(result.verifiableCredential),
      ...asArray(result.vp?.verifiableCredential),
    ]
      .filter(notEmpty)
      .map((credential: VerifiableCredential) => {
        if (typeof credential === 'object' && credential.proof?.jwt) {
          return credential.proof.jwt
        } else {
          return credential
        }
      })
  }

  if (removeOriginalFields) {
    delete result.verifiableCredential
  }

  if (input.holder && Object.getOwnPropertyNames(input).indexOf('iss') === -1) {
    if (typeof input.holder === 'string') {
      result.iss = input.holder
      if (removeOriginalFields) {
        delete result.holder
      }
    } else {
      // nop
    }
  }

  if (input.verifier) {
    const audience = [...asArray(input.verifier), ...asArray(input.aud)].filter(notEmpty)
    result.aud = [...new Set(audience)]
    if (removeOriginalFields) {
      delete result.verifier
    }
  }

  return result as JwtPresentationPayload
}
