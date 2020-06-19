import {
  VerifiableCredential,
  JWT,
  JwtPresentationPayload,
  JwtCredentialPayload,
  CredentialPayload,
  Credential,
  Verifiable,
  PresentationPayload,
  Presentation
} from './types'
import { decodeJWT } from 'did-jwt'
import { JWT_FORMAT, DEFAULT_JWT_PROOF_TYPE } from './constants'

function asArray(input: any) {
  return Array.isArray(input) ? input : [input]
}

function notEmpty<TValue>(value: TValue | null | undefined): value is TValue {
  return value !== null && value !== undefined
}

function cleanUndefined<T>(input: T): T {
  if (typeof input !== 'object') {
    return input
  }
  const obj = { ...input }
  Object.keys(obj).forEach((key) => obj[key] === undefined && delete obj[key])
  return obj
}

function normalizeJwtCredentialPayload(input: Partial<JwtCredentialPayload>): Credential {
  let result: Partial<CredentialPayload> = { ...input }

  //FIXME: handle case when credentialSubject(s) are not object types
  result.credentialSubject = { ...input.credentialSubject, ...input.vc?.credentialSubject }
  if (input.sub && !input.credentialSubject?.id) {
    result.credentialSubject.id = input.sub
    delete result.sub
  }
  delete result.vc?.credentialSubject

  if (typeof input.issuer === 'undefined' || typeof input.issuer === 'object') {
    result.issuer = cleanUndefined({ id: input.iss, ...input.issuer })
    if (!input.issuer?.id) {
      delete result.iss
    }
  }

  if (!input.id && input.jti) {
    result.id = result.id || result.jti
    delete result.jti
  }

  const types = [...asArray(result.type), ...asArray(result.vc?.type)].filter(notEmpty)
  result.type = [...new Set(types)]
  delete result.vc?.type

  const contextArray: string[] = [
    ...asArray(input.context),
    ...asArray(input['@context']),
    ...asArray(input.vc?.['@context'])
  ].filter(notEmpty)
  result['@context'] = [...new Set(contextArray)]
  delete result.context
  delete result.vc?.['@context']

  if (!input.issuanceDate && (input.iat || input.nbf)) {
    result.issuanceDate = new Date((input.nbf || input.iat) * 1000).toISOString()
    if (input.nbf) {
      delete result.nbf
    } else {
      delete result.iat
    }
  }

  if (!input.expirationDate && input.exp) {
    result.expirationDate = new Date(input.exp * 1000).toISOString()
    delete result.exp
  }

  if (result.vc && Object.keys(result.vc).length == 0) {
    delete result.vc
  }

  //FIXME: interpret `aud` property as `verifier`

  return result as Credential
}

function normalizeJwtCredential(input: JWT): Verifiable<Credential> {
  let decoded
  try {
    decoded = decodeJWT(input)
  } catch (e) {
    const err = new Error('unknown credential format')
    err['cause'] = e
    throw err
  }
  return {
    ...normalizeJwtCredentialPayload(decoded.payload),
    proof: {
      type: DEFAULT_JWT_PROOF_TYPE,
      jwt: input
    }
  }
}

/**
 * Normalizes a credential payload into an unambiguous W3C credential data type
 * In case of conflict, Existing W3C Credential specific properties take precedence,
 * except for arrays and object types which get merged.
 * @param input either a JWT or JWT payload, or a VerifiableCredential
 */
export function normalizeCredential(
  input: Partial<VerifiableCredential> | Partial<JwtCredentialPayload>
): Verifiable<Credential> {
  if (typeof input === 'string') {
    if (JWT_FORMAT.test(input)) {
      return normalizeJwtCredential(input)
    } else {
      let parsed: object
      try {
        parsed = JSON.parse(input)
      } catch (e) {
        const err = new Error('unknown credential format')
        err['cause'] = e
        throw err
      }
      return normalizeCredential(parsed)
    }
  } else if (input.proof?.jwt) {
    //TODO: test that it correctly propagates app specific proof properties
    return { ...normalizeJwtCredential(input.proof.jwt), proof: input.proof }
  } else {
    //TODO: test that it accepts JWT payload, CredentialPayload, VerifiableCredential
    //TODO: test that it correctly propagates proof, if any
    return { proof: {}, ...normalizeJwtCredentialPayload(input) }
  }
}

/**
 * type used to signal a very loose input is accepted
 */
type DeepPartial<T> = T extends object ? { [K in keyof T]?: DeepPartial<T[K]> } : T

/**
 * Transforms a W3C Credential payload into a JWT compatible encoding.
 * The method accepts app specific fields and in case of collision, existing JWT properties will take precedence.
 * Also, `nbf`, `exp` and `jti` properties can be explicitly set to `undefined` and they will be kept intact.
 * @param input either a JWT payload or a CredentialPayloadInput
 */
export function transformCredentialInput(
  input: Partial<CredentialPayload> | DeepPartial<JwtCredentialPayload>
): JwtCredentialPayload {
  if (Array.isArray(input.credentialSubject)) throw Error('credentialSubject of type array not supported')

  const result: Partial<JwtCredentialPayload> = { vc: { ...input.vc }, ...input }

  const credentialSubject = { ...input.credentialSubject, ...input.vc?.credentialSubject }
  if (!input.sub) {
    result.sub = input.credentialSubject?.id
    delete credentialSubject.id
  }
  result.vc.credentialSubject = credentialSubject
  delete result.credentialSubject

  const contextEntries = [
    ...asArray(input.context),
    ...asArray(input['@context']),
    ...asArray(input.vc?.['@context'])
  ].filter(notEmpty)
  result.vc['@context'] = [...new Set(contextEntries)]
  delete result.context
  delete result['@context']

  const types = [...asArray(input.type), ...asArray(input.vc?.type)].filter(notEmpty)
  result.vc.type = [...new Set(types)]
  delete result.type

  if (input.id && Object.getOwnPropertyNames(input).indexOf('jti') == -1) {
    result.jti = input.id
    delete result.id
  }

  if (input.issuanceDate && Object.getOwnPropertyNames(input).indexOf('nbf') == -1) {
    const converted = Date.parse(input.issuanceDate)
    if (!isNaN(converted)) {
      result.nbf = converted / 1000
      delete result.issuanceDate
    }
  }

  if (input.expirationDate && Object.getOwnPropertyNames(input).indexOf('exp') == -1) {
    const converted = Date.parse(input.expirationDate)
    if (!isNaN(converted)) {
      result.exp = converted / 1000
      delete result.expirationDate
    }
  }

  if (input.issuer && Object.getOwnPropertyNames(input).indexOf('iss') == -1) {
    if (typeof input.issuer === 'object') {
      result.iss = input.issuer?.id
      delete result.issuer.id
      if (Object.keys(result.issuer).length == 0) {
        delete result.issuer
      }
    } else if (typeof input.issuer === 'string') {
      result.iss = input.iss || '' + input.issuer
      delete result.issuer
    } else {
      //nop
    }
  }

  return result as JwtCredentialPayload
}

function normalizeJwtPresentationPayload(input: DeepPartial<JwtPresentationPayload>): Presentation {
  let result: Partial<PresentationPayload> = { ...input }

  result.verifiableCredential = [
    ...asArray(input.verifiableCredential),
    ...asArray(input.vp?.verifiableCredential)
  ].filter(notEmpty)
  result.verifiableCredential = result.verifiableCredential.map(normalizeCredential)

  if (input.iss && !input.holder) {
    result.holder = input.iss
    delete result.iss
  }

  if (input.aud) {
    result.verifier = [...asArray(input.verifier), ...asArray(input.aud)].filter(notEmpty)
    result.verifier = [...new Set(result.verifier)]
    delete result.aud
  }

  if (input.jti && Object.getOwnPropertyNames(input).indexOf('id') == -1) {
    result.id = input.id || input.jti
    delete result.jti
  }

  const types = [...asArray(input.type), ...asArray(input.vp?.type)].filter(notEmpty)
  result.type = [...new Set(types)]
  delete result.vp?.type

  const contexts = [
    ...asArray(input.context),
    ...asArray(input['@context']),
    ...asArray(input.vp?.['@context'])
  ].filter(notEmpty)
  result['@context'] = [...new Set(contexts)]
  delete result.context
  delete result.vp?.['@context']

  if (!input.issuanceDate && (input.iat || input.nbf)) {
    result.issuanceDate = new Date((input.nbf || input.iat) * 1000).toISOString()
    if (input.nbf) {
      delete result.nbf
    } else {
      delete result.iat
    }
  }

  if (!input.expirationDate && input.exp) {
    result.expirationDate = new Date(input.exp * 1000).toISOString()
    delete result.exp
  }

  if (result.vp && Object.keys(result.vp).length == 0) {
    delete result.vp
  }

  return result as Presentation
}

function normalizeJwtPresentation(input: JWT): Verifiable<Presentation> {
  let decoded
  try {
    decoded = decodeJWT(input)
  } catch (e) {
    const err = new Error('unknown presentation format')
    err['cause'] = e
    throw err
  }
  return {
    ...normalizeJwtPresentationPayload(decoded.payload),
    proof: {
      type: DEFAULT_JWT_PROOF_TYPE,
      jwt: input
    }
  }
}

/**
 * Normalizes a presentation payload into an unambiguous W3C Presentation data type
 * @param input either a JWT or JWT payload, or a VerifiablePresentation
 */
export function normalizePresentation(
  input: Partial<PresentationPayload> | Partial<JwtPresentationPayload> | JWT
): Verifiable<Presentation> {
  if (typeof input === 'string') {
    if (JWT_FORMAT.test(input)) {
      return normalizeJwtPresentation(input)
    } else {
      let parsed: object
      try {
        parsed = JSON.parse(input)
      } catch (e) {
        const err = new Error('unknown presentation format')
        err['cause'] = e
        throw err
      }
      return normalizePresentation(parsed)
    }
  } else if (input.proof?.jwt) {
    //TODO: test that it correctly propagates app specific proof properties
    return { ...normalizeJwtPresentation(input.proof.jwt), proof: input.proof }
  } else {
    //TODO: test that it accepts JWT payload, PresentationPayload, VerifiablePresentation
    //TODO: test that it correctly propagates proof, if any
    return { proof: {}, ...normalizeJwtPresentationPayload(input) }
  }
}

/**
 * Transforms a W3C Presentation payload into a JWT compatible encoding.
 * The method accepts app specific fields and in case of collision, existing JWT properties will take precedence.
 * Also, `nbf`, `exp` and `jti` properties can be explicitly set to `undefined` and they will be kept intact.
 * @param input either a JWT payload or a CredentialPayloadInput
 */
export function transformPresentationInput(
  input: Partial<PresentationPayload> | Partial<JwtPresentationPayload>
): JwtPresentationPayload {
  const result: Partial<JwtPresentationPayload> = { vp: { ...input.vp }, ...input }

  const contextEntries = [
    ...asArray(input.context),
    ...asArray(input['@context']),
    ...asArray(input.vp?.['@context'])
  ].filter(notEmpty)
  result.vp['@context'] = [...new Set(contextEntries)]
  delete result.context
  delete result['@context']

  const types = [...asArray(input.type), ...asArray(input.vp?.type)].filter(notEmpty)
  result.vp.type = [...new Set(types)]
  delete result.type

  if (input.id && Object.getOwnPropertyNames(input).indexOf('jti') == -1) {
    result.jti = input.id
    delete result.id
  }

  if (input.issuanceDate && Object.getOwnPropertyNames(input).indexOf('nbf') == -1) {
    const converted = Date.parse(input.issuanceDate)
    if (!isNaN(converted)) {
      result.nbf = converted / 1000
      delete result.issuanceDate
    }
  }

  if (input.expirationDate && Object.getOwnPropertyNames(input).indexOf('exp') == -1) {
    const converted = Date.parse(input.expirationDate)
    if (!isNaN(converted)) {
      result.exp = converted / 1000
      delete result.expirationDate
    }
  }

  result.vp.verifiableCredential = [
    ...asArray(result.verifiableCredential),
    ...asArray(result.vp?.verifiableCredential)
  ]
  .filter(notEmpty)
  .map((credential: VerifiableCredential) => {
    if (typeof credential === 'object' && credential.proof?.jwt) {
      return credential.proof.jwt
    } else {
      return credential
    }
  })
  delete result.verifiableCredential

  if (input.holder && Object.getOwnPropertyNames(input).indexOf('iss') == -1) {
    if (typeof input.holder === 'string') {
      result.iss = input.holder
      delete result.holder
    } else {
      //nop
    }
  }

  if (input.verifier) {
    const audience = [...asArray(input.verifier), ...asArray(input.aud)].filter(notEmpty)
    result.aud = [...new Set(audience)]
    delete result.verifier
  }

  return result as JwtPresentationPayload
}
