import { createJWT, createMultisignatureJWT, verifyJWT } from 'did-jwt'
import type { Resolvable } from 'did-resolver'
import * as validators from './validators.js'
import { VC_ERROR } from './validators.js'
import type {
  CreateCredentialOptions,
  CreatePresentationOptions,
  CredentialPayload,
  Issuer,
  JWT,
  JwtCredentialPayload,
  JwtPresentationPayload,
  PresentationPayload,
  Verifiable,
  VerifiableCredential,
  VerifiablePresentation,
  VerifiedCredential,
  VerifiedPresentation,
  VerifyCredentialOptions,
  VerifyCredentialPolicies,
  VerifyPresentationOptions,
  W3CCredential,
  W3CPresentation,
} from './types.js'
import { JWT_ALG } from './types.js'
import {
  asArray,
  normalizeCredential,
  normalizePresentation,
  notEmpty,
  transformCredentialInput,
  transformPresentationInput,
} from './converters.js'

export { VC_ERROR, VC_JWT_ERROR } from './validators.js'

export type {
  Issuer,
  CredentialPayload,
  PresentationPayload,
  JwtCredentialPayload,
  JwtPresentationPayload,
  VerifiableCredential,
  VerifiablePresentation,
  VerifiedCredential,
  VerifiedPresentation,
  Verifiable,
  W3CCredential,
  W3CPresentation,
  CreateCredentialOptions,
  CreatePresentationOptions,
  VerifyCredentialOptions,
  VerifyCredentialPolicies,
  VerifyPresentationOptions,
}

export { transformCredentialInput, transformPresentationInput, normalizeCredential, normalizePresentation }

/**
 * Creates a VerifiableCredential given a `CredentialPayload` or `JwtCredentialPayload` and an `Issuer`.
 *
 * This method transforms the payload into the [JWT encoding](https://www.w3.org/TR/vc-data-model/#jwt-encoding)
 * described in the [W3C VC spec](https://www.w3.org/TR/vc-data-model) and then validated to conform to the minimum
 * spec
 * required spec.
 *
 * The `issuer` is then used to assign an algorithm, override the `iss` field of the payload and then sign the JWT.
 *
 * @param payload - `CredentialPayload` or `JwtCredentialPayload`
 * @param issuer - `Issuer` the DID, signer and algorithm that will sign the token
 * @param options - Use these options to tweak the creation of the JWT Credential. These are forwarded to did-jwt.
 * @return a `Promise` that resolves to the JWT encoded verifiable credential or rejects with `TypeError` if the
 * `payload` is not W3C compliant
 */
export async function createVerifiableCredentialJwt(
  payload: JwtCredentialPayload | CredentialPayload,
  issuer: Issuer | Issuer[],
  options: CreateCredentialOptions = {}
): Promise<JWT> {
  const parsedPayload: JwtCredentialPayload = {
    iat: undefined,
    ...transformCredentialInput(payload, options.removeOriginalFields),
  }
  validateJwtCredentialPayload(parsedPayload)

  if (!Array.isArray(issuer)) {
    return createJWT(
      parsedPayload,
      {
        ...options,
        issuer: issuer.did || parsedPayload.iss || '',
        signer: issuer.signer,
      },
      {
        ...options.header,
        alg: issuer.alg || options.header?.alg || JWT_ALG,
      }
    )
  } else {
    const did = issuer[0].did
    const issuers = []
    for (const iss of issuer) {
      if (iss.did !== did) {
        throw new Error('All issuers must be the same did to comply with the Verifiable Conditions spec')
      }
      issuers.push({
        issuer: iss.did || parsedPayload.iss || '',
        signer: iss.signer,
        alg: iss.alg || options.header?.alg || JWT_ALG,
      })
    }

    return createMultisignatureJWT(parsedPayload, { ...options }, issuers)
  }
}

/**
 * Creates a VerifiablePresentation JWT given a `PresentationPayload` or `JwtPresentationPayload` and an `Issuer`.
 *
 * This method transforms the payload into the [JWT encoding](https://www.w3.org/TR/vc-data-model/#jwt-encoding)
 * described in the [W3C VC spec](https://www.w3.org/TR/vc-data-model) and then validated to conform to the minimum
 * spec
 * required spec.
 *
 * The `holder` is then used to assign an algorithm, override the `iss` field of the payload and then sign the JWT.
 *
 * @param payload - `PresentationPayload` or `JwtPresentationPayload`
 * @param holder - `Issuer` of the Presentation JWT (holder of the VC), signer and algorithm that will sign the token
 * @param options - `CreatePresentationOptions` allows to pass additional values to the resulting JWT payload. These
 *   options are forwarded to did-jwt.
 * @return a `Promise` that resolves to the JWT encoded verifiable presentation or rejects with `TypeError` if the
 * `payload` is not W3C compliant
 */
export async function createVerifiablePresentationJwt(
  payload: JwtPresentationPayload | PresentationPayload,
  holder: Issuer,
  options: CreatePresentationOptions = {}
): Promise<JWT> {
  const parsedPayload: JwtPresentationPayload = {
    iat: undefined,
    ...transformPresentationInput(payload, options?.removeOriginalFields),
  }

  // add challenge to nonce
  if (options.challenge && Object.getOwnPropertyNames(parsedPayload).indexOf('nonce') === -1) {
    parsedPayload.nonce = options.challenge
  }

  // add domain to audience.
  if (options.domain) {
    const audience = [...asArray(options.domain), ...asArray(parsedPayload.aud)].filter(notEmpty)
    parsedPayload.aud = [...new Set(audience)]
  }

  validateJwtPresentationPayload(parsedPayload)
  return createJWT(
    parsedPayload,
    {
      ...options,
      issuer: holder.did || parsedPayload.iss || '',
      signer: holder.signer,
    },
    {
      ...options.header,
      alg: holder.alg || options.header?.alg || JWT_ALG,
    }
  )
}

export function validateJwtCredentialPayload(payload: JwtCredentialPayload): void {
  validators.validateContext(payload.vc['@context'])
  validators.validateVcType(payload.vc.type)
  validators.validateCredentialSubject(payload.vc.credentialSubject)
  if (payload.nbf) validators.validateTimestamp(payload.nbf)
  if (payload.exp) validators.validateTimestamp(payload.exp)
}

export function validateCredentialPayload(payload: CredentialPayload): void {
  validators.validateContext(payload['@context'])
  validators.validateVcType(payload.type)
  validators.validateCredentialSubject(payload.credentialSubject)
  if (payload.issuanceDate) validators.validateTimestamp(payload.issuanceDate)
  if (payload.expirationDate) validators.validateTimestamp(payload.expirationDate)
}

export function validateJwtPresentationPayload(payload: JwtPresentationPayload): void {
  validators.validateContext(payload.vp['@context'])
  validators.validateVpType(payload.vp.type)
  // empty credential array is allowed
  if (payload.vp.verifiableCredential && payload.vp.verifiableCredential.length >= 1) {
    for (const vc of asArray(payload.vp.verifiableCredential)) {
      if (typeof vc === 'string') {
        validators.validateJwtFormat(vc)
      } else {
        validateCredentialPayload(vc)
      }
    }
  }
  if (payload.exp) validators.validateTimestamp(payload.exp)
}

export function validatePresentationPayload(payload: PresentationPayload): void {
  validators.validateContext(payload['@context'])
  validators.validateVpType(payload.type)
  // empty credential array is allowed
  if (payload.verifiableCredential && payload.verifiableCredential.length >= 1) {
    for (const vc of payload.verifiableCredential) {
      if (typeof vc === 'string') {
        validators.validateJwtFormat(vc)
      } else {
        validateCredentialPayload(vc)
      }
    }
  }
  if (payload.expirationDate) validators.validateTimestamp(payload.expirationDate)
}

/**
 * Verifies and validates a VerifiableCredential that is encoded as a JWT according to the W3C spec.
 *
 * @return a `Promise` that resolves to a `VerifiedCredential` or rejects with `TypeError` if the input is not
 * W3C compliant
 * @param vc - the credential to be verified. Currently only the JWT encoding is supported by this library
 * @param resolver - a configured `Resolver` (or an implementation of `Resolvable`) that can provide the DID document
 *   of the JWT issuer
 * @param options - optional tweaks to the verification process. These are forwarded to did-jwt.
 */
export async function verifyCredential(
  vc: JWT,
  resolver: Resolvable,
  options: VerifyCredentialOptions = {}
): Promise<VerifiedCredential> {
  const nbf = options?.policies?.issuanceDate === false ? false : undefined
  const exp = options?.policies?.expirationDate === false ? false : undefined
  options = { ...options, policies: { ...options?.policies, nbf, exp, iat: nbf } }
  const verified: Partial<VerifiedCredential> = await verifyJWT(vc, { resolver, ...options })
  verified.verifiableCredential = normalizeCredential(verified.jwt as string, options?.removeOriginalFields)
  if (options?.policies?.format !== false) {
    validateCredentialPayload(verified.verifiableCredential)
  }
  return verified as VerifiedCredential
}

/**
 * Verifies that the given JwtPresentationPayload contains the appropriate options from VerifyPresentationOptions
 *
 * @param payload - the JwtPresentationPayload to verify against
 * @param options - the VerifyPresentationOptions that contain the optional values to verify.
 * @throws {Error} If VerifyPresentationOptions are not satisfied
 */
export function verifyPresentationPayloadOptions(
  payload: JwtPresentationPayload,
  options: VerifyPresentationOptions
): void {
  if (options.challenge && options.challenge !== payload.nonce) {
    throw new Error(
      `${VC_ERROR.AUTH_ERROR}: Presentation does not contain the mandatory challenge (JWT: nonce) for : ${options.challenge}`
    )
  }

  if (options.domain) {
    // aud might be an array
    let matchedAudience
    if (payload.aud) {
      const audArray = Array.isArray(payload.aud) ? payload.aud : [payload.aud]
      matchedAudience = audArray.find((item) => options.domain === item)
    }

    if (typeof matchedAudience === 'undefined') {
      throw new Error(
        `${VC_ERROR.AUTH_ERROR}: Presentation does not contain the mandatory domain (JWT: aud) for : ${options.domain}`
      )
    }
  }
}

/**
 * Verifies and validates a VerifiablePresentation that is encoded as a JWT according to the W3C spec.
 *
 * @return a `Promise` that resolves to a `VerifiedPresentation` or rejects with `TypeError` if the input is
 * not W3C compliant or the VerifyPresentationOptions are not satisfied.
 * @param presentation - the presentation to be verified. Currently only the JWT encoding is supported by this library
 * @param resolver - a configured `Resolver` or an implementation of `Resolvable` that can provide the DID document of
 *   the JWT issuer (presentation holder)
 * @param options - optional verification options that need to be satisfied. These are also forwarded to did-jwt.
 */
export async function verifyPresentation(
  presentation: JWT,
  resolver: Resolvable,
  options: VerifyPresentationOptions = {}
): Promise<VerifiedPresentation> {
  const nbf = options?.policies?.issuanceDate === false ? false : undefined
  const exp = options?.policies?.expirationDate === false ? false : undefined
  options = { audience: options.domain, ...options, policies: { ...options?.policies, nbf, exp, iat: nbf } }
  const verified: Partial<VerifiedPresentation> = await verifyJWT(presentation, {
    resolver,
    ...options,
  })
  verifyPresentationPayloadOptions(verified.payload as JwtPresentationPayload, options)
  verified.verifiablePresentation = normalizePresentation(verified.jwt as string, options?.removeOriginalFields)
  if (options?.policies?.format !== false) {
    validatePresentationPayload(verified.verifiablePresentation)
  }
  return verified as VerifiedPresentation
}
