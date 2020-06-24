import { createJWT, verifyJWT } from 'did-jwt'
import { JWT_ALG } from './constants'
import * as validators from './validators'
import {
  JwtCredentialPayload,
  Issuer,
  JwtPresentationPayload,
  JWT,
  VerifiablePresentation,
  VerifiableCredential,
  CredentialPayload,
  PresentationPayload,
  Verifiable,
  Credential,
  Presentation,
  VerifiedCredential,
  VerifiedPresentation
} from './types'
import { DIDDocument } from 'did-resolver'
import {
  transformCredentialInput,
  transformPresentationInput,
  normalizeCredential,
  normalizePresentation,
  asArray
} from './converters'

export {
  Issuer,
  JwtCredentialPayload,
  JwtPresentationPayload,
  VerifiableCredential,
  VerifiablePresentation,
  VerifiedCredential,
  VerifiedPresentation,
  Verifiable,
  Credential,
  Presentation,
  transformCredentialInput,
  transformPresentationInput,
  normalizeCredential,
  normalizePresentation
}

interface Resolvable {
  resolve: (did: string) => Promise<DIDDocument>
}

/**
 * Creates a VerifiableCredential given a `CredentialPayload` or `JwtCredentialPayload` and an `Issuer`.
 *
 * This method transforms the payload into the [JWT encoding](https://www.w3.org/TR/vc-data-model/#jwt-encoding)
 * described in the [W3C VC spec](https://www.w3.org/TR/vc-data-model) and then validated to conform to the minimum spec
 * required spec.
 *
 * The `issuer` is then used to assign an algorithm, override the `iss` field of the payload and then sign the JWT.
 *
 * @param payload `CredentialPayload` or `JwtCredentialPayload`
 * @param issuer `Issuer` the DID, signer and algorithm that will sign the token
 * @return a `Promise` that resolves to the JWT encoded verifiable credential or rejects with `TypeError` if the
 * `payload` is not W3C compliant
 */
export async function createVerifiableCredentialJwt(
  payload: JwtCredentialPayload | CredentialPayload,
  issuer: Issuer
): Promise<JWT> {
  const parsedPayload = transformCredentialInput(payload)
  validateJwtCredentialPayload(parsedPayload)
  return createJWT(parsedPayload, {
    issuer: issuer.did,
    signer: issuer.signer,
    alg: issuer.alg || JWT_ALG
  })
}

/**
 * Creates a VerifiablePresentation JWT given a `PresentationPayload` or `JwtPresentationPayload` and an `Issuer`.
 *
 * This method transforms the payload into the [JWT encoding](https://www.w3.org/TR/vc-data-model/#jwt-encoding)
 * described in the [W3C VC spec](https://www.w3.org/TR/vc-data-model) and then validated to conform to the minimum spec
 * required spec.
 *
 * The `issuer` is then used to assign an algorithm, override the `iss` field of the payload and then sign the JWT.
 *
 * @param payload `PresentationPayload` or `JwtPresentationPayload`
 * @param issuer `Issuer` the DID, signer and algorithm that will sign the token
 * @return a `Promise` that resolves to the JWT encoded verifiable presentation or rejects with `TypeError` if the
 * `payload` is not W3C compliant
 */
export async function createVerifiablePresentationJwt(
  payload: JwtPresentationPayload | PresentationPayload,
  issuer: Issuer
): Promise<JWT> {
  const parsedPayload = transformPresentationInput(payload)
  validateJwtPresentationPayload(parsedPayload)
  return createJWT(parsedPayload, {
    issuer: issuer.did,
    signer: issuer.signer,
    alg: issuer.alg || JWT_ALG
  })
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
  if (payload.issuanceDate) validators.validateTimestamp(new Date(payload.issuanceDate).valueOf() / 1000)
  if (payload.expirationDate) validators.validateTimestamp(new Date(payload.expirationDate).valueOf() / 1000)
}

export function validateJwtPresentationPayload(payload: JwtPresentationPayload): void {
  validators.validateContext(payload.vp['@context'])
  validators.validateVpType(payload.vp.type)
  if (payload.vp.verifiableCredential.length < 1) {
    throw new TypeError('vp.verifiableCredential must not be empty')
  }
  for (const vc of asArray(payload.vp.verifiableCredential)) {
    if (typeof vc === 'string') {
      validators.validateJwtFormat(vc)
    } else {
      validateCredentialPayload(vc)
    }
  }
  if (payload.exp) validators.validateTimestamp(payload.exp)
}

export function validatePresentationPayload(payload: PresentationPayload): void {
  validators.validateContext(payload['@context'])
  validators.validateVpType(payload.type)
  if (payload.verifiableCredential.length < 1) {
    throw new TypeError('vp.verifiableCredential must not be empty')
  }
  for (const vc of payload.verifiableCredential) {
    if (typeof vc === 'string') {
      validators.validateJwtFormat(vc)
    } else {
      validateCredentialPayload(vc)
    }
  }
  if (payload.expirationDate) validators.validateTimestamp(payload.expirationDate)
}

/**
 * Verifies and validates a VerifiableCredential that is encoded as a JWT according to the W3C spec.
 *
 * @return a `Promise` that resolves to a `VerifiedCredential` or rejects with `TypeError` if the input is not
 * W3C compliant
 * @param vc the credential to be verified. Currently only the JWT encoding is supported by this library
 * @param resolver a configured `Resolver` that can provide the DID document of the JWT issuer
 */
export async function verifyCredential(vc: JWT, resolver: Resolvable): Promise<VerifiedCredential> {
  const verified: Partial<VerifiedCredential> = await verifyJWT(vc, { resolver })
  verified.verifiableCredential = normalizeCredential(verified.jwt)
  validateCredentialPayload(verified.verifiableCredential)
  return verified as VerifiedCredential
}

/**
 * Verifies and validates a VerifiablePresentation that is encoded as a JWT according to the W3C spec.
 *
 * @return a `Promise` that resolves to a `VerifiedPresentation` or rejects with `TypeError` if the input is
 * not W3C compliant
 * @param presentation the presentation to be verified. Currently only the JWT encoding is supported by this library
 * @param resolver a configured `Resolver` that can provide the DID document of the JWT issuer (presentation holder)
 */
export async function verifyPresentation(presentation: JWT, resolver: Resolvable): Promise<VerifiedPresentation> {
  const verified: Partial<VerifiedPresentation> = await verifyJWT(presentation, { resolver })
  verified.verifiablePresentation = normalizePresentation(verified.jwt)
  validatePresentationPayload(verified.verifiablePresentation)
  return verified as VerifiedPresentation
}
