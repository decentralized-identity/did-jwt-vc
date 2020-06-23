import { createJWT, verifyJWT } from 'did-jwt'
import { JWT_ALG, DEFAULT_CONTEXT, DEFAULT_VC_TYPE, DEFAULT_JWT_PROOF_TYPE } from './constants'
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
  VerifiedPresentation,
  Verified
} from './types'
import { DIDDocument } from 'did-resolver'
import {
  transformCredentialInput,
  transformPresentationInput,
  normalizePresentation,
  normalizeCredential,
  isLegacyAttestationFormat,
  attestationToVcFormat,
  asArray
} from './converters'

export {
  Issuer,
  JwtCredentialPayload,
  JwtPresentationPayload,
  VerifiableCredential,
  VerifiablePresentation,
  VerifiedCredential,
  VerifiedPresentation
}

interface Resolvable {
  resolve: (did: string) => Promise<DIDDocument>
}

export async function createVerifiableCredentialJwt(
  payload: JwtCredentialPayload | CredentialPayload,
  issuer: Issuer
): Promise<JWT> {
  const parsedPayload = transformCredentialInput(payload)
  validateJwtVerifiableCredentialPayload(parsedPayload)
  return createJWT(parsedPayload, {
    issuer: issuer.did,
    signer: issuer.signer,
    alg: issuer.alg || JWT_ALG
  })
}

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

export function validateJwtVerifiableCredentialPayload(payload: JwtCredentialPayload): void {
  validators.validateContext(payload.vc['@context'])
  validators.validateVcType(payload.vc.type)
  validators.validateCredentialSubject(payload.vc.credentialSubject)
  if (payload.nbf) validators.validateTimestamp(payload.nbf)
  if (payload.exp) validators.validateTimestamp(payload.exp)
}

export function validateVerifiableCredentialPayload(payload: CredentialPayload): void {
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
      validateVerifiableCredentialPayload(vc)
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
      validateVerifiableCredentialPayload(vc)
    }
  }
  if (payload.expirationDate) validators.validateTimestamp(payload.expirationDate)
}

export async function verifyCredential(vc: JWT, resolver: Resolvable): Promise<VerifiedCredential> {
  const verified: Partial<VerifiedCredential> = await verifyJWT(vc, { resolver })
  verified.verifiableCredential = normalizeCredential(verified.jwt)
  validateVerifiableCredentialPayload(verified.verifiableCredential)
  return verified as VerifiedCredential
}

export async function verifyPresentation(presentation: JWT, resolver: Resolvable): Promise<VerifiedPresentation> {
  const verified: Partial<VerifiedPresentation> = await verifyJWT(presentation, { resolver })
  verified.verifiablePresentation = normalizePresentation(verified.jwt)
  validatePresentationPayload(verified.verifiablePresentation)
  return verified as VerifiedPresentation
}
