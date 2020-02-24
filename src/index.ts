import { createJWT, verifyJWT } from 'did-jwt'
import { JWT_ALG, DEFAULT_CONTEXT, DEFAULT_VC_TYPE } from './constants'
import * as validators from './validators'
import {
  VerifiableCredentialPayload,
  Issuer,
  PresentationPayload
} from './types'
import { DIDDocument } from 'did-resolver'

export {
  Issuer,
  VerifiableCredentialPayload,
  PresentationPayload,
}

interface Resolvable {
  resolve: (did: string) => Promise<DIDDocument | null>
}

export async function createVerifiableCredential(
  payload: VerifiableCredentialPayload,
  issuer: Issuer
): Promise<string> {
  validateVerifiableCredentialAttributes(payload)
  return createJWT(payload, {
    issuer: issuer.did,
    signer: issuer.signer,
    alg: JWT_ALG
  })
}

export async function createPresentation(
  payload: PresentationPayload,
  issuer: Issuer
): Promise<string> {
  validatePresentationAttributes(payload)
  return createJWT(payload, {
    issuer: issuer.did,
    signer: issuer.signer,
    alg: JWT_ALG
  })
}

export function validateVerifiableCredentialAttributes(
  payload: VerifiableCredentialPayload
): void {
  validators.validateContext(payload.vc['@context'])
  validators.validateVcType(payload.vc.type)
  validators.validateCredentialSubject(payload.vc.credentialSubject)
  if (payload.nbf) validators.validateTimestamp(payload.nbf)
  if (payload.exp) validators.validateTimestamp(payload.exp)
}

export function validatePresentationAttributes(payload: PresentationPayload): void {
  validators.validateContext(payload.vp['@context'])
  validators.validateVpType(payload.vp.type)
  if (payload.vp.verifiableCredential.length < 1) {
    throw new TypeError('vp.verifiableCredential must not be empty')
  }
  for (const vc of payload.vp.verifiableCredential) {
    validators.validateJwtFormat(vc)
  }
  if (payload.exp) validators.validateTimestamp(payload.exp)
}

function isLegacyAttestationFormat(payload: any): boolean {
  // payload is an object and has all the required fields of old attestation format
  return payload instanceof Object && payload.sub && payload.iss && payload.claim && payload.iat
}

function attestationToVcFormat(payload: any): VerifiableCredentialPayload {
  const { iat, nbf, claim, vc, ...rest } = payload
  const result:VerifiableCredentialPayload = {
    ...rest,
    nbf: nbf ? nbf : iat,
    vc: {
      '@context': [DEFAULT_CONTEXT],
      type: [DEFAULT_VC_TYPE],
      credentialSubject: payload.claim
    }
  }
  if (vc) payload.issVc = vc
  return result
}

export async function verifyCredential(vc: string, resolver: Resolvable): Promise<any> {
  const verified = await verifyJWT(vc, { resolver })
  if(isLegacyAttestationFormat(verified.payload)) {
    verified.payload = attestationToVcFormat(verified.payload)
  }
  validateVerifiableCredentialAttributes(verified.payload)
  return verified
}

export async function verifyPresentation(presentation: string, resolver: Resolvable): Promise<any> {
  const verified = await verifyJWT(presentation, { resolver })
  validatePresentationAttributes(verified.payload)
  return verified
}