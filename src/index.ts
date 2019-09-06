import { createJWT, verifyJWT } from 'did-jwt'
import { JWT_ALG, DEFAULT_CONTEXT, DEFAULT_TYPE } from './constants'
import * as validators from './validators'
import {
  VerifiableCredentialPayload,
  Issuer,
  PresentationPayload
} from './types'

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

function validateVerifiableCredentialAttributes(
  payload: VerifiableCredentialPayload
): void {
  validators.validateContext(payload.vc['@context'])
  validators.validateType(payload.vc.type)
  validators.validateCredentialSubject(payload.vc.credentialSubject)
  if (payload.nbf) validators.validateTimestamp(payload.nbf)
  if (payload.exp) validators.validateTimestamp(payload.exp)
}

function validatePresentationAttributes(payload: PresentationPayload): void {
  validators.validateContext(payload.vp['@context'])
  validators.validateType(payload.vp.type)
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
      type: [DEFAULT_TYPE],
      credentialSubject: payload.claim
    }
  }
  if (vc) payload.issVc = vc
  return result
}

export async function verifyCredential(vc: string): Promise<any> {
  const verified = await verifyJWT(vc)
  if(isLegacyAttestationFormat(verified.payload)) {
    verified.payload = attestationToVcFormat(verified.payload)
  }
  validateVerifiableCredentialAttributes(verified.payload)
  return verified
}
