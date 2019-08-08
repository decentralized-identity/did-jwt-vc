import { createJWT } from 'did-jwt'
import { JWT_ALG } from './constants'
import * as validators from './validators'
import { VerifiableCredentialBuilder } from './VerifiableCredential'
import {
  VerifiableCredentialPayload,
  Issuer,
  PresentationPayload
} from './types'

export { VerifiableCredentialBuilder }

export async function createVerifiableCredential(
  payload: VerifiableCredentialPayload,
  issuer: Issuer
): Promise<string> {
  validateVerifiableCredentialAttributes(payload)
  validators.validateDidFormat(issuer.did)
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
  validators.validateDidFormat(issuer.did)
  return createJWT(payload, {
    issuer: issuer.did,
    signer: issuer.signer,
    alg: JWT_ALG
  })
}

function validateVerifiableCredentialAttributes(
  payload: VerifiableCredentialPayload
): void {
  validators.validateDidFormat(payload.sub)
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
  if (payload.aud) validators.validateDidFormat(payload.aud)
  if (payload.exp) validators.validateTimestamp(payload.exp)
}
