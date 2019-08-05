import { createJWT, Signer } from 'did-jwt'
import {
  JWT_ALG} from './constants'
import * as validators from './validators'

interface VC {
  '@context': string[]
  type: string[]
  credentialSubject: object
}

interface VerifiableCredentialPayload {
  sub: string
  nbf: number
  vc: VC
  aud?: string
  exp?: number
  jti?: string
  [x: string]: any
}

interface VP {
  '@context': string[]
  type: string[]
  verifiableCredential: string[]
}

interface PresentationPayload {
  vp: VP
  aud?: string
  exp?: number
  jti?: string
  [x: string]: any
}

export interface Issuer {
  did: string
  signer: Signer
}

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
  if (Object.keys(payload.vc.credentialSubject).length === 0) {
    throw new TypeError('vc.credentialSubject must not be empty')
  }
  if(payload.nbf) validators.validateTimestamp(payload.nbf)
  if(payload.exp) validators.validateTimestamp(payload.exp)
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
  if(payload.aud) validators.validateDidFormat(payload.aud)
  if(payload.exp) validators.validateTimestamp(payload.exp)
}
