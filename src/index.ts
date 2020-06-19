import { createJWT, verifyJWT } from 'did-jwt'
import { JWT_ALG, DEFAULT_CONTEXT, DEFAULT_VC_TYPE } from './constants'
import * as validators from './validators'
import {
  JwtCredentialPayload,
  Issuer,
  JwtPresentationPayload,
  JWT,
  VerifiablePresentation,
  VerifiableCredential
} from './types'
import { DIDDocument } from 'did-resolver'

export { Issuer, JwtCredentialPayload, JwtPresentationPayload, VerifiableCredential, VerifiablePresentation }

interface Resolvable {
  resolve: (did: string) => Promise<DIDDocument>
}

export async function createVerifiableCredentialJwt(payload: JwtCredentialPayload, issuer: Issuer): Promise<JWT> {
  validateJwtVerifiableCredentialPayload(payload)
  return createJWT(payload, {
    issuer: issuer.did,
    signer: issuer.signer,
    alg: issuer.alg || JWT_ALG
  })
}

export async function createPresentationJwt(payload: JwtPresentationPayload, issuer: Issuer): Promise<JWT> {
  validateJwtPresentationPayload(payload)
  return createJWT(payload, {
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

export function validateJwtPresentationPayload(payload: JwtPresentationPayload): void {
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

function attestationToVcFormat(payload: any): JwtCredentialPayload {
  const { iat, nbf, claim, vc, ...rest } = payload
  const result: JwtCredentialPayload = {
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

export async function verifyCredential(vc: JWT, resolver: Resolvable): Promise<any> {
  const verified = await verifyJWT(vc, { resolver })
  if (isLegacyAttestationFormat(verified.payload)) {
    verified.payload = attestationToVcFormat(verified.payload)
  }
  validateJwtVerifiableCredentialPayload(verified.payload)
  return verified
}

export async function verifyPresentation(presentation: JWT, resolver: Resolvable): Promise<any> {
  const verified = await verifyJWT(presentation, { resolver })
  validateJwtPresentationPayload(verified.payload)
  return verified
}
