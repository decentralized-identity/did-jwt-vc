import { createJWT, Signer } from 'did-jwt'

const JWT_ALG = 'ES256K-R'

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
}

interface VP {
  '@context': string[]
  type: string[]
  verifiableCredential: string[]
}

interface PresentationPayload {
  vp: VP
  aud?:string
  exp?: number
  jti?:string
}

interface Issuer {
  did: string
  signer: Signer
}

export async function createVerifiableCredential(
  payload: VerifiableCredentialPayload,
  issuer: Issuer
): Promise<string> {
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
  return createJWT(payload, {
    issuer: issuer.did,
    signer: issuer.signer,
    alg: JWT_ALG
  })
}