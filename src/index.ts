import { createJWT, Signer } from 'did-jwt'

interface VC {
  '@context': string[]
  type: string[]
  credentialSubject: object
}

interface VerifiableCredentialPayload {
  sub: string
  nbf: number
  vc: VC
  jti?: string
  aud?: string
  exp?: number
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
    alg: 'ES256K-R'
  })
}