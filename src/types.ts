import { Signer } from 'did-jwt'

export interface JwtCredentialSubject {
  [x: string]: any
}

export interface CredentialStatus {
  id: string
  type: string
}

export interface VC {
  '@context': string[]
  type: string[]
  credentialSubject: JwtCredentialSubject
}

export interface JwtVerifiableCredentialPayload {
  sub: string
  vc: VC
  nbf?: number
  aud?: string
  exp?: number
  jti?: string
  [x: string]: any
}

export interface VP {
  '@context': string[]
  type: string[]
  verifiableCredential: string[]
}

export interface JwtPresentationPayload {
  vp: VP
  aud?: string
  nbf?: number
  exp?: number
  jti?: string
  [x: string]: any
}

export interface Issuer {
  did: string
  signer: Signer
  alg?: string
}
