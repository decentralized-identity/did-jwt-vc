import { Signer } from 'did-jwt'

export interface CredentialSubject {
  [x: string]: any
}

export interface CredentialStatus {
  id: string
  type: string
}

export interface VC {
  '@context': string[]
  type: string[]
  credentialSubject: CredentialSubject
  credentialStatus?: CredentialStatus
}

export interface VerifiableCredentialPayload {
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

export interface PresentationPayload {
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
  alg: string
}
