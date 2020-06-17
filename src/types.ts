import { Signer } from 'did-jwt'

export interface JwtCredentialSubject {
  [x: string]: any
}

export interface CredentialStatus {
  id: string
  type: string
}

export interface JwtVerifiableCredentialPayload {
  sub: string
  vc: {
    '@context': string[]
    type: string[]
    credentialSubject: JwtCredentialSubject
  }
  nbf?: number
  aud?: string
  exp?: number
  jti?: string
  [x: string]: any
}

export interface JwtPresentationPayload {
  vp: {
    '@context': string[]
    type: string[]
    verifiableCredential: string[]
  }
  aud?: string
  nbf?: number
  exp?: number
  jti?: string
  [x: string]: any
}

/**
 * used as input when creating Verifiable Credentials
 */
export interface CredentialPayload {
  '@context': string[]
  id?: string
  type: string[]
  issuer: string
  issuanceDate: Date | string
  expirationDate?: Date | string
  credentialSubject: {
    id: string,
    [x: string]: any
  }
  credentialStatus?: CredentialStatus
  //application specific fields
  [x: string]: any
}

/**
* used as input when creating Verifiable Presentations
*/
export interface PresentationPayload {
  '@context': string[]
  type: string[]
  id?: string
  verifiableCredential: VerifiableCredential[]
  holder: string
}

export interface Proof {
  type?: string
  [x: string]: any
}

export type Verifiable<T> = T & { proof: Proof }
export type JWT = string

export type VerifiablePresentation = Verifiable<PresentationPayload> | JWT
export type VerifiableCredential = Verifiable<CredentialPayload> | JWT

export interface Issuer {
  did: string
  signer: Signer
  alg?: string
}
