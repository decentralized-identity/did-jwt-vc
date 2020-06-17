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

export type IssuerType = { id: string; [x: string]: any } | string
export type DateType = string | Date
/**
 * used as input when creating Verifiable Credentials
 */
export interface CredentialPayloadInput {
  '@context': string[]
  id?: string
  type: string[]
  issuer: IssuerType
  issuanceDate: DateType
  expirationDate?: DateType
  credentialSubject: {
    id: string
    [x: string]: any
  }
  credentialStatus?: CredentialStatus
  //application specific fields
  [x: string]: any
}

/**
 * This is meant to reflect unambiguous types for the properties in `CredentialPayloadInput`
 */
interface NarrowDefinitions {
  issuer: Exclude<IssuerType, string>
  issuanceDate: string
  expirationDate?: string
}

/**
 * Replaces the matching property types of T with the ones in U
 */
type Replace<T, U> = Omit<T, keyof U> & U

export type Credential = Replace<CredentialPayloadInput, NarrowDefinitions>

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

export type Verifiable<T> = Readonly<T> & { proof: Proof }
export type JWT = string

export type VerifiablePresentation = Verifiable<PresentationPayload> | JWT
export type VerifiableCredential = Verifiable<CredentialPayloadInput> | JWT

export interface Issuer {
  did: string
  signer: Signer
  alg?: string
}
