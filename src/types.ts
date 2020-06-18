import { Signer } from 'did-jwt'

export interface JwtCredentialSubject {
  [x: string]: any
}

export interface CredentialStatus {
  id: string
  type: string
}

export interface JwtCredentialPayload {
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

export type IssuerType = { id: string;[x: string]: any } | string
export type DateType = string | Date
/**
 * used as input when creating Verifiable Credentials
 */
export interface CredentialPayload {
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
interface NarrowCredentialDefinitions {
  issuer: Exclude<IssuerType, string>
  issuanceDate: string
  expirationDate?: string
}

/**
 * Replaces the matching property types of T with the ones in U
 */
type Replace<T, U> = Omit<T, keyof U> & U

/**
 * This data type represents a parsed VerifiableCredential.
 * It is meant to be an unambiguous representation of the properties of a Credential and is usually the result of a transformation method.
 * 
 * `issuer` is always an object with an `id` property and potentially other app specific issuer claims
 * `issuanceDate` is an ISO DateTime string
 * `expirationDate`, is a nullable ISO DateTime string
 * 
 * Any JWT specific properties are transformed to the broader W3C variant and any app specific properties are left intact
 */
export type Credential = Replace<CredentialPayload, NarrowCredentialDefinitions>

/**
 * used as input when creating Verifiable Presentations
 */
export interface PresentationPayload {
  '@context': string[]
  type: string[]
  id?: string
  verifiableCredential: VerifiableCredential[]
  holder: string
  verifier?: string[]
  //application specific fields
  [x: string]: any
}

interface NarrowPresentationDefinitions {
  verifiableCredential: Verifiable<Credential>[]
}

/**
 * This data type represents a parsed Presentation payload.
 * It is meant to be an unambiguous representation of the properties of a Presentation and is usually the result of a transformation method.
 * 
 * The `verifiableCredential` array should contain parsed `Verifiable<Credential>` elements.
 * Any JWT specific properties are transformed to the broader W3C variant and any other app specific properties are left intact.
 */
export type Presentation = Replace<PresentationPayload, NarrowPresentationDefinitions>

export interface Proof {
  type?: string
  [x: string]: any
}

export type Verifiable<T> = Readonly<T> & { proof: Proof }
export type JWT = string

export type VerifiablePresentation = Verifiable<Presentation> | JWT
export type VerifiableCredential = Verifiable<Credential> | JWT

export interface Issuer {
  did: string
  signer: Signer
  alg?: string
}
