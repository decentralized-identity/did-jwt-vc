import { Signer, verifyJWT } from 'did-jwt'

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
    '@context': string[] | string
    type: string[] | string
    credentialSubject: JwtCredentialSubject
    [x: string]: any
  }
  nbf?: number
  aud?: string | string[]
  exp?: number
  jti?: string
  [x: string]: any
}

export interface JwtPresentationPayload {
  vp: {
    '@context': string[] | string
    type: string[] | string
    verifiableCredential: VerifiableCredential[] | VerifiableCredential
    [x: string]: any
  }
  aud?: string | string[]
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
interface FixedCredentialPayload {
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
}

export type CredentialPayload = Extensible<FixedCredentialPayload>

/**
 * This is meant to reflect unambiguous types for the properties in `CredentialPayload`
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
type Extensible<T> = T & { [x: string]: any }

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
export type Credential = Extensible<Replace<FixedCredentialPayload, NarrowCredentialDefinitions>>

/**
 * used as input when creating Verifiable Presentations
 */
export interface FixedPresentationPayload {
  '@context': string[]
  type: string[]
  id?: string
  verifiableCredential: VerifiableCredential[]
  holder: string
  verifier?: string[]
  issuanceDate?: string
  expirationDate?: string
}

export type PresentationPayload = Extensible<FixedPresentationPayload>

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
export type Presentation = Extensible<Replace<FixedPresentationPayload, NarrowPresentationDefinitions>>

export interface Proof {
  type?: string
  [x: string]: any
}

export type Verifiable<T> = Readonly<T> & { proof: Proof }
export type JWT = string

export type VerifiablePresentation = Verifiable<Presentation> | JWT
export type VerifiableCredential = JWT | Verifiable<Credential>

type UnpackedPromise<T> = T extends Promise<infer U> ? U : T
export type VerifiedJWT = UnpackedPromise<ReturnType<typeof verifyJWT>>

export type VerifiedPresentation = VerifiedJWT & {
  verifiablePresentation: Verifiable<Presentation>
}

export type VerifiedCredential = VerifiedJWT & {
  verifiableCredential: Verifiable<Credential>
}

export interface Issuer {
  did: string
  signer: Signer
  alg?: string
}
