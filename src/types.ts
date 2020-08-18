import { Signer, JWTVerified, JWTPayload } from 'did-jwt'

export interface JwtCredentialSubject {
  [x: string]: any
}

export interface CredentialStatus {
  id: string
  type: string
}

/**
 * A JWT payload representation of a Credential
 * @see https://www.w3.org/TR/vc-data-model/#jwt-encoding
 */
export interface JwtCredentialPayload {
  iss?: string
  sub?: string
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

/**
 * A JWT payload representation of a Presentation
 * @see https://www.w3.org/TR/vc-data-model/#jwt-encoding
 */
export interface JwtPresentationPayload {
  vp: {
    '@context': string[] | string
    type: string[] | string
    verifiableCredential: VerifiableCredential[] | VerifiableCredential
    [x: string]: any
  }
  iss?: string
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
  '@context': string | string[]
  id?: string
  type: string | string[]
  issuer: IssuerType
  issuanceDate: DateType
  expirationDate?: DateType
  credentialSubject: {
    id?: string
    [x: string]: any
  }
  credentialStatus?: CredentialStatus
}

/**
 * A more flexible representation of a {@link W3CCredential} that can be used as input to methods
 * that expect it.
 */
export type CredentialPayload = Extensible<FixedCredentialPayload>

/**
 * This is meant to reflect unambiguous types for the properties in `CredentialPayload`
 */
interface NarrowCredentialDefinitions {
  '@context': string[]
  type: string[]
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
export type W3CCredential = Extensible<Replace<FixedCredentialPayload, NarrowCredentialDefinitions>>

/**
 * used as input when creating Verifiable Presentations
 */
export interface FixedPresentationPayload {
  '@context': string | string[]
  type: string | string[]
  id?: string
  verifiableCredential: VerifiableCredential[]
  holder: string
  verifier?: string | string[]
  issuanceDate?: string
  expirationDate?: string
}

/**
 * A more flexible representation of a {@link W3CPresentation} that can be used as input to methods
 * that expect it.
 */
export type PresentationPayload = Extensible<FixedPresentationPayload>

interface NarrowPresentationDefinitions {
  '@context': string[]
  type: string[]
  verifier: string[]
  verifiableCredential: Verifiable<W3CCredential>[]
}

/**
 * This data type represents a parsed Presentation payload.
 * It is meant to be an unambiguous representation of the properties of a Presentation and is usually the result of a transformation method.
 *
 * The `verifiableCredential` array should contain parsed `Verifiable<Credential>` elements.
 * Any JWT specific properties are transformed to the broader W3C variant and any other app specific properties are left intact.
 */
export type W3CPresentation = Extensible<Replace<FixedPresentationPayload, NarrowPresentationDefinitions>>

export interface Proof {
  type?: string
  [x: string]: any
}

/**
 * Represents a readonly representation of a verifiable object, including the {@link Proof}
 * property that can be used to verify it.
 */
export type Verifiable<T> = Readonly<T> & { readonly proof: Proof }
export type JWT = string

/**
 * A union type for both possible representations of a Credential (JWT and W3C standard)
 *
 * @see https://www.w3.org/TR/vc-data-model/#proof-formats
 */
export type VerifiableCredential = JWT | Verifiable<W3CCredential>

/**
 * A union type for both possible representations of a Presentation (JWT and W3C standard)
 *
 * @see https://www.w3.org/TR/vc-data-model/#proof-formats
 */
export type VerifiablePresentation = JWT | Verifiable<W3CPresentation>

export type VerifiedJWT = JWTVerified

/**
 * Represents the result of a Presentation verification.
 * It includes the properties produced by `did-jwt` and a W3C compliant representation of
 * the Presentation that was just verified.
 *
 * This is usually the result of a verification method and not meant to be created by generic code.
 */
export type VerifiedPresentation = VerifiedJWT & {
  verifiablePresentation: Verifiable<W3CPresentation>
}

/**
 * Represents the result of a Credential verification.
 * It includes the properties produced by `did-jwt` and a W3C compliant representation of
 * the Credential that was just verified.
 *
 * This is usually the result of a verification method and not meant to be created by generic code.
 */
export type VerifiedCredential = VerifiedJWT & {
  verifiableCredential: Verifiable<W3CCredential>
}

/**
 * Represents a tuple of a DID-URL with a `Signer` and associated algorithm.
 */
export interface Issuer {
  did: string
  signer: Signer
  alg?: string
}
