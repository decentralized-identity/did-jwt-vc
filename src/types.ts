import { Signer, JWTVerified, JWTHeader, JWTOptions } from 'did-jwt'

export const JWT_ALG = 'ES256K'
export const DID_FORMAT = /^did:([a-zA-Z0-9_]+):([:[a-zA-Z0-9_.-]+)(\/[^#]*)?(#.*)?$/
export const JWT_FORMAT = /^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/
export const DEFAULT_CONTEXT = 'https://www.w3.org/2018/credentials/v1'
export const DEFAULT_VC_TYPE = 'VerifiableCredential'
export const DEFAULT_VP_TYPE = 'VerifiablePresentation'
export const DEFAULT_JWT_PROOF_TYPE = 'JwtProof2020'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type JwtCredentialSubject = Record<string, any>

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
  vc: Extensible<{
    '@context': string[] | string
    type: string[] | string
    credentialSubject: JwtCredentialSubject
    credentialStatus?: CredentialStatus
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    evidence?: any
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    termsOfUse?: any
  }>
  nbf?: number
  aud?: string | string[]
  exp?: number
  jti?: string
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any
}

/**
 * A JWT payload representation of a Presentation
 * @see https://www.w3.org/TR/vc-data-model/#jwt-encoding
 */
export interface JwtPresentationPayload {
  vp: Extensible<{
    '@context': string[] | string
    type: string[] | string
    verifiableCredential?: VerifiableCredential[] | VerifiableCredential
  }>
  iss?: string
  aud?: string | string[]
  nbf?: number
  exp?: number
  jti?: string
  nonce?: string
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any
}

export type IssuerType = Extensible<{ id: string }> | string
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
  credentialSubject: Extensible<{
    id?: string
  }>
  credentialStatus?: CredentialStatus
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  evidence?: any
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  termsOfUse?: any
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
// eslint-disable-next-line @typescript-eslint/no-explicit-any
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
  verifiableCredential?: VerifiableCredential[]
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
  verifiableCredential?: Verifiable<W3CCredential>[]
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
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
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

/**
 * Represents the Creation Options that can be passed to the createVerifiableCredentialJwt method.
 */
export interface CreateCredentialOptions extends Partial<JWTOptions> {
  /**
   * Determines whether the JSON->JWT transformation will remove the original fields from the input payload.
   * See https://www.w3.org/TR/vc-data-model/#jwt-encoding
   *
   * @default true
   */
  removeOriginalFields?: boolean

  /**
   * Allows including or overriding some header parameters for the resulting JWT.
   * If the issuer or holder does not list an `alg`, then the one specified in `header` will be used
   */
  header?: Partial<JWTHeader>

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any
}

/**
 * Represents the Verification Options that can be passed to the verifyCredential method.
 * These options are forwarded to the lower level verification code
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type VerifyCredentialOptions = Record<string, any>

/**
 * Represents the Verification Options that can be passed to the verifyPresentation method.
 * The verification will fail if given options are NOT satisfied.
 */
export interface VerifyPresentationOptions extends VerifyCredentialOptions {
  domain?: string
  challenge?: string
}

/**
 * Represents the Creation Options that can be passed to the createVerifiablePresentationJwt method.
 */
export interface CreatePresentationOptions extends CreateCredentialOptions {
  domain?: string
  challenge?: string
}
