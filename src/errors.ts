import { JWT_ERROR } from 'did-jwt'

/**
 * Error prefixes used for known verification failure cases related to the
 * {@link https://www.w3.org/TR/vc-data-model/ | Verifiable Credential data model }
 */
export const enum VC_ERROR {
  /**
   * Thrown when the credential or presentation being verified does not conform to the data model defined by
   * {@link https://www.w3.org/TR/vc-data-model/ | the spec}
   */
  SCHEMA_ERROR = 'schema_error',

  /**
   * Thrown when the input is not a JWT string
   */
  FORMAT_ERROR = 'format_error',

  /**
   * Thrown when verifying a presentation where `challenge` and/or `domain` don't match the expected values.
   */
  AUTH_ERROR = 'auth_error',
}

/**
 * Known validation or verification error prefixes.
 */
export type VC_JWT_ERROR = VC_ERROR | JWT_ERROR
