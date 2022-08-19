import { DEFAULT_CONTEXT, DEFAULT_VC_TYPE, DEFAULT_VP_TYPE, JWT_FORMAT } from './types'
import { JwtCredentialSubject, DateType } from './types'
import { VerifiableCredential } from '.'
import { asArray } from './converters'
import { JWT_ERROR } from 'did-jwt'

/**
 * Error prefixes used for known verification failure cases related to the
 * {@link https://www.w3.org/TR/vc-data-model/ | Verifiable Credential data model }
 */
export const VC_ERROR = {
  /**
   * Thrown when the credential or presentation being verified does not conform to the data model defined by
   * {@link https://www.w3.org/TR/vc-data-model/ | the spec}
   */
  SCHEMA_ERROR: 'schema_error',

  /**
   * Thrown when the input is not a JWT string
   */
  FORMAT_ERROR: 'format_error',

  /**
   * Thrown when verifying a presentation where `challenge` and/or `domain` don't match the expected values.
   */
  AUTH_ERROR: 'auth_error',
}

/**
 * Known validation or verification error prefixes.
 */
export const VC_JWT_ERROR = { ...VC_ERROR, ...JWT_ERROR }

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function isDateObject(input: any): input is Date {
  return input && !isNaN(input) && Object.prototype.toString.call(input) === '[object Date]'
}

export function validateJwtFormat(value: VerifiableCredential): void {
  if (typeof value === 'string' && !value.match(JWT_FORMAT)) {
    throw new TypeError(`${VC_ERROR.FORMAT_ERROR}: "${value}" is not a valid JWT format`)
  }
}

// The main scenario we want to guard against is having a timestamp in milliseconds
// instead of seconds (ex: from new Date().getTime()).
// We will check the number of digits and assume that any number with 12 or more
// digits is a millisecond timestamp.
// 10 digits max is 9999999999 -> 11/20/2286 @ 5:46pm (UTC)
// 11 digits max is 99999999999 -> 11/16/5138 @ 9:46am (UTC)
// 12 digits max is 999999999999 -> 09/27/33658 @ 1:46am (UTC)
export function validateTimestamp(value: number | DateType): void {
  if (typeof value === 'number') {
    if (!(Number.isInteger(value) && value < 100000000000)) {
      throw new TypeError(`${VC_ERROR.SCHEMA_ERROR}: "${value}" is not a unix timestamp in seconds`)
    }
  } else if (typeof value === 'string') {
    validateTimestamp(Math.floor(new Date(value).valueOf() / 1000))
  } else if (!isDateObject(value)) {
    throw new TypeError(`${VC_ERROR.SCHEMA_ERROR}: "${value}" is not a valid time`)
  }
}

export function validateContext(value: string | string[]): void {
  const input = asArray(value)
  if (input.length < 1 || input.indexOf(DEFAULT_CONTEXT) === -1) {
    throw new TypeError(`${VC_ERROR.SCHEMA_ERROR}: @context is missing default context "${DEFAULT_CONTEXT}"`)
  }
}

export function validateVcType(value: string | string[]): void {
  const input = asArray(value)
  if (input.length < 1 || input.indexOf(DEFAULT_VC_TYPE) === -1) {
    throw new TypeError(`${VC_ERROR.SCHEMA_ERROR}: type is missing default "${DEFAULT_VC_TYPE}"`)
  }
}

export function validateVpType(value: string | string[]): void {
  const input = asArray(value)
  if (input.length < 1 || input.indexOf(DEFAULT_VP_TYPE) === -1) {
    throw new TypeError(`${VC_ERROR.SCHEMA_ERROR}: type is missing default "${DEFAULT_VP_TYPE}"`)
  }
}

export function validateCredentialSubject(value: JwtCredentialSubject): void {
  if (Object.keys(value).length === 0) {
    throw new TypeError(`${VC_ERROR.SCHEMA_ERROR}: credentialSubject must not be empty`)
  }
}
