import {
  DID_FORMAT,
  DEFAULT_CONTEXT,
  DEFAULT_TYPE,
  JWT_FORMAT
} from './constants'

export function validateDidFormat(value: string): void {
  if (!value.match(DID_FORMAT)) {
    throw new TypeError(`"${value}" is not a valid DID format`)
  }
}

export function validateJwtFormat(value: string): void {
  if (!value.match(JWT_FORMAT)) {
    throw new TypeError(`"${value}" is not a valid JWT format`)
  }
}

// The main scenario we want to guard against is having a timestamp in milliseconds
// instead of seconds (ex: from new Date().getTime()).
// We will check the number of digits and assume that any number with 12 or more
// digits is a millisecond timestamp.
// 10 digits max is 9999999999 -> 11/20/2286 @ 5:46pm (UTC)
// 11 digits max is 99999999999 -> 11/16/5138 @ 9:46am (UTC)
// 12 digits max is 999999999999 -> 09/27/33658 @ 1:46am (UTC)
export function validateTimestamp(value: number): void {
  if (!(Number.isInteger(value) && value < 100000000000)) {
    throw new TypeError(`"${value}" is not a unix timestamp in seconds`)
  }
}

export function validateContext(value: string[]): void {
  if (value.length < 1 || !value.includes(DEFAULT_CONTEXT)) {
    throw new TypeError(
      `@context is missing default context "${DEFAULT_CONTEXT}"`
    )
  }
}

export function validateType(value: string[]): void {
  if (value.length < 1 || !value.includes(DEFAULT_TYPE)) {
    throw new TypeError(`type is missing default "${DEFAULT_TYPE}"`)
  }
}