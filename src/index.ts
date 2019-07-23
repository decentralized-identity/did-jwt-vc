import { createJWT, Signer } from 'did-jwt'

const JWT_ALG = 'ES256K-R'
const DID_FORMAT = /^did:([a-zA-Z0-9_]+):([:[a-zA-Z0-9_.-]+)(\/[^#]*)?(#.*)?$/
const DEFAULT_CONTEXT = 'https://www.w3.org/2018/credentials/v1'
const DEFAULT_TYPE = 'VerifiableCredential'

interface VC {
  '@context': string[]
  type: string[]
  credentialSubject: object
}

interface VerifiableCredentialPayload {
  sub: string
  nbf: number
  vc: VC
  aud?: string
  exp?: number
  jti?: string
}

interface VP {
  '@context': string[]
  type: string[]
  verifiableCredential: string[]
}

interface PresentationPayload {
  vp: VP
  aud?: string
  exp?: number
  jti?: string
}

interface Issuer {
  did: string
  signer: Signer
}

export async function createVerifiableCredential(
  payload: VerifiableCredentialPayload,
  issuer: Issuer
): Promise<string> {
  validateVerifiableCredentialAttributes(payload)
  return createJWT(payload, {
    issuer: issuer.did,
    signer: issuer.signer,
    alg: JWT_ALG
  })
}

export async function createPresentation(
  payload: PresentationPayload,
  issuer: Issuer
): Promise<string> {
  return createJWT(payload, {
    issuer: issuer.did,
    signer: issuer.signer,
    alg: JWT_ALG
  })
}

// The main scenario we want to guard against is having a timestamp in milliseconds
// instead of seconds (ex: from new Date().getTime()).
// We will check the number of digits and assume that any number with 12 or more
// digits is a millisecond timestamp.
// 10 digits max is 9999999999 -> 11/20/2286 @ 5:46pm (UTC)
// 11 digits max is 99999999999 -> 11/16/5138 @ 9:46am (UTC)
// 12 digits max is 999999999999 -> 09/27/33658 @ 1:46am (UTC)
function isTimestampInSeconds(t: number): boolean {
  return Number.isInteger(t) && t < 100000000000
}

function validateVerifiableCredentialAttributes(
  payload: VerifiableCredentialPayload
): void {
  if (!payload.sub.match(DID_FORMAT)) {
    throw new TypeError('sub must be a valid did')
  }
  if (!isTimestampInSeconds(payload.nbf)) {
    throw new TypeError('nbf must be a unix timestamp in seconds')
  }
  if (
    payload.vc['@context'].length < 1 ||
    !payload.vc['@context'].includes(DEFAULT_CONTEXT)
  ) {
    throw new TypeError(
      `vc['@context'] must include at least "${DEFAULT_CONTEXT}"`
    )
  }
  if (payload.vc.type.length < 1 || !payload.vc.type.includes(DEFAULT_TYPE)) {
    throw new TypeError(`vc.type must include at least "${DEFAULT_TYPE}"`)
  }
  if (Object.keys(payload.vc.credentialSubject).length === 0) {
    throw new TypeError('vc.credentialSubject must not be empty')
  }
  if (payload.aud && !payload.aud.match(DID_FORMAT)) {
    throw new TypeError('aud must be a valid did or undefined')
  }
  if (payload.exp && !isTimestampInSeconds(payload.exp)) {
    throw new TypeError('exp must be a unix timestamp in seconds')
  }
}
