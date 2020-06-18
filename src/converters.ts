import {
  VerifiableCredential,
  JWT,
  JwtPresentationPayload,
  JwtCredentialPayload as JwtCredentialPayload,
  CredentialPayload,
  Credential,
  Verifiable,
  PresentationPayload,
  Presentation
} from './types'
import { decodeJWT } from 'did-jwt'

function asArray(input: any) {
  return Array.isArray(input) ? input : [input]
}

function normalizeJwtCredentialPayload(input: Partial<JwtCredentialPayload>): Credential {
  let result: Partial<CredentialPayload> = { ...input }

  result.credentialSubject = { ...result.credentialSubject, ...result.vc?.credentialSubject }
  result.credentialSubject.id = result.credentialSubject?.id || result.sub
  delete result.sub

  result.issuer = typeof result.issuer === 'object' ? { ...result.issuer, id: result.iss } : { id: result.iss }
  delete result.iss

  result.id = result.id || result.jti
  delete result.jti

  result.type = [...asArray(result.type), ...asArray(result.vc.type)]
  result['@context'] = [...asArray(result.context), ...asArray(result['@context']), ...asArray(result.vc['@context'])]
  delete result.context
  delete result.vc

  //TODO: test parsing Date strings into Date objects
  if (result.iat || result.nbf) {
    result.issuanceDate = result.issuanceDate || new Date(result.nbf || result.iat).toISOString()
    delete result.nbf
    delete result.iat
  }

  if (result.exp) {
    result.expirationDate = result.expirationDate || new Date(result.exp).toISOString()
    delete result.exp
  }

  return result as Credential
}

function normalizeJwtCredential(input: JWT): Verifiable<Credential> {
  return {
    ...normalizeJwtCredentialPayload(decodeJWT(input)),
    proof: {
      type: 'JwtProof2020',
      jwt: input
    }
  }
}

/**
 * Normalizes a credential payload into an unambiguous W3C credential data type
 * @param input either a JWT or JWT payload, or a VerifiableCredential
 */
export function normalizeCredential(
  input: Partial<VerifiableCredential> | Partial<JwtCredentialPayload>
): Verifiable<Credential> {
  if (typeof input === 'string') {
    //FIXME: attempt to deserialize as JSON before assuming it is a JWT
    return normalizeJwtCredential(input)
  } else if (input.proof?.jwt) {
    //TODO: test that it correctly propagates app specific proof properties
    return { ...normalizeJwtCredential(input.proof.jwt), proof: input.proof }
  } else {
    //TODO: test that it accepts JWT payload, CredentialPayload, VerifiableCredential
    //TODO: test that it correctly propagates proof, if any
    return { proof: {}, ...normalizeJwtCredentialPayload(input) }
  }
}

/**
 * Transforms a W3C Credential payload into a JWT compatible encoding.
 * The method accepts app specific fields and in case of collision, existing JWT properties will take precedence.
 * @param input either a JWT payload or a CredentialPayloadInput
 */
export function transformCredentialInput(
  input: Partial<CredentialPayload> | Partial<JwtCredentialPayload>
): JwtCredentialPayload {
  if (Array.isArray(input.credentialSubject)) throw Error('credentialSubject of type array not supported')

  //TODO: test that app specific input.vc properties are preserved
  const result: Partial<JwtCredentialPayload> = { vc: { ...input.vc }, ...input }

  //TODO: test credentialSubject.id becomes sub and that original sub takes precedence
  result.sub = input.sub || input.credentialSubject?.id
  const credentialSubject = { ...input.credentialSubject, ...input.vc?.credentialSubject }
  if (!input.sub) {
    delete credentialSubject.id
  }
  result.vc.credentialSubject = credentialSubject

  //TODO: check that all context combos are preserved
  result.vc['@context'] = [...asArray(input.context), ...asArray(input['@context']), ...asArray(input.vc['@context'])]
  delete result.context
  delete result['@context']

  //TODO: check that all type combos are preserved
  result.vc.type = [...asArray(input.type), ...asArray(input.vc?.type)]
  delete result.type

  //TODO: check that existing jti is preserved and that id is used if not
  if (input.id) {
    result.jti = input.jti || input.id
    delete result.id
  }

  //TODO: check that issuanceDate is used if present and that nbf is preserved if present
  if (input.issuanceDate) {
    result.nbf = input.nbf || Date.parse(input.issuanceDate) / 1000
    delete result.issuanceDate
  }

  //TODO: check that expiryDate is used if present and that exp is preserved if present
  if (input.expirationDate) {
    result.exp = input.exp || Date.parse(input.expirationDate) / 1000
    delete result.expirationDate
  }

  //TODO: check that iss is preserved, if present
  //TODO: check that issuer is used as string if present
  //TODO: check that issuer.id is used if iss is missing
  //TODO: check that issuer claims are preserved, no matter what
  if (input.issuer) {
    if (typeof input.issuer === 'object') {
      result.iss = input.iss || input.issuer?.id
      delete result.issuer.id
    } else {
      result.iss = input.iss || '' + input.issuer
      delete result.issuer
    }
  }

  return result as JwtCredentialPayload
}

function normalizeJwtPresentationPayload(input: Partial<JwtPresentationPayload>): Presentation {
  let result: Partial<PresentationPayload> = { ...input }

  result.verifiableCredential = [...asArray(input.verifiableCredential), ...asArray(input.vp?.verifiableCredential)]
  result.verifiableCredential = result.verifiableCredential.map(normalizeCredential)

  if (input.iss) {
    result.holder = input.holder || input.iss
    delete result.iss
  }

  if (input.aud) {
    result.verifier = [...asArray(input.verifier), ...asArray(input.aud)]
    delete result.aud
  }

  if (input.jti) {
    result.id = input.id || input.jti
    delete result.jti
  }

  result.type = [...asArray(input.type), ...asArray(input.vp.type)]
  result['@context'] = [...asArray(input.context), ...asArray(input['@context']), ...asArray(input.vp['@context'])]
  delete result.context
  //TODO: figure out if the whole vp property should be deleted
  delete result.vp.context
  delete result.vp.type

  //TODO: test parsing Date strings into Date objects
  if (input.iat || input.nbf) {
    result.issuanceDate = input.issuanceDate || new Date(input.nbf || input.iat).toISOString()
    delete result.nbf
    delete result.iat
  }

  if (input.exp) {
    result.expirationDate = input.expirationDate || new Date(input.exp).toISOString()
    delete result.exp
  }

  return result as Presentation
}

function normalizeJwtPresentation(input: JWT): Verifiable<Presentation> {
  return {
    ...normalizeJwtPresentationPayload(decodeJWT(input)),
    proof: {
      type: 'JwtProof2020',
      jwt: input
    }
  }
}

/**
 * Normalizes a presentation payload into an unambiguous W3C Presentation data type
 * @param input either a JWT or JWT payload, or a VerifiablePresentation
 */
export function normalizePresentation(
  input: Partial<PresentationPayload> | Partial<JwtPresentationPayload>
): Verifiable<Presentation> {
  if (typeof input === 'string') {
    //FIXME: attempt to deserialize as JSON before assuming it is a JWT
    return normalizeJwtPresentation(input)
  } else if (input.proof?.jwt) {
    //TODO: test that it correctly propagates app specific proof properties
    return { ...normalizeJwtPresentation(input.proof.jwt), proof: input.proof }
  } else {
    //TODO: test that it accepts JWT payload, PresentationPayload, VerifiablePresentation
    //TODO: test that it correctly propagates proof, if any
    return { proof: {}, ...normalizeJwtPresentationPayload(input) }
  }
}

export function transformPresentationInput(
  input: Partial<PresentationPayload> | Partial<JwtPresentationPayload>
): JwtPresentationPayload {
  //TODO: test that app specific input.vp properties are preserved
  const result: Partial<JwtPresentationPayload> = { vp: { ...input.vp }, ...input }

  //TODO: check that all context combos are preserved
  result.vp['@context'] = [...asArray(input.context), ...asArray(input['@context']), ...asArray(input.vp['@context'])]
  delete result.context
  delete result['@context']

  //TODO: check that all type combos are preserved
  result.vc.type = [...asArray(input.type), ...asArray(input.vp?.type)]
  delete result.type

  result.vp.verifiableCredential = [...asArray(result.verifiableCredential), ...asArray(result.vp?.verifiableCredential)]
    .map((credential: VerifiableCredential) => {
      if (typeof credential === 'object' && credential.proof?.jwt) {
        return credential.proof.jwt
      } else {
        return credential
      }
    })
  delete result.verifiableCredential

  //TODO: check that existing jti is preserved and that id is used if not
  if (input.id) {
    result.jti = input.jti || input.id
    delete result.id
  }

  //TODO: check that issuanceDate is used if present and that nbf is preserved if present
  if (input.issuanceDate) {
    result.nbf = input.nbf || Date.parse(input.issuanceDate) / 1000
    delete result.issuanceDate
  }

  //TODO: check that expiryDate is used if present and that exp is preserved if present
  if (input.expirationDate) {
    result.exp = input.exp || Date.parse(input.expirationDate) / 1000
    delete result.expirationDate
  }

  //TODO: check that iss is preserved, if present
  //TODO: check that issuer is used as string if present
  if (input.holder) {
    result.iss = input.iss || input.holder
    delete result.issuer
  }

  //TODO: check that aud members are preserved, if present
  if (input.verifier) {
    result.aud = [...asArray(input.verifier), ...asArray(input.aud)]
    delete result.verifier
  }

  return result as JwtPresentationPayload
}
