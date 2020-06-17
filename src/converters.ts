import {
  VerifiableCredential,
  JWT,
  JwtPresentationPayload,
  JwtVerifiableCredentialPayload,
  CredentialPayloadInput,
  Credential,
  Verifiable
} from './types'
import { decodeJWT } from 'did-jwt'
import { VerifiableCredentialPayload } from 'src'

function asArray(input: any) {
  return Array.isArray(input) ? input : [input]
}

function normalizeJwtCredentialPayload(input: Partial<JwtVerifiableCredentialPayload>): Credential {
  let result: Partial<CredentialPayloadInput> = { ...input }

  result.credentialSubject = { ...result.credentialSubject, ...result.vc?.credentialSubject }
  result.credentialSubject.id = result.credentialSubject.id || result.sub
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
  input: Partial<VerifiableCredential> | Partial<JwtVerifiableCredentialPayload>
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

