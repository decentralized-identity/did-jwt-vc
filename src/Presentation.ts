// tslint:disable: variable-name
import { Signer } from 'did-jwt'
import { DEFAULT_CONTEXT, DEFAULT_TYPE } from './constants';
import { createPresentation } from '.';
import { PresentationPayload } from './types';

export class PresentationBuilder {
  private _signer: Signer
  private _issuer: string
  private _verifiableCredentials: string[] = []
  private _context: string[] = [DEFAULT_CONTEXT]
  private _type: string[] = [DEFAULT_TYPE]
  private _validFrom?: number
  private _validUntil?: number
  private _expiresIn?: number
  private _audience?: string
  private _id?: string

  async build(): Promise<string> {
    if (this._signer === undefined) throw new Error('signer must be set before calling build()')
    if (this._issuer === undefined) throw new Error('issuer must be set before calling build()')
    if (this._verifiableCredentials.length < 1) throw new Error('at least one verifiableCredential must be added before calling build()')
    const payload: PresentationPayload = {
      vp: {
        '@context': this._context,
        type: this._type,
        verifiableCredential: this._verifiableCredentials
      }
    }
    if (this._audience) payload.aud = this._audience
    if (this._validFrom) payload.nbf = this._validFrom
    if (this._validUntil) payload.exp = this._validUntil
    else if (payload.nbf && this._expiresIn) payload.exp = payload.nbf + this._expiresIn
    if (this._id) payload.jti = this._id
    return createPresentation(payload, {
      did: this._issuer,
      signer: this._signer
    })
  }

  setSigner(signer: Signer): PresentationBuilder {
    this._signer = signer
    return this
  }
  setIssuer(issuer: string): PresentationBuilder {
    this._issuer = issuer
    return this
  }
  addVerifiableCredential(verifiableCredential: string): PresentationBuilder {
    this._verifiableCredentials.push(verifiableCredential)
    return this
  }
  addContext(context: string): PresentationBuilder {
    this._context.push(context)
    return this
  }
  addType(type: string): PresentationBuilder {
    this._type.push(type)
    return this
  }
  setAudience(audience: string): PresentationBuilder {
    this._audience = audience
    return this
  }
  setValidFrom(value: number): PresentationBuilder {
    this._validFrom = value
    return this
  }
  setValidUntil(value: number): PresentationBuilder {
    this._validUntil = value
    return this
  }
  expiresIn(value: number): PresentationBuilder {
    this._expiresIn = value
    return this
  }
  setId(value: string): PresentationBuilder {
    this._id = value
    return this
  }
  get signer() {
    return this._signer
  }
  get audience() {
    return this._audience
  }
  get issuer() {
    return this._issuer
  }
  get verifiableCredentials() {
    return this._verifiableCredentials
  }
  get context() {
    return this._context
  }
  get type() {
    return this._type
  }
  get validFrom() {
    return this._validFrom
  }
  get validUntil() {
    return this._validUntil
  }
  get id() {
    return this._id
  }
}