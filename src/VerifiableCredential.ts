  // tslint:disable: variable-name
import { Signer } from 'did-jwt'
import { createVerifiableCredential } from '.';
import { CredentialSubject, VerifiableCredentialPayload } from './types';

export class VerifiableCredentialBuilder {
  private _signer: Signer
  private _subject: string
  private _issuer: string
  private _credentialSubject: CredentialSubject
  private _context: string[] = ['https://www.w3.org/2018/credentials/v1']
  private _type: string[] = ['VerifiableCredential']
  private _validFrom?: number
  private _validUntil?: number
  private _expiresIn?: number
  private _id?: string

  async build(): Promise<string> {
    if (this._signer === undefined) throw new Error('signer must be set before calling build()')
    if (this._issuer === undefined) throw new Error('issuer must be set before calling build()')
    if (this._subject === undefined) throw new Error('subject must be set before calling build()')
    if (this._credentialSubject === undefined) throw new Error('credentialSubject must be set before calling build()')
    const payload: VerifiableCredentialPayload = {
      sub: this._subject,
      vc: {
        '@context': this._context,
        type: this._type,
        credentialSubject: this._credentialSubject
      }
    }
    if (this._validFrom) payload.nbf = this._validFrom
    if (this._validUntil) payload.exp = this._validUntil
    else if (payload.nbf && this._expiresIn) payload.exp = payload.nbf + this._expiresIn
    if (this._id) payload.jti = this._id
    return createVerifiableCredential(payload, {
      did: this._issuer,
      signer: this._signer
    })
  }
  setSigner(signer: Signer): VerifiableCredentialBuilder {
    this._signer = signer
    return this
  }
  setSubject(subject: string): VerifiableCredentialBuilder {
    this._subject = subject
    return this
  }
  setIssuer(issuer: string): VerifiableCredentialBuilder {
    this._issuer = issuer
    return this
  }
  setCredentialSubject(credentialSubject: CredentialSubject) {
    this._credentialSubject = credentialSubject
    return this
  }
  addContext(context: string): VerifiableCredentialBuilder {
    this._context.push(context)
    return this
  }
  addType(type: string): VerifiableCredentialBuilder {
    this._type.push(type)
    return this
  }
  setValidFrom(value: number): VerifiableCredentialBuilder {
    this._validFrom = value
    return this
  }
  setValidUntil(value: number): VerifiableCredentialBuilder {
    this._validUntil = value
    return this
  }
  expiresIn(value: number): VerifiableCredentialBuilder {
    this._expiresIn = value
    return this
  }
  setId(value: string): VerifiableCredentialBuilder {
    this._id = value
    return this
  }
  get signer() {
    return this._signer
  }
  get subject() {
    return this._subject
  }
  get issuer() {
    return this._issuer
  }
  get credentialSubject() {
    return this._credentialSubject
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
