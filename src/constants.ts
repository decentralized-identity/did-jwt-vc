export const JWT_ALG = 'ES256K-R'
export const DID_FORMAT = /^did:([a-zA-Z0-9_]+):([:[a-zA-Z0-9_.-]+)(\/[^#]*)?(#.*)?$/
export const JWT_FORMAT = /^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/
export const DEFAULT_CONTEXT = 'https://www.w3.org/2018/credentials/v1'
export const DEFAULT_VC_TYPE = 'VerifiableCredential'
export const DEFAULT_VP_TYPE = 'VerifiablePresentation'
export const DEFAULT_JWT_PROOF_TYPE = 'JwtProof2020'
