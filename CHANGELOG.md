## [1.0.2](https://github.com/decentralized-identity/did-jwt-vc/compare/1.0.1...1.0.2) (2020-06-29)


### Bug Fixes

* converting to jwt ([d7f9578](https://github.com/decentralized-identity/did-jwt-vc/commit/d7f95783c73eaaa521eab1fb352881884b59f42c)), closes [#37](https://github.com/decentralized-identity/did-jwt-vc/issues/37)
* **types:** widen types used as input ([c3e7a2e](https://github.com/decentralized-identity/did-jwt-vc/commit/c3e7a2e745145e985f60da7c343d9889d50e76dc))

## [1.0.1](https://github.com/decentralized-identity/did-jwt-vc/compare/1.0.0...1.0.1) (2020-06-26)


### Bug Fixes

* **build:** Use tsc instead of microbundle ([#38](https://github.com/decentralized-identity/did-jwt-vc/issues/38)) ([f75a967](https://github.com/decentralized-identity/did-jwt-vc/commit/f75a96767f413cecbcd3c09954b04c11be3db24d))

# [1.0.0](https://github.com/decentralized-identity/did-jwt-vc/compare/0.2.0...1.0.0) (2020-06-25)


### Bug Fixes

* **build:** add babel plugin to fix microbundle 0.12 build error ([e14c2aa](https://github.com/decentralized-identity/did-jwt-vc/commit/e14c2aa695a8155c9eab4591ebc82233694dcab5))
* use `ES256K` as the default JWT algorithm ([a097c69](https://github.com/decentralized-identity/did-jwt-vc/commit/a097c69e1c182d448007cbe834a56621f33cdb82))


### Code Refactoring

* rename creation and validation methods to reflect JWT target ([829956f](https://github.com/decentralized-identity/did-jwt-vc/commit/829956f1e063930e47866d5bbd0208dbc1e57d83))
* rename credential validation methods ([2bb2e5a](https://github.com/decentralized-identity/did-jwt-vc/commit/2bb2e5a02c28e2ff24da84f5e8fc9fe3525cb57c))
* rename existing payload types to reflect JWT target ([af74207](https://github.com/decentralized-identity/did-jwt-vc/commit/af742074341e5b2345c3139da7fc6e4d642fe76d))


### Features

* add a method to convert a credential payload from W3C to JWT ([f7e86f0](https://github.com/decentralized-identity/did-jwt-vc/commit/f7e86f0b8696ea407a9820e59f0e3472d928666e))
* add a normalizer method to an unambiguous `Verifiable<Credential>` ([ffbd67f](https://github.com/decentralized-identity/did-jwt-vc/commit/ffbd67fffed6e977399cd4946e8c7c5da14d5dbd))
* add methods to convert to unambiguous `Verifiable<Presentation>` and JWTPresentationPayload ([1721e4a](https://github.com/decentralized-identity/did-jwt-vc/commit/1721e4a34ba42112b4b6df359c11a896c874e703))
* define W3C compatible data types for credentials and presentations ([adb27e9](https://github.com/decentralized-identity/did-jwt-vc/commit/adb27e98171fbead4b903add1d00349e50ed92b0))
* homogenize `verifyCredential()`/`verifyPresentation()` API ([e9fbb99](https://github.com/decentralized-identity/did-jwt-vc/commit/e9fbb9941e0717fb3358e26f977ba6a22005942a))
* homogenize createCredentialJwt/PresentationJwt API ([3999382](https://github.com/decentralized-identity/did-jwt-vc/commit/39993820e0e3bfef8d706515f7a256cd5c2655fd))


### BREAKING CHANGES

* removed `Verifiable` from the credential validation methods since the parameter is only the payload
validateJwtVerifiableCredentialPayload -> validateJwtCredentialPayload
validateVerifiableCredentialPayload -> validateCredentialPayload
* renamed `createPresentationJWT` to `createVerifiablePresentationAJwt`
* the following methods have been renamed:
`createVerifiableCredential` -> `createVerifiableCredentialJwt`
`createPresentation` -> `createPresentationJwt`
`validateVerifiableCredentialAttributes` -> `validateJwtVerifiableCredentialPayload`
`validatePresentationAttributes` -> `validateJwtPresentationPayload`

Also exporting the `JWT` type which maps to `string`
* the following interface definitions have been renamed:
`VerifiableCredentialPayload` -> `JwtVerifiableCredentialPayload`
`PresentationPayload` -> `JwtPresentationPayload`

# [0.2.0](https://github.com/decentralized-identity/did-jwt-vc/compare/0.1.6...0.2.0) (2020-04-30)


### Features

* remove explicit declaration of the nullable `credentialStatus` ([078ba82](https://github.com/decentralized-identity/did-jwt-vc/commit/078ba8215353dbcea08045383e1a970b9dd79851))

## [0.1.6](https://github.com/decentralized-identity/did-jwt-vc/compare/0.1.5...0.1.6) (2020-04-28)


### Bug Fixes

* Issuer alg is optional ([5a4b016](https://github.com/decentralized-identity/did-jwt-vc/commit/5a4b016e0884af69362cfb10c73e6e89296739c2))
