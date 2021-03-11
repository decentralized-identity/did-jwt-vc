# [2.0.0](https://github.com/decentralized-identity/did-jwt-vc/compare/1.2.0...2.0.0) (2021-03-11)


### Bug Fixes

* **deps:** update did-jwt@5.0.1 and did-resolver@3.0 ([#67](https://github.com/decentralized-identity/did-jwt-vc/issues/67)) ([07bfc6b](https://github.com/decentralized-identity/did-jwt-vc/commit/07bfc6bcf6855e16e992e1fb89f99d8ab7b2c99c))


### BREAKING CHANGES

* **deps:** the type of Resolver used for verification has been upgraded to the latest spec and no longer returns just the DID Document

# [1.2.0](https://github.com/decentralized-identity/did-jwt-vc/compare/1.1.0...1.2.0) (2021-03-11)


### Features

* add option to keep original fields when transforming JWT<->JOSE payload formats ([#63](https://github.com/decentralized-identity/did-jwt-vc/issues/63)) ([cf59b6f](https://github.com/decentralized-identity/did-jwt-vc/commit/cf59b6f149dae3b94fa0c6dceada432be80c3b6a)), closes [#62](https://github.com/decentralized-identity/did-jwt-vc/issues/62) [#22](https://github.com/decentralized-identity/did-jwt-vc/issues/22)

# [1.1.0](https://github.com/decentralized-identity/did-jwt-vc/compare/1.0.7...1.1.0) (2021-02-24)


### Features

* support challenge & domain in Presentation creation and verification ([#61](https://github.com/decentralized-identity/did-jwt-vc/issues/61)) ([3a75c47](https://github.com/decentralized-identity/did-jwt-vc/commit/3a75c4708f545165cd5d483de9ec3d390a95e14e)), closes [#60](https://github.com/decentralized-identity/did-jwt-vc/issues/60) [#22](https://github.com/decentralized-identity/did-jwt-vc/issues/22)

## [1.0.7](https://github.com/decentralized-identity/did-jwt-vc/compare/1.0.6...1.0.7) (2021-01-18)


### Bug Fixes

* **deps:** bump dependencies and fix type issues ([#55](https://github.com/decentralized-identity/did-jwt-vc/issues/55)) ([a169cd3](https://github.com/decentralized-identity/did-jwt-vc/commit/a169cd38c975c62e402d5c96b7c010c30b86ff35)), closes [#52](https://github.com/decentralized-identity/did-jwt-vc/issues/52) [#53](https://github.com/decentralized-identity/did-jwt-vc/issues/53)

## [1.0.6](https://github.com/decentralized-identity/did-jwt-vc/compare/1.0.5...1.0.6) (2020-08-18)


### Bug Fixes

* **deps:** update dependency did-resolver@2.1.0 & did-jwt@4.4.2 ([#48](https://github.com/decentralized-identity/did-jwt-vc/issues/48)) ([6a98103](https://github.com/decentralized-identity/did-jwt-vc/commit/6a981033f9a4aa5317a238af45022332cd57a306))

## [1.0.5](https://github.com/decentralized-identity/did-jwt-vc/compare/1.0.4...1.0.5) (2020-08-18)


### Bug Fixes

* set credentialSubject.id as optional ([#45](https://github.com/decentralized-identity/did-jwt-vc/issues/45)) ([c31ee17](https://github.com/decentralized-identity/did-jwt-vc/commit/c31ee1715a7aa749b9419aeed79ee584a645bea3))

## [1.0.4](https://github.com/decentralized-identity/did-jwt-vc/compare/1.0.3...1.0.4) (2020-07-20)


### Bug Fixes

* **build:** use commonjs module format ([#46](https://github.com/decentralized-identity/did-jwt-vc/issues/46)) ([76e503b](https://github.com/decentralized-identity/did-jwt-vc/commit/76e503bc4307d313681a245665250932c98bcd64)), closes [#47](https://github.com/decentralized-identity/did-jwt-vc/issues/47)

## [1.0.3](https://github.com/decentralized-identity/did-jwt-vc/compare/1.0.2...1.0.3) (2020-07-02)


### Bug Fixes

* stop input from being mutated by converter methods ([#41](https://github.com/decentralized-identity/did-jwt-vc/issues/41)) ([346e6f7](https://github.com/decentralized-identity/did-jwt-vc/commit/346e6f7f61ade7c669f38bc1e6dcb42ad8a0ba34))

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
