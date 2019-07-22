import EthrDID from 'ethr-did'
import { createVerifiableCredential } from '../index'

const issuerIdentity = {
  did: 'did:ethr:0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
  address: '0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
  privateKey: 'd8b595680851765f38ea5405129244ba3cbad84467d190859f4c8b20c1ff6c75',
}

const did = new EthrDID(issuerIdentity)

describe('createVerifiableCredential', () => {
  it('creates a valid Verifiable Credential JWT with required fields', async () => {
    const vcJwt = await createVerifiableCredential({
      sub: 'did:ethr:0x12345678',
      nbf: 1562950282801,
      vc: {
        '@context': [
          'https://www.w3.org/2018/credentials/v1',
          'https://www.w3.org/2018/credentials/examples/v1'
        ],
        type: [
          'VerifiableCredential',
          'UniversityDegreeCredential'
        ],
        credentialSubject: {
          'degree': {
            type: 'BachelorDegree',
            name: 'Baccalauréat en musiques numériques'
          }
        }
      }
    }, did)
    expect(vcJwt).toMatchSnapshot()
  })
})