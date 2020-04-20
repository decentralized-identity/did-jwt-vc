import { VerifiableCredentialPayload, Issuer, PresentationPayload } from './types';
import { DIDDocument } from 'did-resolver';
export { Issuer, VerifiableCredentialPayload, PresentationPayload, };
interface Resolvable {
    resolve: (did: string) => Promise<DIDDocument | null>;
}
export declare function createVerifiableCredential(payload: VerifiableCredentialPayload, issuer: Issuer): Promise<string>;
export declare function createPresentation(payload: PresentationPayload, issuer: Issuer): Promise<string>;
export declare function validateVerifiableCredentialAttributes(payload: VerifiableCredentialPayload): void;
export declare function validatePresentationAttributes(payload: PresentationPayload): void;
export declare function verifyCredential(vc: string, resolver: Resolvable): Promise<any>;
export declare function verifyPresentation(presentation: string, resolver: Resolvable): Promise<any>;
//# sourceMappingURL=index.d.ts.map