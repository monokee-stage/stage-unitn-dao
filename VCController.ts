
// Libraries for verification process
import * as jose from 'jose';
import { base58btc } from "multiformats/bases/base58";
import {
    CompactJWT,
    CredentialSubject,
    Credential,
    VerifiableCredential,
    VerifiablePresentation,
    KeyPairDecodedJWT,
    IssuerType,
    W3CVerifiableCredential
} from "../utils/types";
import {
    extractIssuer,
    getEthereumAddress,
    validateDTO,
    resolveDid
} from "../utils/vc-utils";
import {
    MongoDBFindChallenge,
    MongoDBInsertChallengeParams
} from '../utils/mongo-utils';

import didJWT, { JWTVerified } from 'did-jwt';
import * as u8a from 'uint8arrays';
import { recoverTypedSignature, SignTypedDataVersion } from "@metamask/eth-sig-util";

// Resolvers
import { Resolver } from 'did-resolver';
import { getResolver as cheqdDidResolver } from '@cheqd/did-provider-cheqd';
// import { getUniversalResolver } from '@veramo/did-resolver';
import { DIDResolutionResult, DIDResolver } from 'did-resolver';
// this launches an error:
// import { getResolver as keyDidResolver } from 'key-did-resolver';

import crypto, { sign } from "crypto";
import { 
    MonokeeLoginCredentialSubjectSchema, 
    MonokeeRoleCredentialSubjectSchema 
} from '../credential_schemes';

import MonokeeLoginVC from '../credential_schemes/MonokeeLoginVC';
import { MonokeeLoginVC_TYPE, MonokeeVC_CONTEXT } from '../utils/constants';


class VCController {


    constructor() { }

    defaultMethod() {
        return {
            text: `You've reached the ${this.constructor.name} default method`,
        };
    }

    async getIssuerSigner() {

        // Retrieve issuer didurls from .env file manually
        const cheqdDidIssuer = process.env.CHEQD_ISSUER as string;
        const didkeyDidIssuer = process.env.DIDKEY_ISSUER as string;

        // Check if did:cheqd is resolvable
        // !!! Used a try-catch block because the resolveDid function throws an error if the DID is not resolvable
        try {
            const cheqdDidDoc = await resolveDid(cheqdDidIssuer, true);

            if (cheqdDidDoc.id !== cheqdDidIssuer) {
                throw new Error("Cheqd DID doesn't match the DID document")
            }

            const signer = didJWT.EdDSASigner(u8a.fromString(process.env.CHEQD_ISSUER_PRIVATE_KEY_HEX as string, 'hex'))
            return {
                signer: signer,
                didurl: cheqdDidDoc.id
            }
        } catch (error) {
            // console.log(error)

            const signer = didJWT.EdDSASigner(u8a.fromString((process.env.DIDKEY_ISSUER_PRIVATE_KEY_HEX as string), "hex"))

            return {
                signer: signer,
                didurl: didkeyDidIssuer
            }
        }


    }

    /**
     * Creates a Verifiable Credential for Monokee login purposes using the provided claims
     * 
     * @param credentialSubject - The CredentialSubject object to be included in the VC
     * @param type - The type of the VC to be created
     * @returns a VerifiableCredential object for Monokee login purposes
     */
    async getVC(credentialSubject: CredentialSubject, type: string): Promise<VerifiableCredential> {
        try {
            // TO DO - some validation procedures for provided claims
            // ...
            // v1 Ajv validation [TO BE IMPROVED]
            let validateSchema
            switch (type) {
                case "MonokeeLogin":
                    validateSchema = MonokeeLoginCredentialSubjectSchema
                    break;
                case "MonokeeRole":
                    validateSchema = MonokeeRoleCredentialSubjectSchema
                    break;
                default:
                    throw {
                        message: "Invalid VC type"
                    }
            }

            validateDTO(validateSchema, credentialSubject)

            // 1- Retrieve issuer keys
            const signer = await this.getIssuerSigner();

            // 2- Create our custom credential for login
            let credential: Credential = {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                ],
                type: ['VerifiableCredential', type],
                credentialSubject: credentialSubject,
                issuer: {
                    id: signer.didurl
                },
                issuanceDate: new Date().toISOString(),
            }

            // 3 - Create the JWT
            const jwt = await didJWT.createJWT(
                {
                    vc: credential,
                    iss: signer.didurl,
                    sub: credentialSubject.id,
                },
                { issuer: signer.didurl, signer: signer.signer },
                { alg: 'EdDSA', typ: "JWT" }
            )

            // 4- Put the signature into the credential -> that is become a Verifiable Credential
            credential.proof = {
                type: "JwtProof2020",
                jwt: jwt
            }

            // 5- Return the Verifiable Credential
            return credential as VerifiableCredential
        } catch (error) {
            throw error;
        }
    }

    /**
     * Verify a JWT or throw an error if the resolution fails.
     * 
     * @param jwt - the JWT that has to be verified      
     * @returns TO BE DEFINED
     */
    async verifyJWT(jwt: CompactJWT): Promise<JWTVerified> {

        try {
            const uniResolver = this.getUniversalResolver()
            const resolver = new Resolver({
                web: uniResolver,
                key: uniResolver,
                elem: uniResolver,
                ethr: uniResolver,
                cheqd: cheqdDidResolver().cheqd
            })

            const response = await didJWT.verifyJWT(jwt, {
                resolver
            });

            return {
                ...response
            }

        } catch (error: any) {
            const fullError = error.message.split(": ");
            throw {
                verified: false,
                error: {
                    message: fullError[1],
                    errorCode: fullError[0]
                }
            }
        }
    }

    getUniversalResolver(
        url: string = 'https://dev.uniresolver.io/1.0/identifiers/',
    ): DIDResolver {
        if (!url) {
            throw Error('[did-resolver] Universal: url required')
        }

        const resolve: DIDResolver = async (didUrl: string): Promise<DIDResolutionResult> => {
            try {
                const result = await fetch(url + didUrl)
                const ddo = await result.json()
                return ddo
            } catch (e) {
                return Promise.reject(e)
            }
        }

        return resolve
    }

    /**
     * Validate a credential schema and values (context and type)
     * 
     * @param credential - credential object that you want to check
     * @returns true if the credential schema is valid, false otherwise
     */
    verifyLoginCredentialSchema(credential: Credential): boolean {
        
        // v1 Ajv validation [TO BE IMPROVED]
        validateDTO(MonokeeLoginVC, credential)

        // 1 - validation of the object fields
        if (
            credential.type?.includes(MonokeeLoginVC_TYPE) &&
            credential["@context"].includes(MonokeeVC_CONTEXT)
        ) {
            return true
        } else {
            console.log("The credential doesn't match Monokee specification.")
            return false
        }
    }

    /**
     * Verify a Verifiable Credential
     * 
     * @param credential W3CVerifiableCredential - credential object that you want to check
     * @returns an object with property verified (true if the credential is valid, false otherwise) and an error object if the verification fails
     */
    async verifyVerifiableCredential(credential: W3CVerifiableCredential) {
        const jwt: CompactJWT = (typeof credential === 'string') ? credential : credential?.proof?.jwt
        if (jwt) {
            let verificationResult = await this.verifyJWT(jwt)

            // if credential was presented with other fields, make sure those fields match what's in the JWT
            if (verificationResult.verified && typeof credential !== 'string') {
                // this approach permits to avoid the deep copy of the credential object
                const credentialCopy = JSON.parse(JSON.stringify(credential))
                delete credentialCopy.proof // remove the proof from the credential object to compare it with the JWT
                
                const verifiedCopy = JSON.parse(JSON.stringify(verificationResult.payload.vc))
                
                if (JSON.stringify(credentialCopy) != JSON.stringify(verifiedCopy)) {
                    return {
                        verified: false,
                        error: {
                            message: 'Credential does not match JWT'
                        }
                    }
                }
            }

            return verificationResult
        } else {
            return {
                verified: false,
                error: {
                    message: 'invalid_argument: No proof found.'
                }
            }
        }
    }

    /**
     * Verify the passed VerifiablePresentation
     * !!! This works good with the JWT proof but not sure it works the same with the EthereumEip712Signature2021 proofs
     * 
     * @param presentation - VerifiablePresentation that you want to verify
     * @returns true if the verifiable presentation is verified, false otherwise
     */
    async verifyVerifiablePresentation(presentation: VerifiablePresentation) {
        // JWT
        let jwt: string = (typeof presentation === 'string') ? presentation : presentation?.proof?.jwt

        if (!jwt) 
            return {
                verified: false,
                error: {
                    message: 'invalid_argument: No proof found.'
                }
            }

        if(typeof presentation === 'string')
            throw Error('Not implemented yet')

        if (presentation.proof.type == "JwtProof2020") {
            console.log("VP is type: JWT");

            // 1 - Verify the JWT proof of the presentation
            console.log("Verifying jwt proof...")
            const res = await this.verifyJWT(presentation.proof.jwt)

            // 2 - Check that the vc has the right data
            console.log("Verifying VCs...")
            if (res.verified && presentation.verifiableCredential) {
                const results: Array<Promise<boolean>> = presentation.verifiableCredential.map(async (vc) => {
                    vc = vc as VerifiableCredential // exclude CompactJWT

                    // 2.1 - Check if JWT is valid
                    const resVc = await this.verifyJWT(vc.proof.jwt) // as jose.JWTVerifyResult

                    if (!resVc.verified) return false;

                    const signedVC = resVc.payload.vc as Credential             // !!! WE DECIDED TO VERIFY ONLY VC WITH JWT PROOF (which have payload inside the proof)
                    // 2.2 - Check if VC uses the correct schema
                    // if (await this.verifyCredentialSchema(signedVC) !== true) {
                    //     console.log("Invalid schema")
                    //     return false
                    // }
                    // console.log("\tValid Credential Schema")
                    // 2.3 - Verify that the VP holder == VC credentialSubject.id
                    if (signedVC.credentialSubject.id != presentation.holder) {
                        console.log("VP holder doesn't match the subject of the VerifiableCredential")
                        return false
                    }
                    console.log("\tValid subject")
                    // 2.4 - Verify that the VC issuer is ours
                    const issuersArray = [process.env.CHEQD_ISSUER as string, process.env.DIDKEY_ISSUER as string]
                    const extractedIssuer = extractIssuer(signedVC)
                    if (!issuersArray.includes(extractedIssuer)) {
                        console.log("Failed to verify issuer")
                        return false
                    }
                    console.log("\tValid issuer")
                    return true
                })
                const finalResult = await Promise.all(results)  // with this row we are certain that the verification process is ended
                if (finalResult.includes(true))
                    return res
                else
                    return {
                        verified: false,
                        error: {
                            message: "The Verifiable Presentation doesn't match our rules"
                        }
                    }
            } else {
                return res
            }
        } else if (presentation.proof.type == "EthereumEip712Signature2021") {
            if (
                !presentation.proof.eip712 ||
                !presentation.proof.eip712.messageSchema ||
                !presentation.proof.eip712.domain ||
                !presentation.proof.proofValue
            )
                throw new Error('proof.eip712 is undefined')
            console.log("VP is type EIP712")

            const { proof, ...signingInput } = presentation
            const { proofValue, eip712, ...verifyInputProof } = proof
            const verificationMessage = {
                ...signingInput,
                proof: verifyInputProof,
            }

            const objectToVerify = {
                message: verificationMessage,
                domain: eip712.domain,
                types: eip712.messageSchema,
                primaryType: eip712.primaryType,
            }

            // Address recovered from proofValue into VerifiablePresentation proof
            const recovered = recoverTypedSignature({
                data: objectToVerify,
                signature: proofValue,
                version: SignTypedDataVersion.V4,
            })

            const issuer = extractIssuer(presentation)
            console.log("Presentation Issuer (Holder in this case): ", issuer)
            if (!issuer || typeof issuer === 'undefined') {
                throw new Error('invalid_argument: args.presentation.issuer must not be empty')
            }

            const didDocument = await resolveDid(issuer)
            console.log("Issuer DIDDocument: ", didDocument)

            if (didDocument.verificationMethod) {
                for (const verificationMethod of didDocument.verificationMethod) {
                    const computedEthereumAddress = getEthereumAddress(verificationMethod)?.toLowerCase()
                    const recoveredEthereumAddress = recovered.toLowerCase()
                    console.log(computedEthereumAddress, recoveredEthereumAddress)
                    if (computedEthereumAddress === recoveredEthereumAddress) {
                        return true
                    }
                }
            } else {
                throw new Error('resolver_error: holder DIDDocument does not contain any verificationMethods')
            }

            return false
        }
    }

    /**
     * Generate a challenge in jwt format that will be used to verify the validity of the VerifiablePresentation.
     * The challenge has validity of 10 minutes.
     * 
     * @param fe_nonce  - the nonce generated by the frontend
     * @param mm_pub    - the public key of the metamask account
     * @returns the challenge in jwt format
     */
    async getVPChallenge(
        fe_nonce: string,
        mm_pub: string
    ) {
        // - create our local keypair
        let alg = 'ES256'
        let keypair = await jose.generateKeyPair(alg)
        let private_jwk = await jose.exportJWK(keypair.privateKey)
        let public_jwk = await jose.exportJWK(keypair.publicKey)
        let public_pem = await jose.exportSPKI(keypair.publicKey)
        public_jwk.alg = alg

        // - save the keypair to verify the challenge in a second step
        await MongoDBInsertChallengeParams({
            fe_nonce: fe_nonce,                 // fe_nonce is the unique identifier
            mm_pub: mm_pub,
            pubJWK: public_jwk,
            priJWK: private_jwk
        })

        // - generate a be_nonce
        const be_nonce = crypto.randomUUID()

        // - sign challenge and create a JWT
        const jwt = await new jose.SignJWT(
            {
                fe_nonce: fe_nonce,
                mm_pub: mm_pub,
                be_nonce: be_nonce
            }
        )
            .setProtectedHeader({
                alg: alg,
                jwk: public_jwk     // can we remove this now that we use Mongo?
            })
            .setIssuer('Monokee')
            .setAudience('Monokee')
            .setExpirationTime('10m')
            .sign(keypair.privateKey)

        return jwt
    }

    /**
     * Verify the validity of the challenge generated by the getVPChallenge function.
     * 
     * @param jwt   - the challenge in jwt format
     * @returns true if the challenge is valid, false otherwise
     */
    async verifyVPChallenge(jwt: CompactJWT) {

        let decodedJwt = jose.decodeJwt(jwt) as KeyPairDecodedJWT
        // console.log(decodedJwt)

        if (decodedJwt && decodedJwt.fe_nonce && decodedJwt.mm_pub) {
            const savedChallengeParams = await MongoDBFindChallenge(decodedJwt.fe_nonce)
            if (savedChallengeParams) {
                let verification = await jose.jwtVerify(jwt, await jose.importJWK(savedChallengeParams?.pubJWK))

                // check all other params
                if (
                    decodedJwt.iss == 'Monokee' &&
                    decodedJwt.aud == 'Monokee'
                    // decodedJwt.exp && decodedJwt.exp > (Math.floor((new Date()).getTime() / 1000)) THIS CHECK is already done
                ) {
                    return verification
                } else {
                    return false
                }
            } else {
                throw {
                    message: "Wrong fe_nonce value. It doesn't match in our systems"
                }
            }
        } else {
            throw {
                message: "Invalid jwk format."
            }
        }
    }
}

export = new VCController();
