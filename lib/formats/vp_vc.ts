export interface JWT_VP {
    header: Header,
    payload: JWT_VP_Payload,
    signature: any,
}

export interface Header {
    kid: string,
}

export interface JWT_VC {
    header: Header,
    payload: JWT_VC_Payload,
    signature: any,
}

export interface JWT_VC_Payload {
    iss: string, // issuer of the JWT
    sub?: string, // subject of the JWT (DID)
    nbf: number, // issuance date
    exp: number, // expiration date
    iat?: number,
    aud: string, // audience
    jti: string, // UUID
    vc: JSON_LD_VC,
}

export interface JSON_LD_VC {
    '@context': string[]
    id?: string, // specify the identifier of the credential
    type: string[]; // example: ["VerifiableCredential", "UniversityDegreeCredential"]
    issuer?: string, // entity that issued the credential
    issuanceDate?: string,
    credentialSubject: {
        [key: string]: any, 
        id: string
    }, // claims about the subject of VC (JSON object)
    proof?: any,
    credentialSchema?: Array<CredentialSchema> | CredentialSchema,
}

interface CredentialSchema {
    type: string,
    id: string,
}

export interface JSON_LD_VP {
    "@context": string[],
    id?: string,
    type: string[],
    verifiableCredential: string[],
    holder?: string,
    proof?: any,
}

export interface JWT_VP_Payload {
    iss: string, // issuer of the JWT
    sub?: string, // subject of the JWT (DID)
    nbf: number, // issuance date
    exp: number, // expiration date
    aud: string, // audience
    jti: string, // UUID
    iat?: number,
    vp: JSON_LD_VP,
    nonce?: string,
}