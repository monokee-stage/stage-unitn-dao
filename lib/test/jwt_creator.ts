import { generateKeyPairSync } from 'crypto'
import * as jose from 'jose'
import { JSON_LD_VC, JSON_LD_VP } from '../formats/vp_vc'
// import { bytesToBase58 } from 'did-jwt/lib/util';
// import * as u8a from 'uint8arrays'


// const signlll = createSign("EdDSA")
// signlll.write("")
// signlll.end()



let keypair = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: 'jwk', type: 'pkcs8' },
    publicKeyEncoding: { format: 'pem', type: 'spki' }
});
// console.log(keypair)
// const signt = sign("Ed25519",Buffer.from(""), keypair.privateKey);

// const signt = signlll.sign(keypair.privateKey)
// console.log(signt)
// const signer = didJWT.ES256KSigner(Buffer.from(keypair.privateKey))

// console.log(signer)

const vc: JSON_LD_VC = {
    "@context": [
        "https://www.w3.org/2018/credentials/v1"
    ],
    "type": [
        "VerifiableCredential",
        "MonokeeRole"
    ],
    "credentialSubject": {
        "id": "did:key:zQ3sheJKHnGuiVnrMYnTPfQgFEVarxKdaFBCjfP4i4ohHVNFY",
        "email": "example@gmail.com",
        "uid": "ccccccc",
        "role": "llll"
    },
}

const vp: JSON_LD_VP = {
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
    ],
    "type": [
        "VerifiablePresentation",
        "CredentialManagerPresentation"
    ],
    "verifiableCredential": [],
}

// jwt_vc from vc
// jose.generateKeyPair('RS256').then(({ publicKey, privateKey }) => {



let privKey = keypair.privateKey
//console.log(priv)

// let str: string = keypair.publicKey as unknown as string
// str = str.split("\n")[1]
// console.log(str)
// // str = Buffer.from(str, "base64")
// // .toString('base64url')

// // didJWT.base58ToBytes(str)
// console.log(str)

// function encodeDID(publicKey: Buffer): string {
//     const bytes = new Uint8Array(publicKey.length + 2)
//     bytes[0] = 0xed // ed25519 multicodec
//     // The multicodec is encoded as a varint so we need to add this.
//     // See js-multicodec for a general implementation
//     bytes[1] = 0x01
//     bytes.set(publicKey.writeUInt8(), 2)
//     return "did:key:z" + u8a.toString(bytes, "base58btc");
// }




// const issuer = encodeDID(Buffer.from(str, "base64"))

// console.log(issuer)


function vp_gen(vc_iss: any, vc_kid: any, vc_sub: string, vp_iss: string, vp_kid: string) {
    jose.importJWK(privKey as unknown as jose.JWK , "ed25519" ).then((privKey) => {

        new jose.SignJWT({ "vc": vc }).setIssuer(vc_iss).setProtectedHeader({ "alg": "EdDSA", "kid": vc_kid }).setSubject(vc_sub).sign(privKey).then((jwt_vc) => {
    
            // jwt_vc in vp
            vp.verifiableCredential.push(jwt_vc)
        
            // jwt_vp from vp
            // jose.generateKeyPair('RS256').then(({ publicKey, privateKey }) => { 
        
            new jose.SignJWT({ "vp": vp }).setIssuer(vp_iss).setProtectedHeader({ "alg": "EdDSA", "kid": vp_kid }).sign(privKey).then((res) => {
                console.log("\n\nvp: {\n\t" + res + "\n\n}")
                //syncWriteFile("./out.txt", res);
            })
    
            vp.verifiableCredential.pop()
        })
    
    })
}

vp_gen("aaa","aaa","iss","iss","iss")