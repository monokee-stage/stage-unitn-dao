import { JWT_VP_Payload, JWT_VC_Payload, JSON_LD_VC, Header, JWT_VP } from './formats';
import jwt_decode from 'jwt-decode';
import { Resolver } from 'did-resolver';
import * as ethr from 'ethr-did-resolver';
import * as web from 'web-did-resolver';
import * as jose from 'jose'
import { Fields, InputDescriptor } from './request_types';
import { VP_Token, DescriptorMap } from './response_types';
import { authorization_request } from '../modules/request'; // todo: save it somewhere (i.d. and nonces)
import { vp_to_vcs, id_to_vcs } from '../modules/response';
import * as jp from 'jsonpath';
import Ajv from 'ajv';

const ajv = new Ajv({allErrors: true})



export function isJSON(vc: JSON_LD_VC | JWT_VC_Payload): vc is JSON_LD_VC {
    return (vc as JSON_LD_VC).issuer !== undefined;
}

export function isVCPayload(payload: JWT_VC_Payload | JWT_VP_Payload): payload is JWT_VC_Payload {
    return (payload as JWT_VC_Payload).vc !== undefined;
}


/*
    checks if the iss and kid parameters match by returning a boolean
    return value: TRUE if matches
*/
export function issIsKid(jwt: string): boolean {

    let decoded_jwt_header: Header = jwt_decode(jwt, { header: true }); // check if it returns only the header
    let decoded_jwt_payload: JWT_VP_Payload | JWT_VC_Payload = jwt_decode(jwt) // check if returns only the payload
    return (decoded_jwt_header.kid === decoded_jwt_payload.iss);
}

/*
checks if the iss parameter of the VP and the kid parameter of the VC match by returning a boolean
return value: TRUE if matches
*/
export function subIsIss_vp_vc(jwt_vp: string, jwt_vc: string): boolean {
    return (jwt_decode<JWT_VC_Payload>(jwt_vc).sub === jwt_decode<JWT_VP_Payload>(jwt_vp).iss);
}

/*
checks if the subject and the issuer are the same in the same credential
*/
export function subIsIss(vc: JWT_VC_Payload | JSON_LD_VC, input_descriptor: InputDescriptor) {

    if (input_descriptor.constraints.subject_is_issuer !== "required") return true;

    if (isJSON(vc)) {
        vc.credentialSubject.some((sub: any) => {
            sub.id === vc.issuer;
        })
    }
    else {
        return vc.iss === vc.sub
    }
}

/*
    used to retrieve VP's and VC's (by filling <vp_to_vcs> Map)
    used to link all the VC's to theirs input_descriptor id (by filling <vc_to_id> Map)
*/
export function filteringWrapper(descriptor_map: DescriptorMap, vp_token: VP_Token) {

    //check id
    if (!authorization_request.presentation_definition.input_descriptors.some((input_descriptor) => {
        return input_descriptor.id === descriptor_map.id;
    })) throw new Error("descritor_map.id has no matches with input_descriptor.id's");

    // check format
    if (descriptor_map.format === "jwt_vp") {
        throw new Error("outer 'descriptor_map.format' not supported");
    }
    else {
        let jwt_vp: string = jp.value(vp_token, descriptor_map.path); // TODO: add encoding in string if JWT_VP is not a string

        if (typeof jwt_vp !== "string") throw new Error("jwt's MUST be strings");

        if (vp_to_vcs.get(jwt_vp) === undefined) vp_to_vcs.set(jwt_vp, new Array<string>());

        if (descriptor_map.path_nested === undefined) {
            throw new Error("VerifiablePresentation has to contain at least one VerifiableCredential");
        }
        else {
            vp_to_vcs.get(jwt_vp)?.push(filtering(jwt_vp,descriptor_map,descriptor_map.id));
            if (vp_to_vcs.get(jwt_vp) === undefined) { // if the value in the map is empty -> delete che key-value pair
                vp_to_vcs.delete(jwt_vp);
            }
        }
    }

}

export function filtering(jwt: string, descriptor_map: DescriptorMap, id: string): string {

    // check if id matches with outer id
    if (descriptor_map.id !== id) throw new Error("Nested id's have to match with the outer one");

    if (descriptor_map.format === "jwt_vc") { // todo: upgrade to all formats?

        let payload = jwt_decode<JWT_VC_Payload | JWT_VP_Payload>(jwt);
        let jsonld;
        
        if (isVCPayload(payload)) {
            jsonld = payload.vc;
        }
        else {
            jsonld = payload.vp;
        }   /*
                    id = ciao

                    descmap
                        id ciao
                            vp -> vc -> vc1        id->vc[]
                        id ciao
                            vp1 -> vc -> vc2

        */

        let jwt_vc: string = jp.value(jsonld, descriptor_map.path); // todo: check if it has to be retrieved from a jsonld
        
        if (id_to_vcs.get(id) === undefined) id_to_vcs.set(id, new Array<string>());
        id_to_vcs.get(id)?.push(jwt_vc);
        
        if (typeof jwt_vc !== "string") throw new Error("jwt's MUST be strings");

        if(descriptor_map.path_nested !== undefined) return filtering(jwt_vc, descriptor_map.path_nested, descriptor_map.id);
        else {
            return jwt_vc;
        }
    }

    else throw new Error("nested 'descriptor_map.format' has to be 'jwt_vc'" );
}




export async function getKey(jwt_string: string) {

    let jwt_payload: JWT_VP_Payload | JWT_VC_Payload = jwt_decode(jwt_string);

    // TODO
    let ethrResolver = ethr.getResolver({}); 
    let webResolver = web.getResolver();

    const resolver = new Resolver({
        ...ethrResolver,
        ...webResolver,
    });
    // end todo

    let didDoc = await resolver.resolve(jwt_payload.iss);
    if (didDoc.didDocument === null) throw new Error("invalid DidDocument");
    else {
        let key = didDoc.didDocument.verificationMethod?.at(0)?.publicKeyJwk;
        if (key === undefined) throw new Error("invalid DidDocument.verificationMethod[0].publicKeyJwt"); // TODO check which key
        else {
            // switching type (to use it in verifySignature: required KeyLike)
            let ans = await jose.importJWK(key,"PS256"); // check ps256  |   type compatibility problem
            return ans;
        }
    }
}

export async function verifySignature(jwt: string) {

    let key = await getKey(jwt);
    
    if (await jose.jwtVerify(jwt, key) !== undefined) return true;
    else return false; // TODO: check the return type of func

}

/*
    checks is the vc's schema matches at least one i.d. -> schema -> uri.value
*/
export function uri(vc: JSON_LD_VC | JWT_VC_Payload, input_descriptor: InputDescriptor) { // check input type of vc
    
    if (isJSON(vc)) {
        if (vc.credentialSchema === undefined) return false; // TODO: is false correct here? (i.d. cred. schema has to be defined, so it would be resonable if credential schema of vc is too)

        return input_descriptor.schema.some((schema) => {
            if (Array.isArray(vc.credentialSchema)) {
                return vc.credentialSchema.some((credentialSchema) => {
                    return credentialSchema.id === schema.uri;
                })
            }
            else {
                return vc.credentialSchema?.id === schema.uri;
            }
        })
    }
    else {
        uri(vc.vc, input_descriptor);
    }

    
}

export function constraints(vc: JWT_VC_Payload | JSON_LD_VC, input_descriptor: InputDescriptor) {
    
    if (input_descriptor.constraints === undefined) return true;
    if (input_descriptor.constraints.fields === undefined) return true;
    
    return fields(vc,input_descriptor);

}

function fields(vc: JWT_VC_Payload | JSON_LD_VC, input_descriptor: InputDescriptor) {
    
    let matched_paths = new Array();

    // each field in at least one path JSONPATH has to match
    return (input_descriptor.constraints.fields?.every((field) => {

        return field.path.some((path) => {
            const path_value = jp.value(vc, path);
            if (path_value === undefined) return false;

            // path match
            matched_paths.push(path_value);
            if (field.predicate === undefined) return filter(field,path_value);
            else {
                return predicate(field, path_value);
            }
        })

    }) && limitDisclosure(vc,matched_paths,input_descriptor)) && subIsIss(vc,input_descriptor);
}

function filter(field: Fields, obj: any) {
    // optional parameter
    if (field.filter === undefined) return true;

    let validate = ajv.compile(field.filter);
    return validate(obj)

}

function predicate(field: Fields, obj: any, ) {
    if (field.filter === undefined) return false;

    return (typeof obj === "boolean");

}

function limitDisclosure(vc: JWT_VC_Payload | JSON_LD_VC, path_match: any[], input_descriptor: InputDescriptor) {    

    if (input_descriptor.constraints.limit_disclosure !== "required") return true;

    if (isJSON(vc)) {
        return Object.values(vc).every((value) => {
            return path_match.includes(value)
        })
    }
    else {
        limitDisclosure(vc.vc, path_match, input_descriptor);
    }
    
}

export function getKeyFromValue(map: Map<string, string[]>, value: string): string | undefined {
    for (const [key, val] of map.entries()) {
        for (let i = 0; i < val.length; i++) {
            if (val[i] === value) {
                return key;
            }
        }
    }
    return undefined;
}

