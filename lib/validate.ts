import { JWT_VP_Payload, JWT_VC_Payload, Header } from './formats/vp_vc';
import jwt_decode from 'jwt-decode';
import { Resolver, DIDResolver, DIDResolutionResult } from 'did-resolver';
import { ConstraintsObject, Fields, InputDescriptor } from './formats/request_types';
import { VP_Token, DescriptorMap } from './formats/response_types';
import { authorization_request } from '../modules/request';
import { vp_to_vcs, id_to_vcs, vc_to_claims } from '../modules/response';
import * as didJWT from 'did-jwt';
import * as jp from 'jsonpath';
import Ajv from 'ajv';

const ajv = new Ajv({ allErrors: true })



/*
    returns TRUE if the kid and the issuer of a jwt match
*/
export function iss_kid(jwt: string): boolean {

    let header: Header = jwt_decode(jwt, { header: true });
    let payload: JWT_VP_Payload | JWT_VC_Payload = jwt_decode(jwt)
    return (header.kid === payload.iss);
}



/*
    return TRUE if the issuer of the presentation and the subject of the credential match
*/
export function vc_vp_binding(vp: JWT_VP_Payload, vc: JWT_VC_Payload): boolean {
    return (vc.sub === vp.iss);
}



/*
    returns TRUE if the subject and the issuer of a credential match
*/
export function sub_iss(vc: string, constraints: ConstraintsObject): boolean {

    if (constraints.subject_is_issuer !== "required") return true;

    let jwt_vc_payload: JWT_VC_Payload = jwt_decode(vc);
    if (jwt_vc_payload.iss === jwt_vc_payload.sub) return true
    else throw new Error("subject_is_issuer evaluation went wrong")
}



/*
    returns TRUE if the credentialSchema of the VC matches at least one schema of the InputDescriptor
*/
export function uri(vc: JWT_VC_Payload, input_descriptor: InputDescriptor): boolean {

    if (input_descriptor.schema === undefined) return true;
    if (vc.vc.credentialSchema === undefined) return false;


    return input_descriptor.schema.some((schema) => {
        if (Array.isArray(vc.vc.credentialSchema)) {
            return vc.vc.credentialSchema.some((credentialSchema) => {
                return credentialSchema.id === schema.uri;
            })
        }
        else {
            return vc.vc.credentialSchema?.id === schema.uri;
        }
    })

}



/*
    returns TRUE if all the checks on the constraints attributes (fields, limitDisclosure and subject_is_issuer) are satisfied
*/
export function constraints(vc: string, input_descriptor: InputDescriptor, vp: JWT_VP_Payload) {

    if (input_descriptor.constraints === undefined) return true;

    return fields(vc, input_descriptor.constraints) && limitDisclosure(vc, input_descriptor.constraints) && sub_iss(vc, input_descriptor.constraints);

}



/*
    returns TRUE if for ALL the field objects, at least one value of the path array matches a VC value 
*/
function fields(vc: string, constraints: ConstraintsObject): boolean {

    if (constraints.fields === undefined) return true;

    let vc_payload: JWT_VC_Payload = jwt_decode(vc);

    // each field in at least one path JSONPATH has to match
    if (constraints.fields?.every((field) => {

        return field.path.some((path) => {      // iss - vc.issuer - issuer   // birth.date - vc.bd

            /*
                if claims are retrieved inside the cred (in the jwt) add the .vc in path (check fillClaims function)
            */

            // !!! changing vc_payload requires changes also in limitDisclosure function
            const path_value = jp.value(vc_payload, path); // isHolder {iss} // TODO: only vc_payload or vc attribute?
            if (path_value === undefined) return false;

            return predicate(field, path_value) && filter(field, path_value)
        })

    })) return true
    else throw new Error("fields evaluation went wrong")
}



/*
    returns TRUE if the jsonpath value of a VC matches the schema of the filter
*/
function filter(field: Fields, obj: any) {

    if (field.filter === undefined) return true;

    let validate = ajv.compile(field.filter);
    if (validate(obj)) return true
    else throw new Error("filter evaluation went wrong")

}



/*
    returns TRUE if the jsonpath value of a VC is typeof boolean 
*/
function predicate(field: Fields, obj: any,) {

    if (field.predicate === undefined || field.predicate === "preferred") return true;
    else {
        if (field.filter === undefined) throw new Error("predicate evaluation went wrong");
        if (typeof obj === "boolean") return true
        else throw new Error("predicate evaluation went wrong")
    }

}



/*
    returns TRUE if ALL the claims of a VC are included in its field paths
*/
function limitDisclosure(vc: string, constraints: ConstraintsObject) {

    if (constraints.limit_disclosure !== "required") return true

    let claims = new Array<string>()
    let vc_payload: JWT_VC_Payload = jwt_decode(vc)

    constraints.fields?.forEach((field) => { 
        field.path.forEach((path) => {
            const path_value: any = jp.nodes(vc_payload, path) // isHolder {iss}
            if (path_value !== undefined) {
                claims.push(path_value.toString())
            }
        })
    })

    if (claims.length === vc_to_claims.get(vc)) return true
    else throw new Error("limit_disclosure evaluation went wrong")
}



/*
    returns TRUE if a JWT is valid, FALSE otherwise
*/
export async function verifyJWT(jwt: string): Promise<boolean> {


    try {
        const uniResolver = await getUniversalResolver()
        const resolver = new Resolver({
            web: uniResolver,
            key: uniResolver,
            // elem: uniResolver,
            // ethr: uniResolver,
            // cheqd: cheqdDidResolver().cheqd
        })

        const response = await didJWT.verifyJWT(jwt, {
            resolver
        });

        return true;

    } catch (error: any) {
        return false;
    }
}

function getUniversalResolver(
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



/*
    by analizing a descriptor_map retrieves the VC from the VP and fills the vp_to_vcs Map
*/
export function filteringWrapper(descriptor_map: DescriptorMap, vp_token: VP_Token) {

    //check id
    let temp_input_descriptor: InputDescriptor | undefined = authorization_request.presentation_definition.input_descriptors.find((input_desc) => {
        return descriptor_map.id === input_desc.id;
    })

    // this type check is ignored in lambda functions, that's why a temp variable is here needed
    if (temp_input_descriptor === undefined) throw new Error("The DescriptorMap has no id matches with any InputDescriptor")
    let input_descriptor: InputDescriptor = temp_input_descriptor;

    // check format
    if (descriptor_map.format !== "jwt_vp") throw new Error("outer 'descriptor_map.format: " + descriptor_map.format + "' not supported");
    // check path_nested
    if (descriptor_map.path_nested === undefined) throw new Error("path_nested attribute has to be defined")


    let jwt_vp: string = jp.value(vp_token, descriptor_map.path)

    if (vp_to_vcs.get(jwt_vp) === undefined) vp_to_vcs.set(jwt_vp, new Array<string>())
    if (id_to_vcs.get(input_descriptor) === undefined) id_to_vcs.set(input_descriptor, new Array())

    vp_to_vcs.get(jwt_vp)?.push(filtering(jwt_vp, descriptor_map.path_nested, input_descriptor))

    if (vp_to_vcs.get(jwt_vp) === undefined) { // if the value in the map is empty -> delete che key-value pair
        vp_to_vcs.delete(jwt_vp);
    }

}

function filtering(jwt: string, descriptor_map: DescriptorMap, input_descriptor: InputDescriptor): string {

    // check if inner id matches with outer id
    if (descriptor_map.id !== input_descriptor.id) throw new Error("nested id's have to match with the outer ones");

    if (descriptor_map.format !== "jwt_vc") throw new Error("nested_path format must be jwt_vc")

    let payload = jwt_decode<JWT_VC_Payload | JWT_VP_Payload>(jwt)
    let jwt_vc: string = jp.value(payload, descriptor_map.path)

    if (descriptor_map.path_nested === undefined) {
        id_to_vcs.get(input_descriptor)?.push(jwt_vc);
        return jwt_vc
    }
    else { // path_nested defined
        return filtering(jwt_vc, descriptor_map.path_nested, input_descriptor)
    }
}




/*  
    !!! SUBSTITUTED BY filteringWrapper()

    binds each VP to its VC's and the InputDescriptor to its VC's by filling <vp_to_vcs> and <id_to_vcs> Maps
*/
function getVPs(descriptor_map: DescriptorMap, vp_token: VP_Token) {
    let temp_input_descriptor: InputDescriptor | undefined = authorization_request.presentation_definition.input_descriptors.find((input_desc) => {
        descriptor_map.id === input_desc.id;
    })

    // this type check is ignored in lambda functions, that's why a temp variable is here needed
    if (temp_input_descriptor === undefined) throw new Error("The DescriptorMap has no id matches with any InputDescriptor")
    let input_descriptor: InputDescriptor = temp_input_descriptor;

    if (descriptor_map.format !== "jwt_vp") throw new Error("Format <" + descriptor_map.format + "> not yet implemented")
    if (descriptor_map.path_nested !== undefined) throw new Error("path_nested property not yet implemented")

    let jwt_vp: string = jp.value(vp_token, descriptor_map.path)

    vp_to_vcs.set(jwt_vp, new Array())
    if (id_to_vcs.get(input_descriptor) === undefined) id_to_vcs.set(input_descriptor, new Array());

    let vp_payload: JWT_VP_Payload = jwt_decode(jwt_vp);
    vp_payload.vp.verifiableCredential.forEach((jwt_vc) => {
        vp_to_vcs.get(jwt_vp)?.push(jwt_vc);
        id_to_vcs.get(input_descriptor)?.push(jwt_vc);
    })

    if (vp_to_vcs.get(jwt_vp)?.length === 0) throw new Error("The VP does not contain any VC");
}