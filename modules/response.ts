import jwt_decode from 'jwt-decode';
import * as express from 'express';
import { AuthorizationResponse } from '../lib/response_types';
import { issIsKid, subIsIss_vp_vc, verifySignature, constraints,getKeyFromValue, filteringWrapper, uri } from '../lib/validate';
import { authorization_request } from './request';
import { JWT_VP_Payload } from '../lib/formats';
import Ajv from 'ajv';
import { responseSchema } from '../lib/response_types';

const ajv = new Ajv({allErrors: true})

const validate = ajv.compile(responseSchema);



// TODO: step8


// TODO: check string-JWT formats and decode and encode functions

// TODO: missing (and the next point) in step4: 
/*
    If the constraints property of the Input Descriptor is present, 
    and it contains an is_holder property, ensure that for each object in the array, 
    any submission of data in relation to the candidate input is fulfilled by the Subject of the attributes 
    so identified by the strings in the field_id array.
*/

// Q: are the formats correct? I require the submission of jwt's in strings... the evaluation that comes after might be specialized if I know the input correctly (only for jwt or jsonld)
// Q: 


export let vp_to_vcs: Map<string, string[]>;
export let id_to_vcs: Map<string,string[]>; // todo: maybe there isnt an array

export function authorizationResponseVerifier(request: express.Request, response: express.Response) {

    

    /*
        Following steps from:
        "https://identity.foundation/jwt-vc-presentation-profile/#structure-of-authorization-response"
        "https://identity.foundation/presentation-exchange/spec/v1.0.0/#input-evaluation"
    */

    try {
        
        if (!validate(request.body)) throw new Error("Invalid response");

        console.log(validate(request.body))


        let authorization_response: AuthorizationResponse = request.body;
        let presentation_submission = authorization_response.presentation_submission;
        let vp_token = authorization_response.vp_token;


        // 1. Determine the number of VPs returned in the VP Token and identify in which VP which requested VC is included, using the Input Descriptor Mapping Object(s) in the Presentation Submission.
        presentation_submission.descriptor_map.forEach((descriptor_map) => (filteringWrapper(descriptor_map, vp_token)));

        vp_to_vcs.forEach(async (_, vp) => { // forEach: value-key

            // 2. Check that the DID value in the kid and iss claims match in each of the VP(s).
            if (!issIsKid(vp)) throw new Error("vp's iss-kid don't match");

            // 3. Validate the signature of each of the VP(s) passed in the VP Token.
            if (!await verifySignature(vp)) throw new Error("Invalid VerifiablePresentation");

            // verify nonce
            if (authorization_request.nonce !== jwt_decode<JWT_VP_Payload>(vp).nonce) throw new Error("Invalid nonce");

            vp_to_vcs.get(vp)?.forEach(async (vc) => {

                // 4. Confirm that the VC meets all requested criteria using the mechanisms outlined in Section 4.3 of Presentation Exchange v1.0.0
                const key_id = getKeyFromValue(id_to_vcs,vc);
                const matched_input_descriptor = authorization_request.presentation_definition.input_descriptors.find((input_descriptor) => {
                    return input_descriptor.id === key_id;
                })
                if (matched_input_descriptor === undefined) throw new Error("VC has no id matches with any InputDescriptor");
                if (!constraints(jwt_decode(vc), matched_input_descriptor) || !uri(jwt_decode(vc), matched_input_descriptor)) throw new Error("Input evaluation went wrong");

                // 5. Check that the DID value in the kid and iss claims match in each of the VC(s).            
                if (!issIsKid(vc)) throw new Error("VC's iss-kid don't match");

                // 6. Validate signature(s) on each VC(s)
                if (!await verifySignature(vc)) throw new Error("Invalid VerifiableCredential");

                // 7. Check that the DID value in the iss Claim of a VP exactly match with the sub Claim in the VC(s). (Holder Binding)
                if (!subIsIss_vp_vc(vp, vc)) throw new Error("VC's 'sub' and related VP's 'iss' don't match");

            })
        
        })

    } catch(e: any) {
        response.status(400).send(e.message);
    }



}



/* 
    scorro tutte le vc che hanno un field contenuto in field_id array e verifico che abviano tutte lo stesso sub
*/

/*

A,B has i.d.
    isholder[]: iss, aud, verifiablecred.
                iss aud vc
                    exp aud vc
    field: iss, aud, exp, vc[0]




A,B,C has the same
    input_descriptor
        IS HOLDER id: a, b

        FIELD id: a, b, c

*/

// function isHolder(input_descriptor: InputDescriptor) {

//     if (input_descriptor.constraints.is_holder === undefined) return true;

//     // collecting vc's with the same input_desc id
//     let vcs: string[];
//     vc_to_id.forEach((id,vc) => {

        
//         if (input_descriptor.id === id) vcs.push(vc);
//     })

    
// }

