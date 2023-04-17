import jwt_decode from 'jwt-decode'
import * as express from 'express'
import { AuthorizationResponse } from '../lib/formats/response_types'
import { authorization_request } from './request'
import { JWT_VC_Payload, JWT_VP_Payload } from '../lib/formats/vp_vc'
import Ajv from 'ajv'
import { responseSchema } from '../lib/formats/response_types'
import { InputDescriptor } from '../lib/formats/request_types'

export let vp_to_vcs: Map<string, string[]> = new Map()
export let id_to_vcs: Map<InputDescriptor, string[]> = new Map()
export let vc_to_claims: Map<string, number> = new Map()

import { iss_kid, vc_vp_binding, constraints, uri, filteringWrapper, verifyJWT } from '../lib/validate'

const ajv = new Ajv({ allErrors: true })
const validate = ajv.compile(responseSchema)


// TODO: implement nested_path of descriptor_map in presentation submission (see OIDC4VP)

export function authorizationResponse(request: express.Request, response: express.Response) {

    // reset of outer function Maps
    vp_to_vcs.clear()
    id_to_vcs.clear()
    vc_to_claims.clear()

    /*
        Following steps from:
        "https://identity.foundation/jwt-vc-presentation-profile/#vp-token-validation"
        "https://identity.foundation/presentation-exchange/spec/v1.0.0/#input-evaluation"
    */

    try {

        if (!validate(request.body)) throw new Error("Invalid response");

        let authorization_response: AuthorizationResponse = request.body
        let presentation_submission = authorization_response.presentation_submission
        let vp_token = authorization_response.vp_token

        if (presentation_submission.definition_id !== authorization_request.presentation_definition.id) throw new Error("presentation_submission id doesn't match presentation_definition's id")

        /* 
            1. Determine the number of VPs returned in the VP Token and identify in which VP requested VC(s) are included, 
            using the descriptor map obtained from the Presentation Submission. 
        */
        process.stdout.write("1. retrieving VP's and VC's... ")
        presentation_submission.descriptor_map.forEach((descriptor_map) => (filteringWrapper(descriptor_map, vp_token)));
        process.stdout.write("Done\n")

        let promises = Array.from(vp_to_vcs.entries(), async ([vp, vcs]) => { // destructuring tuple in two separate values
            let vp_payload: JWT_VP_Payload = jwt_decode(vp);

            /* 2. Check that the DID value in the kid and iss claims match in each of the VP(s). */
            process.stdout.write("2. checking iss and kid parameters of the VP... ")
            if (!iss_kid(vp)) throw new Error("VP's iss and kid MUST match");
            process.stdout.write("Done\n")

            /*
                3. Validate the signature of each of the VP(s) passed in the VP Token. 
                Validation is performed against the key obtained from a DID Document. 
                DID Document MUST be obtained by resolving a Decentralized Identifier included in the iss claim using DID Resolution. 
                If a DID Doc contains multiple keys, kid in the header is used to identify which key to use.
            */
            process.stdout.write("3. verifying the VP jwt... ")
            if (!await verifyJWT(vp)) throw new Error("Invalid VerifiablePresentation");
            process.stdout.write("Done\n")

            // verify nonce
            // TODO: save the nonces for every session and then check it
            //if (authorization_request.nonce !== jwt_decode<JWT_VP_Payload>(vp).nonce) throw new Error("Invalid nonce");

            await Promise.all(vcs.map(async (vc) => {


                fillClaims(vc);

                let vc_payload: JWT_VC_Payload = jwt_decode(vc)
                const matched_input_descriptor = getKeyFromValue(id_to_vcs, vc);
                if (matched_input_descriptor === undefined) throw new Error("VC has no id matches with any InputDescriptor");

                /* 
                    4. Confirm that the VC meets all requested criteria using the mechanisms 
                    outlined in https://identity.foundation/presentation-exchange/spec/v1.0.0/#input-evaluation.
                */
                process.stdout.write("4. input evaluation... ")
                constraints(vc, matched_input_descriptor, vp_payload)
                uri(vc_payload, matched_input_descriptor)
                process.stdout.write("Done\n")


                /* 5. Check that the DID value in the kid and iss claims match in each of the VC(s). */
                process.stdout.write("5. checking iss and kid parameters of the VC... ")
                if (!iss_kid(vc)) throw new Error("VC's iss and kid MUST match");
                process.stdout.write("Done\n")

                /*
                    6. Validate signature(s) on each VC(s). 
                    Validation is performed against the key obtained from a DID Document. 
                    DID Document MUST be obtained by resolving a Decentralized Identifier included in the iss claim using DID Resolution. 
                    If a DID Doc contains multiple keys, kid in the header is used to identify which key to use.
                */
                process.stdout.write("6. verifying the VC jwt... ")
                if (!await verifyJWT(vc)) throw new Error("Invalid VerifiableCredential");
                process.stdout.write("Done\n")

                /* 7. Check that the DID value in the iss Claim of a VP exactly match with the sub Claim in the VC(s). (Holder Binding) */
                process.stdout.write("7. verifying holder binding... ")
                if (!vc_vp_binding(vp_payload, vc_payload)) throw new Error("VC's sub and related VP's iss don't match");
                process.stdout.write("Done\n")

                /* TODO: 8 missing */

                console.log("\nThe response has been successfully validated\n")

            }))

        })

        Promise.all(promises).then((_) => response.status(200).send("Valid AuthorizationResponse")).catch((e: any) => {
            response.status(400).send(e.message);
        })

    } catch (e: any) {
        response.status(400).send(e.message);
    }

}



/*
    maps each VC to its claims
*/
function fillClaims(vc: string) {
    let vc_payload: JWT_VC_Payload = jwt_decode(vc)
    vc_to_claims.set(vc, Object.keys(vc_payload).length)

}



/*
    by giving the value of a Map it returns the corresponding
*/
function getKeyFromValue<T>(map: Map<T, string[]>, value: string): T | undefined {
    for (const [key, val] of map.entries()) {
        for (let i = 0; i < val.length; i++) {
            if (val[i] === value) {
                return key;
            }
        }
    }
    return undefined;
}