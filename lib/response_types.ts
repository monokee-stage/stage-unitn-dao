import {JWT_VP} from './formats';
import {JSONSchemaType} from 'ajv';

export type VP_Token = (JWT_VP | string)[]; // jwt or jwt in string format

export interface AuthorizationResponse {
    vp_token: VP_Token,
    presentation_submission: PresentationSubmission,
}

// Presentation Submission
export interface PresentationSubmission {
    id: string,
    definition_id: string,
    descriptor_map: DescriptorMap[],
}

export interface DescriptorMap {
    id: string, // string that matches the id property of the Input Descriptor in the Presentation Definition that this Presentation Submission is related to
    format: "jwt_vp" | "jwt_vc",
    path: string, // the correct type form is Array<jsonpath>
    path_nested: DescriptorMap,
}

// export let responseSchema: JSONSchemaType<AuthorizationResponse> = {
//     type: "object",
//     properties: {

//         vp_token: {
//             type: "Array", 
//             items: {
//                 type: "string"
//             }
//         },

//         presentation_submission: {
//             type: "object",
//             properties: [],
//         }
//     },

// }


// TODO: well built schema
interface ResponseSchema {
    vp_token: string[],
    presentation_submission: any,
}

export let responseSchema: JSONSchemaType<ResponseSchema> = {
    type: "object",
    properties: {
        vp_token: {
            type: "array",
            items: {
                type: "string"
            },
            nullable: false,
        },
        presentation_submission: {
            type: "object",
            properties: {},
            required: [],
            nullable: true,
        }
        
    },
    required: ["vp_token"]
}