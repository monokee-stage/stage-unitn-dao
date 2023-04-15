import {JSONSchemaType} from 'ajv';

export type VP_Token = string[] | string; // maybe update it to allow other formats

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
    path: string,
    path_nested?: DescriptorMap,
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

let vp_token_schema: JSONSchemaType<VP_Token> = {
    oneOf: [
        {
            type: "string" 
        },
        {
            type: "array",
            items: {
                type: "string"
            }
        }
    ]
}


// TODO: well built schema
interface ResponseSchema {
    vp_token: VP_Token,
    presentation_submission: any,
}

export let responseSchema: JSONSchemaType<ResponseSchema> = {
    type: "object",
    properties: {
        vp_token: vp_token_schema,
        presentation_submission: {
            type: "object",
            properties: {},
            required: [],
            nullable: true,
        }
        
    },
    required: ["vp_token"]
}