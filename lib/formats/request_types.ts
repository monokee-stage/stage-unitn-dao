import { JSONSchemaType } from "ajv";

export interface AuthorizationRequest {
  response_type: "vp_token",
  client_id: string, // a unique string representing the registration information provided by the client
  presentation_definition: PresentationDefinition,
  nonce: string, // UUID string
  response_mode?: "direct_post",
  redirect_uri: string,
  state?: string,
}

export interface PresentationDefinition {
  id: string, // UUID string
  input_descriptors: Array<InputDescriptor>,
}

export interface InputDescriptor {
  id: string,
  constraints: ConstraintsObject,
  schema?: Schema[],
  name?: string,
  purpose?: string,
}

interface Schema {
  uri: string,
  required?: boolean,
}


export interface ConstraintsObject {
  fields?: Fields[],
  limit_disclosure?: "preferred"| "required",
  subject_is_issuer?: "preferred" | "required",
  is_holder?: IsHolder[],
  same_subject?: SameSubject[],
}

type IsHolder = IsHolderAndSameSubject;
type SameSubject = IsHolderAndSameSubject;

interface IsHolderAndSameSubject {
  field_id: string[],
  directive: "required" | "preferred",
}

export interface Fields {
  path: Array<string>,
  id?: string, // string that is unique from every other field object’s id property, including those contained in other Input Descriptor Objects
  purpose?: string,
  name?: string,
  filter?: JSONSchemaType<any>,
  predicate?: "required" | "preferred",
}

/*
{
    "jti": "329d0f14-88f4-4273-9668-ee474608a827",
    "iat": 1679900210,
    "response_type": "id_token",
    "response_mode": "post",
    "scope": "openid",
    "nonce": "hV0M/YzaTIfcVhLSFvh7gA==",
    "client_id": "did:web:entra.ssi.monokee.com",
    "redirect_uri": "https://verifiedid.did.msidentity.com/v1.0/tenants/1f1c2ff8-489d-4639-bf18-12c37e99666c/verifiableCredentials/verifyPresentation",
    "state": "djH+lH5/yI3QlOhrtTPpZXZwzSwgHNQjFxw/zoOHApLBAo0mqLL5jV25VTQqUhZv35uCWvrpoKSXDZt2isJ9kA2y+54rA3BN6q6btmRc357IrjE04Krm9N1e6f07iErKUCHWtkfeKeK2S8IRRD80+EN+kgrTK5KrMsnZaeRAhweHmNU5cMH85JX3xAPiMIH86mvkurOkPf2Q06BxYwoqY1vA0NGVL36hWH9E/DNXo94w7nJ6vDqJTv1HZKFbz8dKJmttlRjmR/vlderGqfmnPeWgU9hqljrIgS42XPeg7SZzpw2v3afsohid3XUao3DsTCchpGBhWHaxFvsNtSE1WxhsrJM1TgNhFrNie/tDGvb/7bJKJokwB3TO1kk26R3aTj/s93UBV+4RLF2U9WPt/02/Gv9ZSISKHyo7OSLybNx9AjrEGBXGqCa08wHuFeA5lGjp1HPMxuBtEAUbmojc5k3ItSwgXnPbQhz7gdP6H5xUnHL7nZ9q7BZEA4+5XMl4wFmC13r5kH5tPfONCPpddvIUpZaZ6AuYNHjZTI01x87AGZPu2sjcxwjrZQan7Fr3D9E5m5nZExucgi+5e27jZ+cCpc42tpD/r+nu4nf1KQ==",
    "exp": 1679900510,
    "registration": {
      "client_name": "Monokee Verifier",
      "subject_syntax_types_supported": [
        "did:ion"
      ],
      "vp_formats": {
        "jwt_vp": {
          "alg": [
            "ES256K",
            "EdDSA"
          ]
        },
        "jwt_vc": {
          "alg": [
            "ES256K",
            "EdDSA"
          ]
        }
      }
    },
    "claims": {
      "vp_token": {
        "presentation_definition": {
          "id": "4fa84504-de5b-4698-806f-e84aa5f7029c",
          "input_descriptors": [
            {
              "id": "MonokeeEmployee",
              "name": "MonokeeEmployee",
              "purpose": "For authentication",
              "schema": [
                {
                  "uri": "MonokeeEmployee"
                }
              ],
              "constraints": {
                "fields": [
                  {
                    "path": [
                      "$.issuer",
                      "$.vc.issuer",
                      "$.iss"
                    ],
                    "filter": {
                      "type": "string",
                      "pattern": "did:web:entra.ssi.monokee.com"
                    }
                  }
                ]
              }
            },
            {
              "id": "MonokeeRole",
              "name": "MonokeeRole",
              "purpose": "For authentication",
              "schema": [
                {
                  "uri": "MonokeeRole"
                }
              ],
              "constraints": {
                "fields": [
                  {
                    "path": [
                      "$.issuer",
                      "$.vc.issuer",
                      "$.iss"
                    ],
                    "filter": {
                      "type": "string",
                      "pattern": "did:web:entra.ssi.monokee.com"
                    }
                  }
                ]
              }
            }
          ]
        }
      }
    }
  }

  */