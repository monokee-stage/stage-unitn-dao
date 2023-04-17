import * as monokee from '../lib/formats/request_types'
import * as express from 'express'
import {randomUUID} from 'crypto'
import * as jp from 'jsonpath'

//TODO input_desc.schema to define

export let authorization_request: monokee.AuthorizationRequest = require('../lib/formats/request.json')

export function authorizationRequest(_request: express.Request ,response: express.Response){ 

    console.log("connected...")

    let presentation_definition: monokee.PresentationDefinition = authorization_request.presentation_definition

    presentation_definition.input_descriptors.forEach((input_descriptors) => {
        let constraints: monokee.ConstraintsObject = input_descriptors.constraints
        let fields: monokee.Fields[] | undefined = constraints.fields

        // check fields.path as jsonpath
        if (fields !== undefined) {
            if (fields.every((field) => {
                return field.path.every((elem) => {
                    try {
                        jp.parse(elem)
                        return true
                    } catch(e: any) {
                        return false
                    }
                })
            }) === false) throw new Error("Fields.path is not a jsonpath array")
        } 
    
        // check if at least one parameter of constraints is defined
        if (constraints.fields === undefined && constraints.limit_disclosure === undefined) {
            throw new Error("Constraints MUST contain at least an object")
        } 

        // check if input_descriptors id are unique
        {
            let input_descriptors_ids = new Set<string>()
            presentation_definition.input_descriptors.forEach((elem) => {
                if (input_descriptors_ids.has(elem.id))
                    throw new Error("input_descriptor id's have to be unique");
                else
                    input_descriptors_ids.add(elem.id)
            })
        }
    })

    // check if the params are correct
    authorization_request.nonce = randomUUID()
    authorization_request.presentation_definition.id = randomUUID()


    response.send(authorization_request) //send the AuthotizationRequest
}