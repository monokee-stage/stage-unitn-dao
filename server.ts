import * as express from 'express';
import * as http from 'http';
import { authorizationRequest } from './modules/request';
import { authorizationResponseVerifier } from './modules/response';

const PORT = 8000;
export const REDIRECT_URI = "localhost:" + PORT.toString() + "/post";

// Create Express server
const app = express();
app.use(express.json()); // check for the correct method
const http_server = http.createServer(app);

// sending authotization request
app.get("/", authorizationRequest);

// handling authorization response
app.post("/post", authorizationResponseVerifier);


// app.post(RESPONSE_URI, vp_token_verifier); 

http_server.listen(PORT, () => { console.log('Listening on ' + PORT.toString() + ' port') })


