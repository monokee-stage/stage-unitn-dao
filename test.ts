// import { Resolver } from 'did-resolver'
// import * as web from 'web-did-resolver'
import { Signature } from 'jose';
import { JWT_VP } from './lib/formats'


// //returns an object of { methodName: resolveFunction}
// let webResolver = web.getResolver()

// //If you are using multiple methods you need to flatten them into one object
// const resolver = new Resolver({
//   ...webResolver,
// })


// resolver.resolve("did:web:entra.ssi.monokee.com").then((res) => {
//     console.log(res.didDocument?.verificationMethod);
// })

interface JWT {
  header: Header,
  payload: Payload,
  signature?: Signature,
}

interface Header {
  typ: string,
  alg: string,
}
interface Payload {
  iat: string,
  sub: string,
  name: string,
}

let header: Header = {
  alg: "HS256",
  typ: "JWT"
};

let payload: Payload = 
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": "1516239022"
}

let jwt: JWT = {
  header: header,
  payload: payload,
}

// console.log(jwtEncode(jwt_prototype));




// const jwt_prototype = {
//   header: { alg: 'ES256K', typ: 'JWT' },
// payload: {
//   aud: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
//   name: 'uPort Developer',
//   iss: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
// },
// signature: 'mAhpAnw-9u57hyAaDufj2GPMbmuZyPDlU7aYSUMKk7P_9_cF3iLk-hFjFhb5xaUQB5nXYrciw6ZJ2RSAZI-IDQ',
// }


// function jwtEncode(jwt: JWT_VP): string {
//   didJWT.decodeJWT(jwt);
//   let header = jwt.header;
//   let payload = jwt.payload;

//   let ans: string = '';
//   ans += Buffer.from(JSON.stringify(header), 'binary').toString('base64');
//   ans += '.';
//   ans += Buffer.from(JSON.stringify(payload), 'binary').toString('base64');
//   ans += '.';
//   ans += jwt.signature;

//   return ans;
// }
