/* Copyright 2017-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.

 Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file
 except in compliance with the License. A copy of the License is located at

     http://aws.amazon.com/apache2.0/

 or in the "license" file accompanying this file. This file is distributed on an "AS IS"
 BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 License for the specific language governing permissions and limitations under the License.
*/

const https = require('https');
const jose = require('node-jose');

const region = process.env.AWS_DEFAULT_REGION;
const userPoolId = process.env.AWS_USER_POOL_ID;
const appClientId = process.env.AWS_USER_POOL_APP_CLIENT_ID;
const keysUrl = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}/.well-known/jwks.json`;

exports.handler = (event, context, callback) => {
  const method = event.httpMethod;

  switch(method) {
    case 'OPTIONS':
      callback(null, {
        statusCode: 200,
        headers: {
          "Access-Control-Allow-Origin": event.headers["origin"],
          "Access-Control-Allow-Methods": "POST,OPTIONS",
          "Access-Control-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key",
          "Content-Type": "application/json",
          "Access-Control-Allow-Credentials": "true"
        },
        body: ""
      });
      break;
    case 'POST':
      const token = JSON.parse(event.body).id_token;
      const sections = token.split('.');
      let header = jose.util.base64url.decode(sections[0]);
      header = JSON.parse(header);
      const kid = header.kid;
      // download the public keys
      https.get(keysUrl, function(response) {
        if (response.statusCode == 200) {
          response.on('data', function(body) {
            const keys = JSON.parse(body)['keys'];
            let keyIndex = -1;
            for (let i=0; i < keys.length; i++) {
              if (kid == keys[i].kid) {
                keyIndex = i;
                break;
              }
            }

            if (keyIndex == -1) {
              callback(null, {
                statusCode: 200,
                headers: {
                  "Access-Control-Allow-Origin": event.headers["origin"],
                  "Access-Control-Allow-Credentials": "true"
                },
                body: JSON.stringify({ error: 'Public key not found in jwks.json' })
              });
            }

            jose.JWK.asKey(keys[keyIndex]).
              then(function(result) {
                jose.JWS.createVerify(result).
                  verify(token).
                  then(function(result) {
                    const claims = JSON.parse(result.payload);
                    const currentTs = Math.floor(new Date() / 1000);

                    let response = {};

                    if (currentTs > claims.exp) {
                      response = { error: 'Token is expired' };
                    } else if (claims.client_id != appClientId) {
                      response = { error: 'Token was not issued for this audience' };
                    } else {
                      response = claims;
                    }

                    callback(null, {
                      statusCode: 200,
                      headers: {
                        "Access-Control-Allow-Origin": event.headers["origin"],
                        "Access-Control-Allow-Credentials": "true"
                      },
                      body: JSON.stringify(response)
                    });
                  }).
              catch(function() {
                callback(null, {
                  statusCode: 200,
                  headers: {
                    "Access-Control-Allow-Origin": event.headers["origin"],
                    "Access-Control-Allow-Credentials": "true"
                  },
                  body: JSON.stringify({ error: 'Signature verification failed' })
                });
              });
            });
          });
        }
      });
      break;
    default:
      callback("Unsupported HTTP method", null);
  }
}
