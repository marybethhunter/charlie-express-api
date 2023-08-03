const express = require("express");
const app = express();
const { auth, requiredScopes } = require("express-oauth2-jwt-bearer");
const cors = require("cors");
require("dotenv").config();
const { expressjwt: jwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');

const issuerBaseUrl = process.env.AUTH0_ISSUER_BASE_URL;
const audience = process.env.AUTH0_AUDIENCE;
const clientID = process.env.AUTH0_CLIENT_ID;
const clientSecret = process.env.AUTH0_CLIENT_SECRET;
const managementAPIaudience = process.env.AUTH0_MGMT_AUDIENCE;

const corsOptions = {
  origin: "http://localhost:3000",
};

const checkScopes = requiredScopes('read:actions read:clients read:triggers');

app.use(cors(corsOptions));

const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `${issuerBaseUrl}/.well-known/jwks.json`
  }),
  audience: audience,
  issuer: `${issuerBaseUrl}/`,
  algorithms: ['RS256']
});

app.get("/api/public", function (req, res) {
  res.json({
    message:
      "Hello from a public endpoint! You don't need to be authenticated to see this.",
  });
});

app.get("/api/private", checkJwt, function (req, res) {
  res.json({
    message:
      "Hello from a private endpoint! You need to be authenticated to see this.",
  });
});

app.get(
  "/api/private-scoped",
  checkJwt,
  requiredScopes("read:actions read:clients read:triggers"),
  async (req, res) => {

    let options = {
      method: 'POST',
      url: `${issuerBaseUrl}/oauth/token`,
      headers: { 'content-type': 'application/json' },
      data: {
        grant_type: 'client_credentials',
        client_id: clientID,
        client_secret: clientSecret,
        audience: managementAPIaudience
      }
    };

    const managementAPIToken = await axios.request(options).then(res => {
      return `Bearer ${res.data.access_token}`;
    });
  
    const getAllActions = await axios
      .get(`${managementAPIaudience}actions/actions`, {
        headers: { authorization: managementAPIToken }
      })
      .then(res => {
        return res.data;
      });
  
    const getAllClients = await axios
      .get(`${managementAPIaudience}clients`, {
        headers: { authorization: managementAPIToken }
      })
      .then(res => {
        return res.data;
      });
  
    let finalList = [];
    let noActionMessage = { message: 'This application has no associated actions.' };
  
    const match = (clients, actions) => {
      clients.forEach(client => {
        const oneSingleClient = { name: client.name, id: client.client_id, actions: [] };
        finalList.push(oneSingleClient);
      });
  
      const actionsArray = Object.values(actions);
  
      const finalActionsArray = actionsArray.flat();
  
      finalList.forEach(client => {
        const matchingActions = finalActionsArray.filter(action => action.code?.includes(client.id));
        if (matchingActions.length > 0 && req.auth.permissions.includes('read:triggers')) {
          matchingActions.forEach(action => {
            client.actions.push({
              id: action.id,
              name: action.name,
              trigger: action.supported_triggers[0].id
            });
          });
        }
        if (matchingActions.length > 0 && !req.auth.permissions.includes('read:triggers')) {
          matchingActions.forEach(action => {
            client.actions.push({
              id: action.id,
              name: action.name
            });
          });
        } else {
          client.actions.push(noActionMessage);
        }
      });
    };
  
    match(getAllClients, getAllActions);
  
    const removeLast = array => {
      array.length--;
      return array;
    };
  
    removeLast(finalList);
  
    res.json(finalList);


    // res.json({
    //   message:
    //     "Hello from a private endpoint! You need to be authenticated and have a scope of read:messages to see this.",
    // });
  }
);

app.use(function (err, req, res, next) {
  console.error(err.stack);
  return res.set(err.headers).status(err.status).json({ message: err.message });
});

app.listen(process.env.PORT || 3000);
