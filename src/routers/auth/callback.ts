import {URL, URLSearchParams} from "url";
import {SignJWT} from "jose";
import rTracer from "cls-rtracer";
import config from "config";
import expressAsyncHandler from "express-async-handler";
import {getActiveKey} from "../../controllers/keyController.js";
import {authorizations, byondCerts, clients, userData} from "../../db/index.js";
import {AuthorizationStatus, ResponseMode} from "../../db/types.js";
import {moduleLogger} from "../../logger.js";
import {domain} from "../../util/constants.js";
import {generateOIDCHash, generateSecureString, secureCompare} from "../../util/crypto.js";
import {oauth_authorize_error} from "../../util/responseHelpers.js";

export const callbackLogger = moduleLogger("CallbackEndpoint");

const callbackEndpoint = expressAsyncHandler(async (req, res) => {
  function returnError(error: string) {
    res
      .status(400)
      .type("text/plain")
      .send(`${error} Request ID: ${rTracer.id()}`)
      .end();
  }

  const client_id = req.query.client_id;

  const byondState = req.query.byond_state;
  if (typeof byondState !== "string") {
    callbackLogger.warning("byondState is invalid", {byondState});
    return returnError("byondState is invalid.");
  }

  const encodedCert = req.query.encoded_cert;
  if (typeof encodedCert !== "string") {
    callbackLogger.warning("encodedCert is invalid", {encodedCert});
    return returnError("encodedCert is invalid.");
  }

  const certMaxAge = new Date(Date.now() - 5 * 60 * 1000);
  const decodedCert = await byondCerts.findOne(
    {_id: encodedCert, createdTime: {$gte: certMaxAge}},
    {projection: {byondState: 1, byondCert: 1, clientIp: 1}},
  );

  if (!decodedCert) {
    callbackLogger.warning("encodedCert is invalid", {encodedCert});
    return returnError("encodedCert is invalid.");
  }

  await byondCerts.deleteOne({_id: encodedCert});

  if (decodedCert.clientIp !== req.ip) {
    callbackLogger.warning("clientIp mismatch", {
      expected: decodedCert.clientIp,
      provided: req.ip,
    });
    callbackLogger.crit("Suspicious behvaiour");
    return returnError("Client IP mismatch.");
  }

  if (!secureCompare(decodedCert.byondState, byondState)) {
    callbackLogger.warning("byondState mismatch", {
      expected: decodedCert.byondState,
      provided: byondState,
    });
    callbackLogger.crit("Suspicious behvaiour");
    return returnError("byondState mismatch.");
  }

  // securityMiddleware only encodes it; we verify its shape here.
  const byondCert = JSON.parse(decodedCert.byondCert);
  if (typeof byondCert !== "string") {
    callbackLogger.warning("byondCert is invalid", {
      byondCert: byondCert,
    });
    callbackLogger.crit("Suspicious behvaiour");
    return returnError("byondCert is invalid.");
  }

  const authorization = await authorizations.findOne({byondState});

  if (!authorization) {
    callbackLogger.warning("Can't find authorization request", {
      byondState: byondState,
    });
    return returnError("Unable to find authorization request");
  }

  const authClient = await clients.findOne(
    {_id: authorization.clientId},
    {projection: {expiry: 1, disabled: 1}},
  );
  if (!authClient) {
    callbackLogger.warning("Client from authorization no longer exists", {
      clientId: authorization.clientId,
    });
    return returnError("Unknown client");
  }

  if (authorization.clientId != client_id) {
    callbackLogger.warning("client_id mismatch", {
      authorization: authorization,
      client_id,
    });
    callbackLogger.crit("Suspicious behvaiour");
    return returnError(`client_id mismatch. Got ${client_id}`);
  }

  if (authClient.disabled !== null) {
    callbackLogger.warning("client is disabled", {
      client_id,
    });
    return returnError(
      `The client "${client_id}" is disabled for the following reason: ${authClient.disabled}`,
    );
  }
  req.redirect_uri = authorization.redirectUri;

  // Check that the user hasn't changed IPs between /authorize and /callback
  if (authorization.userIp != req.ip) {
    callbackLogger.warning("IP mismatch", {
      expected_ip: authorization.userIp,
      provided_ip: req.ip,
    });
    callbackLogger.crit("Suspicious behvaiour");
    return oauth_authorize_error(
      res,
      authorization.redirectUri,
      "access_denied",
      "IP mismatch between authorization initiator and finisher.",
      authorization.state,
    );
  }

  if (authorization.status !== AuthorizationStatus.Created) {
    callbackLogger.warning("Authorization is already completed", {
      authorization,
    });
    callbackLogger.crit("Suspicious behvaiour");
    return oauth_authorize_error(
      res,
      authorization.redirectUri,
      "access_denied",
      "Authorization request is already complete.",
      authorization.state,
    );
  }

  const timestamp15minsago = Date.now() - 15 * 60 * 1000;
  if (authorization.startDate.valueOf() < timestamp15minsago) {
    callbackLogger.warning("Authorization is too old", {
      authorization,
    });
    return oauth_authorize_error(
      res,
      authorization.redirectUri,
      "access_denied",
      "Authorization request is too old.",
      authorization.state,
    );
  }

  // Fetch the user data either from BYOND or the test mock
  let userDataResult;
  if (config.get<boolean>("security.test")) {
    // Cert == ckey in test mode
    userDataResult = {
      valid: true,
      key: byondCert,
      gender: "test",
    };
  } else {
    const {requestCkey} = await import("bab-hub-rs");
    userDataResult = await requestCkey(byondCert, domain);
  }

  if (!userDataResult.valid) {
    callbackLogger.warning("Hub does not recognize certificate", {byondCert, domain});
    return oauth_authorize_error(
      res,
      authorization.redirectUri,
      "access_denied",
      "Hub does not recognize certificate",
      authorization.state,
    );
  }

  // Sub claim enforcement: the client asked for a specific user, and someone else is logged in
  if (authorization.subClaim !== null && authorization.subClaim !== userDataResult.key) {
    callbackLogger.warning("Another user is logged in", {byondCert, domain});
    return oauth_authorize_error(
      res,
      authorization.redirectUri,
      "login_required",
      "Another user is logged in and the client has made a sub claim.",
      authorization.state,
    );
  }

  // Mint a code and associate the authorization with the user data
  const code = (authorization.responseTypes.includes("code") as boolean)
    ? await generateSecureString(24)
    : null;
  await userData.updateOne(
    {_id: userDataResult.key},
    {$set: {gender: userDataResult.gender}},
    {upsert: true},
  );
  await authorizations.updateOne(
    {_id: authorization._id},
    {
      $set: {
        code,
        status: authorization.responseTypes.includes("code")
          ? AuthorizationStatus.CodeIssued
          : AuthorizationStatus.Completed,
        endDate: new Date(),
        ckey: userDataResult.key,
      },
    },
  );

  let id_token;
  if (authorization.responseTypes.includes("id_token")) {
    const key = await getActiveKey();

    callbackLogger.info("Issuing ID token via hybrid/implicit flow");
    id_token = await new SignJWT({
      iss: config.get<string>("server.publicUrl"),
      sub: `user:${userDataResult.key}`,
      ckey: userDataResult.key,
      aud: client_id,
      exp: new Date().valueOf() + authClient.expiry * 1000,
      iat: new Date().valueOf(),
      auth_time: new Date().valueOf(),
      nonce: authorization.nonce,
      azp: client_id,
      c_hash: code !== null ? generateOIDCHash(code) : undefined,
      gender: userDataResult.gender,
    })
      .setProtectedHeader({
        alg: "RS256",
        kid: key._id,
        type: "JOSE",
      })
      .sign(key.importedPrivate);
  }

  // Redirect back to app with code / id_token
  const redirect = new URL(authorization.redirectUri);

  // Query response mode
  if (authorization.responseMode === ResponseMode.query) {
    /* Code Grant */ if (code !== null) redirect.searchParams.set("code", code);
    /* State */ if (authorization.state != null)
      redirect.searchParams.set("state", authorization.state);
    // Fragment response mode
  } else if (authorization.responseMode === ResponseMode.fragment) {
    const fragmentParams = new URLSearchParams();

    /* Code Grant */ if (code !== null) fragmentParams.set("code", code);
    /* State */ if (authorization.state != null) fragmentParams.set("state", authorization.state);
    /* ID Token */ if (id_token !== undefined) fragmentParams.set("id_token", id_token);

    redirect.hash = fragmentParams.toString();
    // Invalid response mode
  } else {
    callbackLogger.warning("callback does not recognize response_mode", {
      response_mode: authorization.responseMode,
    });
    return oauth_authorize_error(
      res,
      authorization.redirectUri,
      "access_denied",
      "callback does not recognize response_mode",
      authorization.state,
    );
  }

  res.redirect(redirect.toString());
  callbackLogger.info(`Issued code to "${userDataResult.key}" for client "${client_id}"`);
});

export {callbackEndpoint};
