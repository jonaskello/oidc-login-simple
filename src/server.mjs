import Fastify from "fastify";
import FastifySession from "@fastify/session";
import FastifyCookie from "@fastify/cookie";
import OpenIdClient from "openid-client";
import randomstring from "randomstring";

const fastify = Fastify({ logger: true });

// Session handling
fastify.register(FastifyCookie);
fastify.register(FastifySession, {
  secret: "a secret with minimum length of 32 characters",
  cookie: { secure: "auto", httpOnly: true },
});

fastify.get("/", (request, reply) => {
  reply
    .code(200)
    .type("text/html")
    .send(`You are not logged in. <a href="/login">Login</a>`);
});

const params = {
  client_id: process.env.CLIENT_ID,
  client_secret: process.env.CLIENT_SECRET,
  oidc_issuer_url: process.env.ISSUER_URL,
  redirect_url: "http://localhost:3000/callback",
};
const issuer = await OpenIdClient.Issuer.discover(params.oidc_issuer_url);
const oidcClient = new issuer.Client({
  client_id: params.client_id,
  client_secret: params.client_secret,
  usePKCE: true, // Use authorization code flow with PKCE as standardized by OAuth2.1
  redirect_uris: [params.redirect_url],
  response_types: ["code"],
  token_endpoint_auth_method: "client_secret_basic", // Send auth in header
});

fastify.get("/login", async (req, res) => {
  // State, nonce and PKCE provide protection against CSRF in various forms. See:
  // https://danielfett.de/2020/05/16/pkce-vs-nonce-equivalent-or-not/
  const state = Buffer.from(randomstring.generate(24)).toString("base64");
  const nonce = Buffer.from(randomstring.generate(24)).toString("base64");
  const pkce_verifier = OpenIdClient.generators.codeVerifier();
  const pkce_challenge = OpenIdClient.generators.codeChallenge(pkce_verifier);
  const auth_url = oidcClient.authorizationUrl({
    scope: "openid profile",
    code_challenge: pkce_challenge,
    code_challenge_method: "S256",
    state,
    nonce,
  });
  const postLoginUrl = req.query["url"] ?? "";
  req.session.redirectParams = { pkce_verifier, state, nonce, postLoginUrl };
  console.log("auth_url", auth_url);
  return res.redirect(auth_url);
});

fastify.get("/callback", async (req, res) => {
  const callbackParams = oidcClient.callbackParams(req.url);
  const redirectParams = req.session.redirectParams;
  if (callbackParams.code && callbackParams.state && redirectParams) {
    try {
      const tokenSet = await oidcClient.callback(
        params.redirect_url,
        callbackParams,
        {
          code_verifier: redirectParams.pkce_verifier,
          state: redirectParams.state,
          nonce: redirectParams.nonce,
        }
      );
      storeTokens(req.session, tokenSet);
      if (!redirectParams.postLoginUrl) {
        return await res.redirect("/");
      } else {
        return await res.redirect(redirectParams.postLoginUrl);
      }
    } catch (e) {
      console.log("Error finishing login:", e);
      req.session.destroy();
      return res
        .code(500)
        .type("text/html")
        .send(
          `An error occured while handling login callback. <a href="/login">Try again</a>.`
        );
    }
  } else {
    return res
      .code(500)
      .type("text/html")
      .send(
        `Could not find session during login callback. <a href="/login">Try again</a>.`
      );
  }
});

fastify.get("/userinfo", (req, res) => {
  if (tokensValid(req.session)) {
    console.log("ID token claims", req.session.tokens?.id_token_claims);
    res.code(200).send(req.session.tokens?.id_token_claims);
  } else {
    console.log("*** Tokens expired");
    res.code(200).send({});
  }
});

/*

fastify.get("/logout", async (req, res) => {
  const tokens = req.session.tokens;
  if (tokens && tokens.id_token) {
    const params = paramsOfReq(req);
    const client = await getOidcClient(params);
    const postLogoutUri = params.post_logout_redirect_uri;
    const url = client.endSessionUrl({
      id_token_hint: tokens.id_token,
      post_logout_redirect_uri: postLogoutUri,
    });
    req.session.destroy();
    return res.code(200).send({ logoutUrl: url });
  } else {
    log.jonas("*** No ID token claims");
    req.session.destroy();
    return res.code(200).send({});
  }
});
*/

function storeTokens(session, tokenSet) {
  const tokens = {
    id_token: tokenSet.id_token,
    id_token_claims: tokenSet.claims(),
    access_token: tokenSet.access_token,
    refresh_token: tokenSet.refresh_token,
    expires_at: tokenSet.expires_at,
  };
  session.tokens = tokens;
}

function tokensValid(session) {
  const tokens = session.tokens;
  if (!tokens || !tokens.expires_at || !tokens.id_token) {
    return false;
  }
  const expire_in = tokens.expires_at - Date.now() / 1000;
  console.log("Tokens expire in", expire_in);
  return expire_in > 0;
}

await fastify.listen({ port: 3000 });

console.log("Listening...");
