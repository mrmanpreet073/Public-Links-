import express from "express";
import type { Request, Response } from "express";
import cookieParser from "cookie-parser";
import bcrypt from "bcrypt";
import crypto from "crypto";
import JWT from "jsonwebtoken";
import jose from "node-jose";
import { and, eq } from "drizzle-orm";
import { db } from "./db/index.js";
import { usersTable } from "./db/UserTable.js";
import { PRIVATE_KEY, PUBLIC_KEY } from "./utils/cert.js";
import type { JWTClaims } from "./utils/jwtTypes.js";
import { oauthClientsTable } from "./db/ClientTable.js";
import { log } from "console";
import { refreshTokensTable } from "./db/RefTokenTable.js";
import { sessionsTable } from "./db/SessionTable.js";
import cors from "cors";
import dotenv from "dotenv"


dotenv.config();

const app = express();

app.set("trust proxy", 1);
// 2. Enable CORS for your frontend origin
app.use(cors({
  origin: true,       // allow any origin
  credentials: true
}));


app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
const PORT = process.env.PORT ?? 5000;

// const ISSUER = `http://localhost:${PORT}`;
const ISSUER = process.env.ISSUER;

// ======================================================
// Types
// ======================================================

type AuthCode = {
  code: string;
  userId: string;
  clientId: string;
  redirectUri: string;
  expiresAt: number;
};
type PendingAuthorization = {
  userId: string;
  clientId: string;
  redirectUri: string;
  state?: string;
  expiresAt: number;

};

const pendingAuthorizations = new Map<string, PendingAuthorization>();

// ======================================================
// Temporary In-Memory Authorization Code Store
// ======================================================

const authorizationCodes = new Map<string, AuthCode>();

// ======================================================
// Home
// ======================================================

app.get("/", (_: Request, res: Response) => {
  res.send("OAuth2 + OIDC Provider Running");
});

// ======================================================
// OpenID Configuration
// ======================================================

app.get("/.well-known/openid-configuration", (_: Request, res: Response) => {

  return res.sendFile("configuration.html", {
    root: "./public"
  });


}
);

// ======================================================
// Pages
// ======================================================

app.get("/home", (_: Request, res: Response) => {
  res.sendFile("home.html", {
    root: "./public"
  });
});

app.get("/docs", (_: Request, res: Response) => {
  res.sendFile("oidc-auth.html", {
    root: "./public"
  });
});

app.get("/signup", (_: Request, res: Response) => {
  res.sendFile("signup.html", {
    root: "./public"
  });
});

// ======================================================
// Signup
// ======================================================

app.post("/signup", async (req: Request, res: Response) => {

  const {
    firstName,
    lastName,
    email,
    password,
    client_id,
    redirect_uri,
    state
  } = req.body;

  if (
    !firstName ||
    !lastName ||
    !email ||
    !password
  ) {
    return res.status(400).json({
      message: "All fields are required"
    });
  }

  const [existingUser] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.email, email))
    .limit(1);

  if (existingUser) {
    return res.status(400).send(
      "User already exists"
    );
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const [user] = await db.insert(usersTable).values({
    firstName,
    lastName,
    email,
    password: hashedPassword
  }).returning();

  const newSessionId = crypto.randomBytes(32).toString("hex");

  await db
    .insert(sessionsTable)
    .values({
      sessionId: newSessionId,
      userId: user!.id,
      expiresAt: new Date(Date.now() + Number(process.env.SESSION_TTL) * 1000)
    });

  res.cookie("session", newSessionId,
    {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: Number(process.env.SESSION_TTL) * 1000 //1day     // 2 minutes
    }
  );


  const consentId = crypto.randomBytes(32).toString("hex");

  pendingAuthorizations.set(consentId, {
    userId: user?.id as string,
    clientId: client_id,
    redirectUri: redirect_uri,
    state,
    expiresAt: Date.now() + 1000 * 60 * 5 // Code valid for 5 minutes

  });

  return res.redirect(`/o/consent?consent_id=${consentId}`);

}


);

// ======================================================
// OAuth2 Authorization Endpoint
// ======================================================

app.get("/o/authorize", async (req: Request, res: Response) => {

  const {
    client_id,
    redirect_uri,
    response_type
  } = req.query;

  // ============================
  // Basic Validation
  // ============================

  if (!client_id || !redirect_uri || response_type !== "code") {

    return res.status(400).send(
      "Invalid OAuth request"
    );
  }

  // ============================
  // Find Client
  // ============================

  const [client] = await db
    .select()
    .from(oauthClientsTable)
    .where(
      eq(
        oauthClientsTable.clientId,
        String(client_id)
      )
    )
    .limit(1);

  if (!client) {

    return res.status(400).send(
      "Invalid client"
    );
  }

  // ============================
  // Validate Redirect URI
  // ============================

  if (client.redirectUri !== redirect_uri) {

    return res.status(400).send(
      "Invalid redirect URI"
    );
  }

  const sessionId = req.cookies.session;

  if (sessionId) {
    const [session] = await db.select().from(sessionsTable)
      .where(eq(sessionsTable.sessionId, sessionId)).limit(1);

    if (session && session.expiresAt > new Date()) {

      // Session valid → skip login, go to consent
      const consentId = crypto.randomBytes(32).toString("hex");

      pendingAuthorizations.set(consentId, {
        userId: session.userId,
        clientId: String(client_id),
        redirectUri: String(redirect_uri),
        expiresAt: Date.now() + 1000 * 60 * 5 // Code valid for 5 minutes

      });
      return res.redirect(`/o/consent?consent_id=${consentId}`);
    }
  }

  // ============================
  // Show Login Page
  // ============================

  return res.sendFile("login.html", { root: "./public" });
}
);

// ======================================================
// OAuth2 Login + Authorization Code Generation
// ======================================================

app.post("/o/authorize", async (req: Request, res: Response) => {

  const {
    email,
    password,
    client_id,
    redirect_uri,
    state
  } = req.body;

  let user;

  const sessionId = req.cookies.session;

  // ============================
  // Existing Session
  // ============================
  if (sessionId) {

    const [session] = await db
      .select()
      .from(sessionsTable)
      .where(
        eq(
          sessionsTable.sessionId,
          sessionId
        )
      )
      .limit(1);

    if (session && session.expiresAt > new Date()) {

      const [sessionUser] = await db
        .select()
        .from(usersTable)
        .where(
          eq(
            usersTable.id,
            session.userId
          )
        )
        .limit(1);

      if (sessionUser) {
        user = sessionUser;
      }
    }
  }

  // ============================
  // No Session -> Login Required
  // ============================

  if (!user) {

    if (
      !email ||
      !password ||
      !client_id ||
      !redirect_uri
    ) {
      return res.status(400).send(
        "Missing required fields"
      );
    }

    const [dbUser] = await db
      .select()
      .from(usersTable)
      .where(
        eq(
          usersTable.email,
          email
        )
      )
      .limit(1);

    if (!dbUser) {
      return res.status(401).send(
        "User not found"
      );
    }

    const isMatch = await bcrypt.compare(
      password,
      dbUser.password!
    );

    if (!isMatch) {
      return res.status(401).send(
        "Invalid credentials"
      );
    }

    user = dbUser;

    // ============================
    // Create Session
    // ============================

    const newSessionId = crypto.randomBytes(32).toString("hex");

    await db
      .insert(sessionsTable)
      .values({
        sessionId: newSessionId,
        userId: user.id,
        expiresAt: new Date(Date.now() + Number(process.env.SESSION_TTL) * 1000) // Session valid for 5 minutes
      });

    res.cookie("session", newSessionId,
      {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: Number(process.env.SESSION_TTL) * 1000//----------------------
      }
    );
  }

  //validate client_id and redirect_uri again in case someone tries to forge a request to this endpoint without logging in first
  if (!client_id || !redirect_uri) {
    return res.status(400).send("Missing client_id or redirect_uri");
  }

  const [client] = await db.select().from(oauthClientsTable)
    .where(eq(oauthClientsTable.clientId, client_id)).limit(1);

  if (!client) return res.status(400).send("Invalid client");

  if (client.redirectUri !== redirect_uri) {
    return res.status(400).send("Invalid redirect URI");
  }
  // ============================
  // Create Consent Request
  // ============================

  const consentId = crypto.randomBytes(32).toString("hex");

  pendingAuthorizations.set(consentId,
    {
      userId: user.id,
      clientId: client_id,
      redirectUri: redirect_uri,
      state,
      expiresAt: Date.now() + 1000 * 60 * 5 // Code valid for 5 minutes

    }
  );

  return res.redirect(`/o/consent?consent_id=${consentId}`
  );
});



app.get("/o/consent", async (req, res) => {

  const consentId = req.query.consent_id as string;

  const pending = pendingAuthorizations.get(consentId);

  if (!pending) {
    return res.status(400).send(
      "Invalid consent request"
    );
  }

  const [client] = await db
    .select()
    .from(oauthClientsTable)
    .where(
      eq(
        oauthClientsTable.clientId,
        pending.clientId
      )
    )
    .limit(1);

  if (!client) {
    return res.status(400).send(
      "Client not found"
    );
  }

  return res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Consent</title>

<style>

*{
  margin:0;
  padding:0;
  box-sizing:border-box;
  font-family:Inter,Segoe UI,sans-serif;
}

body{
  min-height:100vh;
  display:flex;
  justify-content:center;
  align-items:center;
  background:#0f172a;
  color:#f8fafc;
}

.card{
  width:100%;
  max-width:500px;
  background:#1e293b;
  border:1px solid #334155;
  border-radius:18px;
  padding:32px;
  box-shadow:0 20px 40px rgba(0,0,0,.35);
}

.logo{
  width:70px;
  height:70px;
  margin:0 auto 20px;
  border-radius:50%;
  background:#2563eb;
  display:flex;
  justify-content:center;
  align-items:center;
  font-size:30px;
  font-weight:bold;
}

h2{
  text-align:center;
  margin-bottom:10px;
}

.subtitle{
  text-align:center;
  color:#94a3b8;
  line-height:1.6;
  margin-bottom:25px;
}

.app{
  color:#60a5fa;
  font-weight:600;
}

.permissions{
  margin-top:20px;
}

.permissions h3{
  margin-bottom:15px;
}

.permission{
  display:flex;
  align-items:center;
  gap:12px;
  padding:14px;
  background:#0f172a;
  border:1px solid #334155;
  border-radius:12px;
  margin-bottom:12px;
}

.permission-icon{
  font-size:20px;
}

.permission-text{
  color:#cbd5e1;
}

.warning{
  margin-top:20px;
  padding:14px;
  border-radius:12px;
  background:#172554;
  border:1px solid #1d4ed8;
  color:#bfdbfe;
  font-size:14px;
}

.actions{
  display:flex;
  gap:12px;
  margin-top:25px;
}

button{
  flex:1;
  border:none;
  border-radius:12px;
  padding:12px;
  font-size:15px;
  font-weight:600;
  cursor:pointer;
  transition:.2s;
}

.allow{
  background:#2563eb;
  color:white;
}

.allow:hover{
  background:#1d4ed8;
}

.deny{
  background:#334155;
  color:white;
}

.deny:hover{
  background:#475569;
}

.footer{
  text-align:center;
  color:#64748b;
  margin-top:20px;
  font-size:13px;
}

</style>
</head>

<body>

<div class="card">

  <div class="logo">O</div>

  <h2>Authorize Application</h2>

  <p class="subtitle">
    <span class="app">${client.appName}</span>
    is requesting permission to access your account.
  </p>

  <div class="permissions">

    <h3>Requested Access</h3>

    <div class="permission">
      <div class="permission-icon">👤</div>
      <div class="permission-text">
        View your profile information
      </div>
    </div>

    <div class="permission">
      <div class="permission-icon">📧</div>
      <div class="permission-text">
        Access your email address
      </div>
    </div>

    <div class="permission">
      <div class="permission-icon">🔐</div>
      <div class="permission-text">
        Sign you in using OpenID Connect
      </div>
    </div>

  </div>

  <div class="warning">
    Only continue if you trust this application.
  </div>

  <form action="/o/consent" method="POST">

    <input
      type="hidden"
      name="consent_id"
      value="${consentId}"
    >

    <div class="actions">

      <button
        type="submit"
        name="decision"
        value="deny"
        class="deny"
      >
        Deny
      </button>

      <button
        type="submit"
        name="decision"
        value="allow"
        class="allow"
      >
        Allow Access
      </button>

    </div>

  </form>

  <div class="footer">
    OAuth 2.0 Authorization Request
  </div>

</div>

</body>
</html>
`);
});
app.post("/o/consent", async (req, res) => {

  const { consent_id, decision } = req.body;

  const pending = pendingAuthorizations.get(consent_id);

  if (!pending) {
    return res.status(400).send(
      "Invalid consent"
    );
  }
  if (pending.expiresAt < Date.now()) { // Prevents someone from using an old code hours later.

    pendingAuthorizations.delete(consent_id);

    return res.status(400).json({
      error: "authorization_request_expired"
    });
  }

  pendingAuthorizations.delete(consent_id);

  if (decision === "deny") {

    return res.redirect(`${pending.redirectUri}?error=access_denied`
    );
  }

  const code = crypto.randomBytes(32).toString("hex");

  //

  authorizationCodes.set(code, {
    code,
    userId: pending.userId,
    clientId: pending.clientId,
    redirectUri: pending.redirectUri,
    expiresAt: Date.now() + 1000 * 60 * 5 // Code valid for 5 minutes
  });




  // redirect to callback with code and state
  //where code is exchange for access token and id token and state is used to prevent csrf attack

  // return res.redirect(`${pending.redirectUri}?code=${code}&state=${pending.state}`);
  return res.redirect(`${pending.redirectUri}?code=${code}`);
});

// ======================================================
// OAuth2 Token Endpoint + Refresh Endpoint
// ======================================================

app.post("/o/token", async (req: Request, res: Response) => {

  const {
    code,
    client_id,
    client_secret,
    redirect_uri,
    grant_type,
    // refresh_token
  } = req.body;


  if (!client_id || !client_secret) {
    return res.status(400).json({ error: "invalid_client0" });
  }
  if (
    grant_type !== "authorization_code" &&
    grant_type !== "refresh_token"
  ) {
    return res.status(400).json({
      error: "unsupported_grant_type"
    });
  }

  // =====================================
  // AUTHORIZATION CODE FLOW
  // =====================================

  if (grant_type === "authorization_code") {

    const storedCode = authorizationCodes.get(code);

    if (!storedCode) {
      return res.status(400).json({
        error: "invalid_code"
      });
    }

    if (storedCode.expiresAt < Date.now()) { // Prevents someone from using an old code hours later.

      authorizationCodes.delete(code);

      return res.status(400).json({
        error: "authorization_code_expired"
      });
    }

    const [client] = await db
      .select()
      .from(oauthClientsTable)
      .where(
        eq(
          oauthClientsTable.clientId,
          client_id
        )
      )
      .limit(1);

    if (!client) {
      return res.status(400).json({
        error: "invalid_client"
      });
    }

    const hashedClientSecret = crypto
      .createHash("sha256")
      .update(client_secret)
      .digest("hex");

    if (client.clientSecret !== hashedClientSecret) {
      return res.status(400).json({ error: "invalid_client" });
    }

    if (
      storedCode.clientId !== client_id || //Does it belong to this client?
      storedCode.redirectUri !== redirect_uri //Prevents a stolen code from being redeemed through a different callback URL.
    ) {
      return res.status(400).json({
        error: "invalid_client"
      });
    }

    authorizationCodes.delete(code);

    const [user] = await db
      .select()
      .from(usersTable)
      .where(
        eq(
          usersTable.id,
          storedCode.userId  //Which user logged in?
        )
      )
      .limit(1);

    if (!user) {
      return res.status(404).json({
        error: "user_not_found"
      });
    }

    const now = Math.floor(Date.now() / 1000);

    const claims: JWTClaims = {
      iss: ISSUER,
      sub: user.id,
      aud: client_id,
      email: user.email,
      email_verified: user.emailVerified,
      iat: now,
      exp: now + Number(process.env.ACCESS_TOKEN_TTL), //---------------
      given_name: user.firstName ?? "",
      family_name: user.lastName ?? undefined,
      name: [user.firstName, user.lastName]
        .filter(Boolean)
        .join(" "),
      picture: user.profileImageURL ?? undefined
    };

    const accessToken = JWT.sign(claims, PRIVATE_KEY, { algorithm: "RS256" });

    const idToken = JWT.sign(claims, PRIVATE_KEY, { algorithm: "RS256" });

    const refreshToken = crypto.randomBytes(64).toString("hex");

    // console.log("Generated Refresh Token:", refreshToken);

    const tokenHash = crypto
      .createHash("sha256")
      .update(refreshToken)
      .digest("hex");

    // console.log("Hashed Refresh Token:", tokenHash);

    //////////////////////////////////////////////////////////////////////////////////////////////
    await db
      .insert(refreshTokensTable)
      .values({
        userId: user.id,
        clientId: client_id,
        tokenHash,
        expiresAt: new Date(Date.now() + Number(process.env.REFRESH_TOKEN_TTL) * 1000) // 10 mins 
      });
    // console.log(
    //   "Stored refresh token in database with hash:",
    //   tokenHash
    // );
    /////////////////////////////////////////////////////////////////////////////////////////////////
    // REFRESH TOKEN 
    res.clearCookie("refresh_token", {
      path: "/"
    });

    res.cookie("refresh_token", refreshToken,
      {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/",
        maxAge: Number(process.env.REFRESH_TOKEN_TTL) * 1000 //
      }
    );
    /////////////////////////////////////////////////////////////////////////////////////

    // console.log(
    //   "REFRESH TOKEN  cookie in authorization :",
    //   req.cookies.refresh_token
    // );

    return res.json({
      access_token: accessToken,
      token_type: "Bearer",
      id_token: idToken,
      refresh_token: refreshToken,
      expires_in: Number(process.env.ACCESS_TOKEN_TTL) 
    });
  }

  // =====================================
  // REFRESH TOKEN FLOW
  // =====================================

  if (grant_type === "refresh_token") {


    const refresh_token = req.cookies.refresh_token;

    // console.log("Cookie Token:", refresh_token);

    if (!refresh_token) {
      return res.status(400).json({
        error: "invalid_request"
      });
    }



    const [client] = await db
      .select()
      .from(oauthClientsTable)
      .where(
        eq(
          oauthClientsTable.clientId,
          client_id
        )
      )
      .limit(1);


    if (!client) {
      return res.status(400).json({
        error: "invalid_client1"
      });
    }




    const hashedClientSecret = crypto
      .createHash("sha256")
      .update(client_secret)
      .digest("hex");

    if (
      client.clientSecret !== hashedClientSecret
    ) {
      return res.status(400).json({
        error: "invalid_client2"
      });
    }

    const tokenHash = crypto // Hash the incoming refresh token to compare with stored hash
      .createHash("sha256")
      .update(refresh_token)
      .digest("hex");

    // console.log("Token Hash:", tokenHash);

    const [storedToken] = await db // 
      .select()
      .from(refreshTokensTable)
      .where(
        and(
          eq(refreshTokensTable.tokenHash, tokenHash), // Find token by hash
          eq(refreshTokensTable.clientId, client_id) // Ensure token belongs to the client
        )
      )
      .limit(1);

    // console.log("Stored Token:", storedToken);

    if (!storedToken) {
      return res.status(401).json({
        error: "invalid_grant"
      });
    }

    if (storedToken.expiresAt && storedToken.expiresAt < new Date()) {

      await db
        .delete(refreshTokensTable)
        .where(
          eq(
            refreshTokensTable.id,
            storedToken.id
          )
        );

      return res.status(401).json({
        error:
          "refresh_token_expired"
      });
    }

    const [user] = await db //  Find the user associated with this refresh token
      .select()
      .from(usersTable)
      .where(eq(usersTable.id, storedToken.userId))
      .limit(1);

    if (!user) {
      return res.status(404).json({
        error: "user_not_found"
      });
    }

    const now = Math.floor(Date.now() / 1000);

    const claims: JWTClaims = {

      iss: ISSUER,
      sub: user.id,
      aud: client_id,
      email: user.email,
      email_verified: user.emailVerified,
      iat: now,
      exp: now + Number(process.env.ACCESS_TOKEN_TTL), //
      given_name: user.firstName ?? "",
      family_name: user.lastName ?? undefined,
      name: [user.firstName, user.lastName].filter(Boolean).join(" "),
      picture: user.profileImageURL ?? undefined
    };

    const accessToken = JWT.sign(claims, PRIVATE_KEY, { algorithm: "RS256" });


    return res.json({
      access_token: accessToken,
      // refresh_token: newRefreshToken,
      token_type: "Bearer",
      expires_in: Number(process.env.ACCESS_TOKEN_TTL)
    });
  }

});

// ======================================================
// UserInfo Endpoint
// ======================================================

app.get("/o/userinfo", (req: Request, res: Response) => {

  const authHeader =
    req.headers.authorization;

  if (!authHeader) {
    return res.status(401).send(
      "Authorization header missing"
    );
  }

  if (
    !authHeader.startsWith("Bearer ")
  ) {
    return res.status(401).send(
      "Invalid authorization format"
    );
  }

  const token = authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).send(
      "Token missing"
    );
  }

  try {

    const decoded = JWT.verify(token, PUBLIC_KEY, { algorithms: ["RS256"] });

    return res.json(decoded);

  } catch (error) {

    return res.status(401).send(
      "Invalid token"
    );
  }
}
);

// ======================================================
// JWKS Endpoint
// ======================================================

// app.get("/.well-known/jwks.json", async (_: Request, res: Response) => {

//   res.sendFile("jwks.html", {
//     root: "./public"
//   });
// },




//   //   or====================================================

//   //   app.get("/.well-known/jwks.json", (_, res) => {
//   //   const key = crypto.createPublicKey(PUBLIC_KEY);
//   //   const jwk = key.export({ format: "jwk" });
//   //   return res.json({ keys: [jwk] });
//   // });


//   // This code snippet is used to convert a public key from the PEM format 
//   // (a widely used text format for cryptographic keys) into a JWK (JSON Web Key)
//   //  format, and then return it as a JSON response.


// );

app.get("/.well-known/jwks.json", async (req: Request, res: Response) => {

  // 1. If a browser visits the page, send the HTML dashboard
  if (req.headers.accept && req.headers.accept.includes('text/html')) {
    return res.sendFile("jwks.html", { root: "./public" });
  }

  // 2. If an OIDC library (or your frontend fetch) asks for JSON via GET, send the raw keys!
  try {
    const key = await jose.JWK.asKey(PUBLIC_KEY, "pem");
    res.setHeader('Content-Type', 'application/json');
    return res.json({ keys: [key.toJSON()] });
  } catch (error) {
    return res.status(500).json({ error: "Failed to compile keys" });
  }
});

// Optional: Keep your POST route active so your existing fetch code doesn't break
app.post("/.well-known/jwks.json", async (_: Request, res: Response) => {
  const key = await jose.JWK.asKey(PUBLIC_KEY, "pem");
  return res.json({ keys: [key.toJSON()] });
});

app.get("/o/register-client", async (req: Request, res: Response) => {
  return res.sendFile("register.html", {
    root: "./public"
  });
})
app.post("/o/register-client", async (req: Request, res: Response) => {

  try {

    const {
      appName,
      redirectUri,
      scope,
      responseType
    } = req.body;

    // ====================================
    // Validation
    // ====================================

    if (!appName || !redirectUri) {

      return res.status(400).json({
        message:
          "App name and redirect URI are required"
      });
    }

    // ====================================
    // Generate Client Credentials
    // ====================================

    const clientId = crypto.randomBytes(16).toString("hex");

    const clientSecret = crypto.randomBytes(32).toString("hex");

    const hashedSecret = crypto
      .createHash("sha256")
      .update(clientSecret)
      .digest("hex");
    // ====================================
    // Save Client In Database
    // ====================================

    await db.insert(oauthClientsTable)
      .values({
        appName,
        clientId,
        clientSecret: hashedSecret,
        redirectUri,
        scope: scope || "openid profile email",
        responseType: responseType || "code"
      });

    // ====================================
    // Return Credentials
    // ====================================

    return res.status(201).json({

      message: "OAuth client registered successfully",
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      scope: scope || "openid profile email",
      response_type: responseType || "code"
    });

  } catch (error) {

    console.log(error);

    return res.status(500).json({
      message:
        "Internal server error"
    });
  }
}
);


app.post("/logout", async (req, res) => {

  const refreshToken =
    req.cookies.refresh_token;

  if (refreshToken) {

    const tokenHash = crypto
      .createHash("sha256")
      .update(refreshToken)
      .digest("hex");

    await db
      .delete(refreshTokensTable)
      .where(
        eq(
          refreshTokensTable.tokenHash,
          tokenHash
        )
      );
  }

  res.clearCookie(
    "refresh_token",
    {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // true in production
      sameSite: "lax"
    }
  );

  return res.json({
    message:
      "Logged out successfully"
  });

});

// ======================================================
// Start Server
// ======================================================

app.listen(PORT, () => {
  console.log(
    `OIDC Provider running on ${ISSUER}`
  );
});