import express from "express";
import type { Request, Response } from "express";
import cookieParser from "cookie-parser";
import bcrypt from "bcrypt";
import crypto from "crypto";
import JWT from "jsonwebtoken";
import jose from "node-jose";
import { eq } from "drizzle-orm";
import { db } from "./db/index.js";
import { usersTable } from "./db/schema.js";
import { PRIVATE_KEY, PUBLIC_KEY } from "./utils/cert.js";
import type { JWTClaims } from "./utils/jwtTypes.js";
import { oauthClientsTable } from "./db/schema2.js";
import { log } from "console";



const app = express();

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

const PORT = process.env.PORT ?? 5000;

const ISSUER = `http://localhost:${PORT}`;

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

  return res.json({
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/o/authorize`,
    token_endpoint: `${ISSUER}/o/token`,
    userinfo_endpoint: `${ISSUER}/o/userinfo`,
    jwks_uri: `${ISSUER}/.well-known/jwks.json`,
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    scopes_supported: ["openid", "profile", "email"],
    token_endpoint_auth_methods_supported: ["client_secret_post"]
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
    password
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

  await db.insert(usersTable).values({
    firstName,
    lastName,
    email,
    password: hashedPassword
  });

  return res.send("User registered");
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

  if (
    client.redirectUri !==
    redirect_uri
  ) {

    return res.status(400).send(
      "Invalid redirect URI"
    );
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

  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.email, email))
    .limit(1);

  if (!user) {
    return res.status(401).send(
      "User not found"
    );
  }

  const isMatch = await bcrypt.compare(
    password,
    user.password!
  );

  if (!isMatch) {
    return res.status(401).send(
      "Invalid credentials"
    );
  }

  // Generate Authorization Code

  const code = crypto.randomBytes(32).toString("hex");

  console.log("Generated Authorization Code:", code);


  authorizationCodes.set(code, {
    code,
    userId: user.id,
    clientId: client_id,
    redirectUri: redirect_uri,
    expiresAt:
      Date.now() + 1000 * 60 * 5
  });


  // Redirect back to client

  const redirectURL = `${redirect_uri}?code=${code}&state=${state}`;

  // console.log(redirectURL);

  return res.redirect(redirectURL);
}
);

// ======================================================
// OAuth2 Token Endpoint
// ======================================================

app.post("/o/token", async (req: Request, res: Response) => {

  const {
    code,
    client_id,
    redirect_uri,
    grant_type
  } = req.body;

  console.log("Token Request:", {
    code,
    client_id,
    redirect_uri,
    grant_type
  });
  console.log("Current Authorization Codes:", Array.from(authorizationCodes.values()));
  if (grant_type !== "authorization_code") {
    return res.status(400).json({
      error: "unsupported_grant_type"
    });
  }

  const storedCode = authorizationCodes.get(code);// code apna hi he ??

  if (!storedCode) {
    return res.status(400).json({
      error: "invalid_code"
    });
  }

  // Expired

  if (storedCode.expiresAt < Date.now()) {

    authorizationCodes.delete(code);

    return res.status(400).json({
      error: "authorization_code_expired"
    });

  }

  // Validate Client

  if (
    storedCode.clientId !== client_id ||
    storedCode.redirectUri !== redirect_uri
  ) {
    return res.status(400).json({
      error: "invalid_client"
    });
  }

  // One Time Use

  authorizationCodes.delete(code);

  // Fetch User

  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.id, storedCode.userId))
    .limit(1);

  if (!user) {
    return res.status(404).send(
      "User not found"
    );
  }

  // JWT Claims

  const now = Math.floor(
    Date.now() / 1000
  );

  const claims: JWTClaims = {
    iss: ISSUER,
    sub: user.id,
    aud: client_id,
    email: user.email,
    email_verified: String(user.emailVerified),
    iat: now,
    exp: now + 3600,
    given_name: user.firstName ?? "",
    family_name: user.lastName ?? undefined,
    name: [user.firstName, user.lastName].filter(Boolean).join(" "),
    picture: user.profileImageURL ?? undefined
  };

  // Access Token

  const accessToken = JWT.sign(claims, PRIVATE_KEY, { algorithm: "RS256" });

  // ID Token

  const idToken = JWT.sign(claims, PRIVATE_KEY, { algorithm: "RS256" });

  const refreshToken =
    crypto
      .randomBytes(64)
      .toString("hex");

  // Store In Cookie

  res.cookie("refresh_token", refreshToken,
    {
      httpOnly: true,
      secure: false,
      sameSite: "lax", //Protects against many CSRF attacks.
      maxAge: 1000 * 60 * 60 * 24 * 7 // 7 days
    }
  );


  return res.json({
    access_token: accessToken,
    token_type: "Bearer",
    id_token: idToken,
    expires_in: 3600,
  });
}
);

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

app.get("/.well-known/jwks.json", async (_: Request, res: Response) => {

  const key = await jose.JWK.asKey(PUBLIC_KEY, "pem");

  return res.json({ keys: [key.toJSON()] });
}


  //   or====================================================

  //   app.get("/.well-known/jwks.json", (_, res) => {
  //   const key = crypto.createPublicKey(PUBLIC_KEY);
  //   const jwk = key.export({ format: "jwk" });
  //   return res.json({ keys: [jwk] });
  // });



);

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

    const clientId =
      crypto.randomBytes(16).toString("hex");

    const clientSecret =
      crypto.randomBytes(32).toString("hex");

    // ====================================
    // Save Client In Database
    // ====================================

    await db.insert(oauthClientsTable)
      .values({
        appName,
        clientId,
        clientSecret,
        redirectUri,
        scope: scope || "openid profile email",
        responseType:
          responseType || "code"
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
      response_type:
        responseType || "code"
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

app.post("/o/refresh", async (req: Request, res: Response) => {

  // ============================
  // Read Refresh Token Cookie
  // ============================

  const refreshToken = req.cookies.refresh_token;

  if (!refreshToken) {

    return res.status(401).json({
      error:
        "Refresh token missing"
    });
  }

  // ============================
  // OPTIONAL:
  // Verify Refresh Token From DB
  // ============================

  // For now demo validation only

  // In production:
  // check DB/Redis

  // ============================
  // Generate New Access Token
  // ============================

  const ISSUER = `http://localhost:${PORT}`;

  const now = Math.floor(Date.now() / 1000);

  // Example demo user
  // Replace with DB lookup

  const [user] = await db
    .select()
    .from(usersTable)
    .limit(1);

  if (!user) {

    return res.status(404).json({
      error:
        "User not found"
    });
  }

  const claims: JWTClaims = {

    iss: ISSUER,
    sub: user.id,
    aud: "client-app",
    email: user.email,
    email_verified: String(user.emailVerified),
    iat: now,
    exp: now + 3600,
    given_name: user.firstName ?? "",
    family_name: user.lastName ?? undefined,
    name: [user.firstName, user.lastName].filter(Boolean).join(" "),
    picture: user.profileImageURL ?? undefined
  };

  // ============================
  // Create New Access Token
  // ============================

  const accessToken = JWT.sign(claims, PRIVATE_KEY, { algorithm: "RS256" });

  // ============================
  // Return New Access Token
  // ============================

  return res.json({

    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600
  });
}
);

// ======================================================
// Start Server
// ======================================================

app.listen(PORT, () => {
  console.log(
    `OIDC Provider running on ${ISSUER}`
  );
});