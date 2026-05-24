// export type JWTClaims = {
//   iss: string;
//   sub: string;
//   email: string;
//   email_verified: string;
//   exp: number;
//   given_name: string;
//   family_name?: string | undefined;  // add | undefined
//   name: string;
//   picture?: string | undefined;      // add | undefined
// };

export interface JWTClaims {

  // Issuer
  iss: string;

  // Subject (user id)
  sub: string;

  // Audience (client id)
  aud: string;

  // User Email
  email: string;

  // Email Verification Status
  email_verified: string;

  // Issued At
  iat: number;

  // Expiration Time
  exp: number;

  // First Name
  given_name?: string;

  // Last Name
  family_name?: string | undefined;

  // Full Name
  name?: string;

  // Profile Picture
  picture?: string| undefined;
}
