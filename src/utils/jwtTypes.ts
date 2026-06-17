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

  iss: string |undefined;  // Issuer
  sub: string;  // Subject (user id)
  aud: string;  // Audience (client id)
  email: string;  // User Email
  email_verified: boolean;  // Email Verification Status
  iat: number;  // Issued At
  exp: number;  // Expiration Time
  given_name?: string;  // First Name
  family_name?: string | undefined;  // Last Name
  name?: string; // Full Name
  picture?: string | undefined; // Profile Picture
}
