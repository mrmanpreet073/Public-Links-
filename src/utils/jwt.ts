// import crypto from "crypto";
// import jwt from "jsonwebtoken";
// import type { JwtPayload, SignOptions } from "jsonwebtoken";

// // =========================
// // Types
// // =========================

// interface TokenPayload extends JwtPayload {
//   id?: string;
//   email?: string;
// }


// // =========================
// // Generate Access Token
// // =========================

// const generateAccessToken = (
//   payload: TokenPayload
// ): string => {

//   return jwt.sign(
//     payload,
//     process.env.JWT_ACCESS_SECRET as string,
//     {
//       expiresIn:
//         (process.env.JWT_ACCESS_EXPIRES_IN || "15m") as SignOptions["expiresIn"]
//     }
//   );
// };

// // =========================
// // Verify Access Token
// // =========================

// const verifyAccessToken = (
//   token: string
// ): string | JwtPayload => {

//   return jwt.verify(
//     token,
//     process.env.JWT_ACCESS_SECRET as string
//   );
// };

// // =========================
// // Generate Refresh Token
// // =========================

// const generateRefreshToken = (
//   payload: TokenPayload
// ): string => {

//   return jwt.sign(
//     payload,
//     process.env.JWT_REFRESH_SECRET as string,
//     {
//       expiresIn:
//         (process.env.JWT_REFRESH_EXPIRES_IN || "7d") as SignOptions["expiresIn"]
//     }
//   );
// };

// // =========================
// // Verify Refresh Token
// // =========================

// const verifyRefreshToken = (
//   token: string
// ): string | JwtPayload => {

//   return jwt.verify(
//     token,
//     process.env.JWT_REFRESH_SECRET as string
//   );
// };

// // =========================
// // Exports
// // =========================

// export {
//   generateResetToken,
//   generateAccessToken,
//   generateRefreshToken,
//   verifyAccessToken,
//   verifyRefreshToken
// };