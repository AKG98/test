import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'refresh';

export function generateAccessToken(id: string): string {
  return jwt.sign({ id }, JWT_SECRET, { expiresIn: '24h' });
}

export function generateRefreshToken(id: string): string {
  return jwt.sign({ id }, JWT_REFRESH_SECRET, { expiresIn: '7d' });
}

export function verifyAccessToken(token: string): string | jwt.JwtPayload {
  return jwt.verify(token, JWT_SECRET);
}

export function verifyRefreshToken(token: string): string | jwt.JwtPayload {
  return jwt.verify(token, JWT_REFRESH_SECRET);
}
