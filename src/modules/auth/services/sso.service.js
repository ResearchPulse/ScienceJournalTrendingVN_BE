import { createJitUser, findUsersByNormalizedEmail, normalizeEmail } from '../repositories/sso.repository.js';

const authError = (statusCode, code, message) => {
  const error = new Error(message);
  error.statusCode = statusCode;
  error.code = code;
  return error;
};

export const resolveLocalSsoUser = async (email) => {
  if (typeof email !== 'string' || !email.trim()) {
    throw authError(401, 'PARENT_SESSION_INVALID', 'Parent session does not contain an email');
  }

  const normalizedEmail = normalizeEmail(email);
  let matches = await findUsersByNormalizedEmail(normalizedEmail);
  if (matches.length > 1) {
    throw authError(409, 'EMAIL_IDENTITY_AMBIGUOUS', 'Multiple local accounts match this email');
  }

  if (!matches[0]) {
    try {
      matches = [await createJitUser(normalizedEmail)];
    } catch (error) {
      if (error.code !== 'P2002') throw error;
      matches = await findUsersByNormalizedEmail(normalizedEmail);
      if (matches.length !== 1) throw error;
    }
  }

  const user = matches[0];
  if (user.status !== 'ACTIVE' || user.role === 'BANNED') {
    throw authError(403, 'ACCOUNT_UNAVAILABLE', 'Account is banned or inactive');
  }
  return user;
};
