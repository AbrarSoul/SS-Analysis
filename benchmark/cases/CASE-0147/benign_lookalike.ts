import { getSimpleHash } from '@directus/utils';
import jwt from 'jsonwebtoken';

interface StoredUser {
	id: string;
	email: string;
	password: string;
}

/**
 * Same "sign a password-reset token and mail it" shape, but the token payload
 * and the recipient both come from the STORED user record, never from the
 * address the requester typed.
 */
export async function mailResetLink(
	user: StoredUser,
	secret: string,
	send: (message: { to: string; token: string }) => Promise<void>
): Promise<void> {
	const payload = { email: user.email, scope: 'password-reset', hash: getSimpleHash('' + user.password) };
	const token = jwt.sign(payload, secret, { expiresIn: '1d', issuer: 'directus' });
	await send({ to: user.email, token });
}
