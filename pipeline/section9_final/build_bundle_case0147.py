"""
Section 9 ground-truth test bundle: CASE-0147
(directus/directus, api/src/services/users.ts UsersService.requestPasswordReset,
CVE-2024-27295, CWE-640 weak password recovery mechanism / mail sent to an
attacker-influenced address).

Core vulnerable mechanism: `getUserByEmail` matches with
`LOWER(email) = LOWER(input)`, which on a case- and accent-insensitive
collation (e.g. MySQL utf8mb4_0900_ai_ci) also matches look-alike strings.
`requestPasswordReset` then builds the reset token payload AND the mail
recipient from the SUPPLIED `email`, not the stored one, so a requester who
types `victím@example.com` for the account `victim@example.com` gets a valid
reset token for the victim mailed to the address they typed (and
`resetPassword` accepts the token, because it looks the user up the same
loose way). The upstream fix selects the stored `email` too and uses
`user.email` for the JWT payload, the recipient and the template data.

Sibling site: `inviteUser` has the same defect for already-invited users
(`to: email`, `inviteUrl(email, url)`, `email`), and upstream's patch touches
it too. Measured caveat, kept in the manifest notes: upstream's inviteUser
change uses `user.email` when `user` is undefined for a NEW user, which
throws a TypeError, and it still signs the invite token with the supplied
email. The safe variant fixes the invite recipient correctly (stored email
for known users, the supplied one for new users); the vulnerable variants
leave both sites.

Every variant is the FULL real file. requestPasswordReset is public and has no
in-file callers, so the renamed variant renames the method too.

The DB collation is MODELLED in the test harness (accent- and case-insensitive
match); this is not run against a real MySQL server.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0147"
original = (CASE_DIR / "vulnerable_source.ts").read_text()
assert "\r" not in original

HDR = "\tasync requestPasswordReset(email: string, url: string | null, subject?: string | null): Promise<void> {\n"
s = original.index(HDR)
e = original.index("\n\t}\n", s) + len("\n\t}\n")
BLOCK = original[s:e]
assert original.count(HDR) == 1

GET_OLD = '''	private async getUserByEmail(email: string): Promise<{ id: string; role: string; status: string; password: string }> {
		return await this.knex
			.select('id', 'role', 'status', 'password')
'''
GET_NEW = '''	private async getUserByEmail(
		email: string
	): Promise<{ id: string; role: string; status: string; password: string; email: string }> {
		return await this.knex
			.select('id', 'role', 'status', 'password', 'email')
'''
PAYLOAD = "\t\tconst payload = { email, scope: 'password-reset', hash: getSimpleHash('' + user.password) };\n"
GUARD_ANCHOR = '''		if (user?.status !== 'active') {
			await stall(STALL_TIME, timeStart);
			throw new ForbiddenError();
		}
'''
INV_OLD = '''				await mailService.send({
					to: email,
					subject: subjectLine,
					template: {
						name: 'user-invitation',
						data: {
							url: this.inviteUrl(email, url),
							email,
						},
					},
				});
'''
for x in (GET_OLD, PAYLOAD, GUARD_ANCHOR, INV_OLD):
    assert original.count(x) == 1
assert BLOCK.count(PAYLOAD) == 1 and BLOCK.count(GUARD_ANCHOR) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


# --- Variant 1: renamed vulnerable variant ---
# Written out in full: the shorthand properties ({ email }) and the
# template-literal ${url} make a blind identifier rename change JWT claim and
# template-data keys.
v1_block = '''	async sendPasswordResetMail(address: string, resetUrl: string | null, mailSubject?: string | null): Promise<void> {
		const STALL_MS = 500;
		const startedAt = performance.now();

		const account = await this.getUserByEmail(address);

		if (account?.status !== 'active') {
			await stall(STALL_MS, startedAt);
			throw new ForbiddenError();
		}

		if (resetUrl && isUrlAllowed(resetUrl, env['PASSWORD_RESET_URL_ALLOW_LIST']) === false) {
			throw new InvalidPayloadError({ reason: `Url "${resetUrl}" can't be used to reset passwords` });
		}

		const mailer = new MailService({
			schema: this.schema,
			knex: this.knex,
			accountability: this.accountability,
		});

		const claims = { email: address, scope: 'password-reset', hash: getSimpleHash('' + account.password) };
		const resetToken = jwt.sign(claims, env['SECRET'] as string, { expiresIn: '1d', issuer: 'directus' });

		const resetLink = resetUrl
			? new Url(resetUrl).setQuery('token', resetToken).toString()
			: new Url(env['PUBLIC_URL']).addPath('admin', 'reset-password').setQuery('token', resetToken).toString();

		const title = mailSubject ? mailSubject : 'Password Reset Request';

		await mailer.send({
			to: address,
			subject: title,
			template: {
				name: 'password-reset',
				data: {
					url: resetLink,
					email: address,
				},
			},
		});

		await stall(STALL_MS, startedAt);
	}
'''
v1 = build(v1_block)
assert "requestPasswordReset" not in v1 and "user.password" not in v1_block
(CASE_DIR / "variant_vulnerable_01.ts").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
b = swap(BLOCK, PAYLOAD + "\t\tconst token = jwt.sign(payload, env['SECRET'] as string, { expiresIn: '1d', issuer: 'directus' });\n",
         "\t\tconst token = this.signResetToken(email, user.password);\n")
b = b.rstrip("\n") + '''

\tprivate signResetToken(email: string, currentPassword: string): string {
\t\tconst payload = { email, scope: 'password-reset', hash: getSimpleHash('' + currentPassword) };
\t\treturn jwt.sign(payload, env['SECRET'] as string, { expiresIn: '1d', issuer: 'directus' });
\t}
'''
(CASE_DIR / "variant_vulnerable_02.ts").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Password reset: the stored address must equal the typed one after
# lower-casing (a look-alike that only matched through the collation is
# refused with the same stalled Forbidden as an unknown user); upstream
# instead mails the stored address. Invite: mail and sign for the STORED
# address of a known user, the supplied one for a new user.
v3 = swap(original, GET_OLD, GET_NEW)
v3 = swap(v3, GUARD_ANCHOR, GUARD_ANCHOR.replace("if (user?.status !== 'active') {",
          "if (user?.status !== 'active' || user.email.toLowerCase() !== email.toLowerCase()) {"))
v3 = swap(v3, "\t\t\t\tconst subjectLine = subject ?? \"You've been invited\";\n",
          "\t\t\t\tconst subjectLine = subject ?? \"You've been invited\";\n\t\t\t\tconst recipient = isEmpty(user) ? email : user.email;\n")
v3 = swap(v3, INV_OLD, INV_OLD.replace("to: email,", "to: recipient,").replace("this.inviteUrl(email, url),", "this.inviteUrl(recipient, url),").replace("\t\t\t\t\t\t\temail,\n", "\t\t\t\t\t\t\temail: recipient,\n"))
(CASE_DIR / "variant_safe_01.ts").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import { getSimpleHash } from '@directus/utils';
import jwt from 'jsonwebtoken';

interface StoredUser {
\tid: string;
\temail: string;
\tpassword: string;
}

/**
 * Same "sign a password-reset token and mail it" shape, but the token payload
 * and the recipient both come from the STORED user record, never from the
 * address the requester typed.
 */
export async function mailResetLink(
\tuser: StoredUser,
\tsecret: string,
\tsend: (message: { to: string; token: string }) => Promise<void>
): Promise<void> {
\tconst payload = { email: user.email, scope: 'password-reset', hash: getSimpleHash('' + user.password) };
\tconst token = jwt.sign(payload, secret, { expiresIn: '1d', issuer: 'directus' });
\tawait send({ to: user.email, token });
}
'''
assert "to: user.email" in benign_source
(CASE_DIR / "benign_lookalike.ts").write_text(benign_source)
print("Wrote 4 new samples for CASE-0147.")
