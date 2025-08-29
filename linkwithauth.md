# Auth Service — Step‑by‑Step Guide (Frontend & Backend)

This is a Dockerized FastAPI authentication service using JWT (RS256), PostgreSQL, and a built‑in admin UI.

Use it as a central auth provider for multiple apps: your frontends ask it for tokens; your backends verify those tokens with the public JWKS.

## 1) Setup

1. Copy env file and edit values:
	 - Copy `.env.example` to `.env` and adjust as needed. For dev, defaults are fine.
2. Start the stack (from repo root `D:\FAS-AUTH\FAP-AMS`):

```powershell
docker-compose up -d --build
```

3. Open the admin UI at http://localhost:8001/admin and log in with the dev admin from `.env` (if seeded) or sign up and promote to admin via an existing admin.

Keys are generated or mounted at `./keys`. For production, mount real keys via secrets and terminate TLS upstream.

## 2) Configuration (env)

- DATABASE_URL: PostgreSQL URL (compose provides one).
- PRIVATE_KEY_PATH, PUBLIC_KEY_PATH: paths inside the container (`/keys`).
- ACCESS_TOKEN_EXPIRE_MINUTES: JWT access token lifetime.
- ADMIN_EMAIL, ADMIN_PASSWORD: optional dev seed for the first admin.
- ALLOWED_ORIGINS: CORS origins (no trailing slash).
- PUBLIC_BASE_URL: the public base URL of this service (used in reset links, issuer default).
- PASSWORD_RESET_EXPIRES_MINUTES: expiry for one‑time reset tokens.
- APP_VERSION: reported by `/version`.
- JWT_ISSUER, JWT_AUDIENCE: issuer and accepted audiences for JWT validation.
- MIN_PASSWORD_LENGTH, REQUIRE_DIGIT, REQUIRE_LETTER, REQUIRE_SPECIAL: password policy.

Tip: In compose output, empty envs show warnings; the service now safely falls back to defaults.

## 3) Endpoints overview

- Auth
	- POST `/auth/signup` → create user (assigns default “visitor” role)
	- POST `/auth/login` → returns `{ access_token, token_type }` (blocks inactive users)
	- POST `/auth/assign-role` → assign role (admin)
	- POST `/auth/assign-role-unassign` → unassign role (admin)
	- Admin: `/auth/admin/*` → add/approve/remove user, change password, manage roles
- Users
	- GET `/users/` → list users (admin)
	- POST `/users/password-reset/request` → create one‑time reset link (admin only)
	- POST `/users/password-reset/use` → consume reset token and set a new password
- Well‑known
	- GET `/.well-known/jwks.json` → JWKS with RSA `n`/`e` and `kid`
	- GET `/.well-known/public_key.pem` → PEM for reference
	- GET `/.well-known/openid-configuration` → minimal discovery (issuer, jwks_uri)
- Health & Metrics
	- GET `/healthz`, `/readyz`, `/version`
	- GET `/metrics` → Prometheus exposition
- Static pages
	- `/admin` → admin SPA
	- `/login` → simple public login page (optional)
	- `/auth/password-reset` → password reset page that consumes `?token=...`

## 4) Frontend integration (step‑by‑step)

Goal: Let users log in, store the JWT, and call your app’s APIs with `Authorization: Bearer <token>`.

1. Configure CORS: set `ALLOWED_ORIGINS` to include your frontend origin(s).
2. Implement a login form that posts to the auth service:

```js
// Example with fetch
async function login(email, password) {
	const res = await fetch('http://localhost:8001/auth/login', {
		method: 'POST', headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ email, password })
	});
	if (!res.ok) throw new Error('Invalid credentials');
	const { access_token } = await res.json();
	localStorage.setItem('access_token', access_token);
}
```

3. Attach the token to your API requests:

```js
function authFetch(url, options={}){
	const token = localStorage.getItem('access_token');
	return fetch(url, {
		...options,
		headers: { ...(options.headers||{}), Authorization: `Bearer ${token}` }
	});
}
```

4. Handle logout by removing the token from storage. Consider token expiry (check exp claim) and re‑prompt for login.

5. Password reset flow (admin‑initiated):
	 - Admin requests a reset: POST `/users/password-reset/request` with `{ email }`.
	 - The API returns `reset_link` and (if `PUBLIC_BASE_URL` set) `absolute_link`.
	 - Email the link to the user or copy it from the admin UI. The static reset page at `/auth/password-reset` will set a new password.

6. Using the built‑in admin UI:
	 - Visit `/admin`. Manage users and roles, generate reset links, toggle active/inactive, edit roles.
	 - Role “admin” is protected (can’t be removed; last active admin protected by safety checks).

## 5) Backend integration (resource server)

Your backend must verify incoming JWTs. Use the RS256 public JWKS at `/.well-known/jwks.json`, and validate `iss`, `exp`, and (optionally) `aud`.

### FastAPI (Python) example

```python
from fastapi import FastAPI, Depends, HTTPException
from jose import jwt
import requests

AUTH_ISSUER = "http://localhost:8001"
JWKS_URL = f"{AUTH_ISSUER}/.well-known/jwks.json"
ALGO = "RS256"

jwks = requests.get(JWKS_URL, timeout=5).json()
keys = {k['kid']: k for k in jwks['keys']}

def verify_token(token: str):
		header = jwt.get_unverified_header(token)
		kid = header.get('kid')
		key = keys.get(kid)
		if not key: raise HTTPException(401, 'Unknown key')
		# Build public key from n/e
		from jose.utils import base64url_decode
		from cryptography.hazmat.primitives.asymmetric import rsa
		from cryptography.hazmat.backends import default_backend
		n = int.from_bytes(base64url_decode(key['n']), 'big')
		e = int.from_bytes(base64url_decode(key['e']), 'big')
		public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
		return jwt.decode(token, public_key, algorithms=[ALGO], issuer=AUTH_ISSUER)

def require_auth(roles: list[str] | None = None):
		def dep(authorization: str | None = None):
				if not authorization or not authorization.startswith('Bearer '):
						raise HTTPException(401, 'Missing token')
				token = authorization.split(' ',1)[1]
				claims = verify_token(token)
				if roles:
						user_roles = set(claims.get('roles', []))
						if not set(roles) & user_roles:
								raise HTTPException(403, 'Insufficient role')
				return claims
		return dep

app = FastAPI()

@app.get('/protected')
def protected(claims = Depends(require_auth(['admin']))):
		return {"ok": True, "sub": claims['sub']}
```

### Node (Express) example

```js
import jwksClient from 'jwks-rsa';
import jwt from 'jsonwebtoken';

const ISSUER = 'http://localhost:8001';
const client = jwksClient({ jwksUri: `${ISSUER}/.well-known/jwks.json` });

function getKey(header, cb){
	client.getSigningKey(header.kid, (err, key) => {
		if (err) return cb(err);
		const signingKey = key.getPublicKey();
		cb(null, signingKey);
	});
}

function requireAuth(roles){
	return (req,res,next)=>{
		const auth = req.headers.authorization||'';
		const token = auth.startsWith('Bearer ')? auth.slice(7): null;
		if(!token) return res.status(401).end();
		jwt.verify(token, getKey, { algorithms:['RS256'], issuer: ISSUER }, (err, payload)=>{
			if(err) return res.status(401).end();
			if(roles && !roles.some(r => (payload.roles||[]).includes(r))) return res.status(403).end();
			req.user = payload; next();
		});
	}
}
```

## 6) JWT claims

- `sub`: user id (string)
- `roles`: array of role names
- `iss`: issuer (set via `JWT_ISSUER` or `PUBLIC_BASE_URL`)
- `exp`, `iat`, `jti`
- Optional `aud` if `JWT_AUDIENCE` is set

## 7) Admin UI tips

- Users page: search/filter/sort, pagination, details modal, activate/deactivate, assign/unassign roles, password reset link, remove user.
- Roles page: add/edit role name and description, remove non‑admin roles.
- Safety: cannot delete/deactivate the last active admin; cannot remove the admin role from the last active admin.

## 8) Observability & audit

- Health: `/healthz`, `/readyz`, `/version`
- Metrics: `/metrics` (Prometheus Counter/Histogram for requests)
- Audit: `audit_logs` table records login success/failure and admin actions.

## 9) Security notes

- Password policy is enforced on signup, admin set, and reset.
- Rate limiting (naive in‑memory) applies to login and reset requests; for production, use a distributed limiter (Redis) and a WAF.
- Use HTTPS in front of this service; set trusted proxies if applicable.
- Rotate keys periodically and consider KMS/HSM for key management.

## 10) Troubleshooting

- Container exits on start: check `.env` values; this service tolerates empty envs with defaults, but `DATABASE_URL` must be reachable.
- CORS errors: ensure `ALLOWED_ORIGINS` includes your exact frontend origins (no trailing slash).
- Invalid token on backends: verify `iss` matches `JWT_ISSUER`/`PUBLIC_BASE_URL`, and your resource verifies against the live JWKS.

---

Roadmap (not yet implemented): refresh tokens with rotation, logout/revocation, full OIDC Authorization Code + PKCE, multi‑tenant isolation, email delivery integration, distributed rate limiting, key rotation with multiple kids.

