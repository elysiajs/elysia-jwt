# @elysia/jwt

[Elysia](https://github.com/elysiajs/elysia) plugin to integrate JSON Web Tokens (JWT).

## Installation

```bash
bun add @elysia/jwt
```

## Example

```typescript
import { Elysia, t } from 'elysia'
import { jwt } from '@elysia/jwt'

const app = new Elysia()
	.use(
		jwt({
			name: 'jwt',
			// This should be Environment Variable
			secret: 'MY_SECRETS'
		})
	)
	.get('/sign/:name', async ({ jwt, cookie: { auth }, params }) => {
		auth.set({
			value: await jwt.sign(params),
			httpOnly: true
		})

		return `Sign in as ${params.name}`
	})
	.get('/profile', async ({ jwt, set, cookie: { auth } }) => {
		const profile = await jwt.verify(auth)

		if (!profile) {
			set.status = 401
			return 'Unauthorized'
		}

		return `Hello ${profile.name}`
	})
	.listen(3000)
```

See [documentation](https://elysiajs.com/plugins/jwt.html) for more details.
