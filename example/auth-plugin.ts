import { Elysia, t } from 'elysia'
import { jwt } from '../src'

const authPlugin = new Elysia({ name: 'authPlugin' })
	.use(
		jwt({
			name: 'jwt',
			secret: 'top-secret',
			schema: t.Object({
				name: t.String()
			})
		})
	)
	.derive(async ({ cookie: { auth }, jwt }) => {
		const user = await jwt.verify(auth.value)
		if (!user) throw new Error('Unauthorized')
		return { user: user }
	})
	.as('scoped')

const protectedRoutes = new Elysia()
	.use(authPlugin)
	.get('/me', ({ user }) => `Viewing protected data as ${user.name}`)

const app = new Elysia()
	.use(protectedRoutes)
	.get('/public', () => ({ message: 'Public Data' }))
	.listen(8080)
