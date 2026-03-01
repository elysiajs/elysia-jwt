import Elysia from 'elysia'
import jwt from '../src'
import { z } from 'zod'

const post = (path: string, body = {}) =>
	new Request(`http://localhost${path}`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify(body)
	})

const app = new Elysia()
	.use(
		jwt({
			name: 'jwt',
			secret: 'hello world',
			schema: z.object({
				name: z.string()
			})
		})
	)
	.post(
		'/sign-token',
		({ jwt, body: { name } }) =>
			jwt.sign({
				name,
				exp: '30m'
			}),
		{
			body: z.object({
				name: z.string()
			})
		}
	)
	.post(
		'/verify-token',
		async ({ jwt, body }) => {
			const verifiedPayload = await jwt.verify(body.token)
			if (!verifiedPayload)
				return {
					success: false,
					data: null,
					message: 'Verification failed'
				}

			return { success: true, data: verifiedPayload }
		},
		{
			body: z.object({ token: z.string() })
		}
	)

const payloadToSign = { name: 'Shirakami' }

const signRequest = post('/sign-token', payloadToSign)
const signResponse = await app.handle(signRequest)
const token = await signResponse.text()

// console.log(token.split('.').length)

const verifyRequest = post('/verify-token', { token })
const verifyResponse = await app.handle(verifyRequest)
const verifiedResult = (await verifyResponse.json()) as {
	success: boolean
	data: { name: string; exp: number } | null
}
