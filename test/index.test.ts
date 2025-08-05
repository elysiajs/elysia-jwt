import { Elysia, t } from 'elysia'
import { jwt } from '../src'
import { SignJWT } from 'jose'

import { describe, expect, it } from 'bun:test'

const post = (path: string, body = {}) =>
	new Request(`http://localhost${path}`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify(body)
	})

const TEST_SECRET = 'A'

describe('JWT Plugin', () => {
	const app = new Elysia()
		.use(
			jwt({
				name: 'jwt',
				secret: TEST_SECRET
				//exp: '1h' // default expiration,
				//iat: true - default iat included
			})
		)
		.post(
			'/sign-token',
			({ jwt, body }) =>
				jwt.sign({
					name: body.name,
					exp: '30m'
				}),
			{
				body: t.Object({
					name: t.String()
				})
			}
		)
		.post(
			'/sign-token-disable-exp-and-iat',
			({ jwt, body }) =>
				jwt.sign({
					name: body.name,
					// nbf: undefined,
					exp: undefined,
					iat: false,
				}),
			{
				body: t.Object({
					name: t.String()
				})
			}
		)
		.post(
			'/verify-token',
			async ({ jwt, body }) => {
				const verifiedPayload = await jwt.verify(body.token)
				if (!verifiedPayload) {
					return {
						success: false,
						data: null,
						message: 'Verification failed'
					}
				}
				return { success: true, data: verifiedPayload }
			},
			{
				body: t.Object({ token: t.String() })
			}
		)
		.post(
			'/verify-token-with-exp-and-iat',
			async ({ jwt, body }) => {
				const verifiedPayload = await jwt.verify(body.token)
				if (!verifiedPayload) {
					return {
						success: false,
						data: null,
						message: 'Verification failed'
					}
				}

				if (!verifiedPayload.exp) {
					return {
						success: false,
						data: null,
						message: 'exp was not setted on jwt'
					}
				}
				if (!verifiedPayload.iat) {
					return {
						success: false,
						data: null,
						message: 'iat was not setted on jwt'
					}
				}
				return { success: true, data: verifiedPayload }
			},
			{
				body: t.Object({ token: t.String() })
			}
		)

	it('should sign JWT and then verify', async () => {
		const payloadToSign = { name: 'Shirokami' }

		const signRequest = post('/sign-token', payloadToSign)
		const signResponse = await app.handle(signRequest)
		const token = await signResponse.text()

		expect(token.split('.').length).toBe(3)

		const verifyRequest = post('/verify-token', { token })
		const verifyResponse = await app.handle(verifyRequest)
		const verifiedResult = (await verifyResponse.json()) as {
			success: boolean
			data: { name: string; exp: number } | null
		}

		expect(verifiedResult.success).toBe(true)
		expect(verifiedResult.data?.name).toBe(payloadToSign.name)
		expect(verifiedResult.data?.exp).toBeDefined()
	})

	it('should return verification failed for an invalid token', async () => {
		const verifyRequest = post('/verify-token', {
			token: 'invalid'
		})
		const verifyResponse = await app.handle(verifyRequest)
		const verifiedResult = await verifyResponse.json()

		expect(verifiedResult.success).toBe(false)
		expect(verifiedResult.message).toBe('Verification failed')
	})

	it('should return verification failed for an expired token', async () => {
		const key = new TextEncoder().encode(TEST_SECRET)
		const expiredToken = await new SignJWT({ name: 'Expired User' })
			.setProtectedHeader({ alg: 'HS256' })
			.setExpirationTime(Math.floor(Date.now() / 1000) - 3600)
			.sign(key)

		const verifyRequest = post('/verify-token', { token: expiredToken })
		const verifyResponse = await app.handle(verifyRequest)
		const verifiedResult = await verifyResponse.json()

		expect(verifiedResult.success).toBe(false)
		expect(verifiedResult.message).toBe('Verification failed')
	})

	it('should sign JWT with default values (exp and iat) and then verify', async () => {
		const payloadToSign = { name: 'John Doe' }

		const signRequest = post('/sign-token', payloadToSign)
		const signResponse = await app.handle(signRequest)
		const token = await signResponse.text()

		expect(token.split('.').length).toBe(3)

		const verifyRequest = post('/verify-token-with-exp-and-iat', { token })
		const verifyResponse = await app.handle(verifyRequest)

		const verifiedResult = (await verifyResponse.json()) as {
			success: boolean
			data: { name: string; exp: number; iat: number } | null
		}

		expect(verifiedResult.success).toBe(true)
		expect(verifiedResult.data?.name).toBe(payloadToSign.name)
		expect(verifiedResult.data?.exp).toBeDefined()
		expect(verifiedResult.data?.iat).toBeDefined()
	})

	it('Should allow disabling default values', async () => {
		const payloadToSign = { name: 'John Doe' }

		const signRequest = post('/sign-token-disable-exp-and-iat', payloadToSign)
		const signResponse = await app.handle(signRequest)
		const token = await signResponse.text()

		expect(token.split('.').length).toBe(3)

		const verifyRequest = post('/verify-token', { token })
		const verifyResponse = await app.handle(verifyRequest)

		const verifiedResult = (await verifyResponse.json()) as {
			success: boolean
			data: { name: string; exp: undefined; iat: undefined } | null
		}

		expect(verifiedResult.success).toBe(true)
		expect(verifiedResult.data?.name).toBe(payloadToSign.name)
		expect(verifiedResult.data?.exp).toBeUndefined()
		expect(verifiedResult.data?.iat).toBeUndefined()
	})
})
