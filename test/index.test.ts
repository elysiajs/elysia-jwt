import { Elysia, t } from 'elysia'
import { jwt } from '../src'
import { createLocalJWKSet, decodeProtectedHeader, exportJWK, generateKeyPair, SignJWT } from 'jose'

import { describe, expect, it } from 'bun:test'
import { inferBodyReference } from 'elysia/dist/sucrose'

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
				jwt.sign!({
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
				jwt.sign!({
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
						message: 'exp was not set on jwt'
					}
				}
				if (!verifiedPayload.iat) {
					return {
						success: false,
						data: null,
						message: 'iat was not set on jwt'
					}
				}
				return { success: true, data: verifiedPayload }
			},
			{
				body: t.Object({ token: t.String() })
			}
		)

	it('should sign JWT and then verify', async () => {
		const payloadToSign = { name: 'Shirakami' }

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

	// Basic JWKS test
	it('Should verify RS256 via jwks and HS256 via local secret when both are configured',
		async () => {
			// RS256 key pair + jwks
			const { publicKey, privateKey } = await generateKeyPair('RS256')
			const pubJwk = await exportJWK(publicKey)
			Object.assign(pubJwk, { alg: 'RS256', kid: 'test' })
			const getKey = createLocalJWKSet({ keys: [pubJwk] })

			const jwksApp = new Elysia()
				.use(jwt({ name: 'jwt', secret: TEST_SECRET, jwks: getKey }))
				.post('/verify', async ({ jwt, body }) => {
					const token = await jwt.verify(body.token)
					return {
						token,
						ok: !!token
					}
				}, {
					body: t.Object({ token: t.String() })
				})
				.post('/sign', async ({ body, jwt }) => await jwt.sign!({
					name: body.name,
					exp: undefined,
					iat: false,
				}), {
					body: t.Object({ name: t.String() })
				})

			// RS256 token -> jwks
			const rsToken = await new SignJWT({ role: 'local' })
				.setProtectedHeader({ alg: 'RS256', kid: 'test' })
				.setExpirationTime('5m')
				.sign(privateKey)
			const rsResp = await jwksApp.handle(post('/verify', { token: rsToken }))
			const rsRespJson = await rsResp.json()
			expect((rsRespJson.ok)).toBe(true)

			// HS256 token -> local secret
			const hsSignResp = await jwksApp.handle(post('/sign', { name: 'test' }))
			const hsToken = await hsSignResp.text()
			expect(decodeProtectedHeader(hsToken).alg).toBe('HS256')
			const hsResp = await jwksApp.handle(post('/verify', { token: hsToken }))
			const hsRespJson = await hsResp.json()
			expect(hsRespJson.ok).toBe(true)
	})
})
