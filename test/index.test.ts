import { Elysia, t } from 'elysia'
import { jwt } from '../src'

import { describe, expect, it } from 'bun:test'

const post = (path: string, body = {}) =>
    new Request(`http://localhost${path}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(body)
    })

describe('JWT Plugin', () => {
    it('signs and verifies JWTs', async () => {
        const app = new Elysia()
            .use(
                jwt({
                    name: 'jwt',
                    secret: 'A'
                })
            )
            .post('/sign', ({ jwt, body }) => jwt.sign(body), {
                body: t.Object({ name: t.String() })
            })
            .post('/verify', ({ jwt, body: { token } }) => jwt.verify(token), {
                body: t.Object({ token: t.String() })
            })

        const name = 'Shirokami'

        const sign = await app.handle(post('/sign', { name }))
        const token = await sign.text()
        expect(token).toMatch(/^[A-Za-z0-9_-]{2,}(?:\.[A-Za-z0-9_-]{2,}){2}$/)

        const verify = await app.handle(post('/verify', { token }))
        const signed = (await verify.json()) as { name: string } | false
        expect(signed).toEqual({ name });

        const verifyForged = await app.handle(post("/verify", {
            token: "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiU2hpcm9rYW1pIn0.SNUb0H5gYTJYPznYxN36glyJAubUelp8zxy53hYeUt4"
        }));
        const forged = (await verifyForged.json()) as { name: string } | false
        expect(forged).toBe(false);
    })
})
