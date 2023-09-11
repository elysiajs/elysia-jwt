import { Elysia, t } from 'elysia'
import { jwt } from '../src'

import { describe, expect, it } from 'bun:test'

const req = (path: string) => new Request(`http://localhost${path}`)
const post = (path: string, body = {}) =>
    new Request(`http://localhost${path}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(body)
    })

describe('Static Plugin', () => {
    it('sign JWT', async () => {
        const app = new Elysia()
            .use(
                jwt({
                    name: 'jwt',
                    secret: 'A'
                })
            )
            .post('/validate', ({ jwt, body }) => jwt.sign(body), {
                body: t.Object({
                    name: t.String()
                })
            })
            .post('/validate', ({ jwt, body: { name } }) => jwt.verify(name), {
                body: t.Object({ name: t.String() })
            })

        const name = 'Shirokami'

        const _sign = post('/sign', { name })
        const token = await _sign.text()

        const _verified = post('/verify', { name })
        const signed = (await _verified.json()) as {
            name: string
        }

        expect(name).toBe(signed.name)
    })
})
