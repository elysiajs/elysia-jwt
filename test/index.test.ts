import { Elysia, t } from 'elysia'
import { importJWK } from 'jose'
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

describe('Static Plugin', () => {
    async function signTest() {
      const name = 'Shirokami'

      const _sign = post('/sign', { name })
      await _sign.text()

      const _verified = post('/verify', { name })
      const signed = (await _verified.json()) as {
        name: string
      }

      expect(name).toBe(signed.name)
    }

    it('sign JWT', async () => {
        new Elysia()
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

        await signTest()
    })
    it('sign JWT (asymmetric)', async () => {
        const crv = 'Ed25519'
        const d = 'N3cOzsFZwiIbtNiBYQP9bcbcTIdkITC8a4iRslrbW7Q'
        const x = 'RjnTe-mqZcVls6SQ5CgW0X__jRaa-Quj5HBDREzVLhc'
        const kty = 'OKP'

        new Elysia()
            .use(
                jwt({
                  name: 'jwt',
                  privateKey: await importJWK({ crv, d, x, kty }, 'EdDSA'),
                  publicKey: await importJWK({ crv, x, kty }, 'EdDSA')
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

        await signTest()
      })
})
