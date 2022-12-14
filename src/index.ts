import {
    createValidationError,
    getSchemaValidator,
    type Elysia,
    type Context,
    type UnwrapSchema
} from 'elysia'

import {
    SignJWT,
    jwtVerify,
    type JWTPayload,
    type JWSHeaderParameters
} from 'jose'

import { Type as t } from '@sinclair/typebox'
import type { Static, TObject, TSchema } from '@sinclair/typebox'

export interface JWTPayloadSpec {
    iss?: string
    sub?: string
    aud?: string | string[]
    jti?: string
    nbf?: number
    exp?: number
    iat?: number
}

export interface JWTOption<
    Name extends string | undefined = 'jwt',
    Schema extends TSchema | undefined = undefined
> extends JWSHeaderParameters,
        Omit<JWTPayload, 'nbf' | 'exp'> {
    /**
     * Name to decorate method as
     *
     * ---
     * @example
     * For example, `jwt` will decorate Context with `Context.jwt`
     *
     * ```typescript
     * app
     *     .decorate({
     *         name: 'myJWTNamespace',
     *         secret: process.env.JWT_SECRETS
     *     })
     *     .get('/sign/:name', ({ myJWTNamespace, params }) => {
     *         return myJWTNamespace.sign(params)
     *     })
     * ```
     */
    name?: Name
    /**
     * JWT Secret
     */
    secret: string
    /**
     * Type strict validation for JWT payload
     */
    schema?: Schema

    /**
     * JWT Not Before
     *
     * @see [RFC7519#section-4.1.5](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5)
     */

    nbf?: string | number
    /**
     * JWT Expiration Time
     *
     * @see [RFC7519#section-4.1.4](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4)
     */
    exp?: string | number
}

export const jwt =
    <
        Name extends string | undefined,
        Schema extends TSchema | undefined = undefined
    >({
        name = 'jwt',
        secret,
        // Start JWT Header
        alg = 'HS256',
        crit,
        schema,
        // End JWT Header
        // Start JWT Payload
        nbf,
        exp,
        ...payload
    }: // End JWT Payload
    JWTOption<Name, Schema>) =>
    (app: Elysia) => {
        if (!secret) throw new Error("Secret can't be empty")

        const key = new TextEncoder().encode(secret)

        const validator = schema
            ? getSchemaValidator(
                  t.Union([
                      schema,
                      t.Object({
                          iss: t.Optional(t.String()),
                          sub: t.Optional(t.String()),
                          aud: t.Optional(
                              t.Union([t.String(), t.Array(t.String())])
                          ),
                          jti: t.Optional(t.String()),
                          nbf: t.Optional(t.Union([t.String(), t.Number()])),
                          exp: t.Optional(t.Union([t.String(), t.Number()])),
                          iat: t.Optional(t.String())
                      })
                  ])
              )
            : undefined

        return app.decorate(name as Name extends string ? Name : 'jwt', {
            sign: (
                morePayload: UnwrapSchema<Schema, Record<string, string>> &
                    JWTPayloadSpec
            ) => {
                let jwt = new SignJWT({
                    ...payload,
                    ...morePayload,
                    nbf: undefined,
                    exp: undefined
                }).setProtectedHeader({
                    alg,
                    crit
                })

                if (nbf) jwt = jwt.setNotBefore(nbf)
                if (exp) jwt = jwt.setExpirationTime(exp)

                return jwt.sign(key)
            },
            verify: async (
                jwt?: string
            ): Promise<
                | (UnwrapSchema<Schema, Record<string, string>> &
                      JWTPayloadSpec)
                | false
            > => {
                if (!jwt) return false

                try {
                    const data: any = (await jwtVerify(jwt, key)).payload

                    if (validator && !validator!.Check(data))
                        throw createValidationError('JWT', validator, data)

                    return data
                } catch (_) {
                    return false
                }
            }
        })
    }

export default jwt
