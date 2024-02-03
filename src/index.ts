import { Elysia, ValidationError, getSchemaValidator } from 'elysia'

import {
    SignJWT,
    jwtVerify,
    type JWTPayload,
    type JWSHeaderParameters,
    type KeyLike
} from 'jose'

import { Type as t } from '@sinclair/typebox'
import type { Static, TSchema } from '@sinclair/typebox'

type UnwrapSchema<
    Schema extends TSchema | undefined,
    Fallback = unknown
> = Schema extends TSchema ? Static<NonNullable<Schema>> : Fallback

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
     * Only `secret` or both `privateKey`, `publicKey` must be set
     */
    secret?: string | Uint8Array | KeyLike
    /**
     * JWT Private Key
     * Only `secret` or both `privateKey`, `publicKey` must be set
     */
    privateKey?: Uint8Array | KeyLike
    /**
     * JWT Public Key
     * Only `secret` or both `privateKey`, `publicKey` must be set
     */
    publicKey?: Uint8Array | KeyLike
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

export const jwt = <
    const Name extends string = 'jwt',
    const Schema extends TSchema | undefined = undefined
>({
    name = 'jwt' as Name,
    secret,
    publicKey,
    privateKey,
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
JWTOption<Name, Schema>) => {
    const key =
        typeof secret === 'string' ? new TextEncoder().encode(secret) : secret

    let asymmetric = false

    if (secret && (privateKey || publicKey)) {
        throw new Error("When using asymmetric algorithm, only `privateKey` and `publicKey` is accepted")
    }

    if (privateKey && !publicKey) {
        throw new Error("When using asymmetric algorithm, both `privateKey` and `publicKey` must be set. Public key is missing")
    }

    if (publicKey && !privateKey) {
        throw new Error("When using asymmetric algorithm, both `privateKey` and `publicKey` must be set. Private key is missing")
    }

    if (privateKey && privateKey) {
        asymmetric = true
    } else if (!secret) {
        throw new Error("Secret can't be empty")
    }

    const validator = schema
        ? getSchemaValidator(
              t.Intersect([
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
              ]),
              {}
          )
        : undefined

    return new Elysia({
        name: '@elysiajs/jwt',
        seed: {
            name,
            secret,
            alg,
            crit,
            schema,
            nbf,
            exp,
            ...payload
        }
    }).decorate(name as Name extends string ? Name : 'jwt', {
        sign: (
            morePayload: UnwrapSchema<Schema, Record<string, string | number>> &
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

            return jwt.sign(asymmetric ? privateKey! : key!)
        },
        verify: async (
            jwt?: string
        ): Promise<
            | (UnwrapSchema<Schema, Record<string, string | number>> &
                  JWTPayloadSpec)
            | false
        > => {
            if (!jwt) return false

            try {
                const data: any = (await jwtVerify(jwt, asymmetric ? publicKey! : key!)).payload

                if (validator && !validator!.Check(data))
                    throw new ValidationError('JWT', validator, data)

                return data
            } catch (_) {
                return false
            }
        }
    })
}

export default jwt
