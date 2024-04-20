import { Elysia, ValidationError, getSchemaValidator } from 'elysia'

import {
    SignJWT,
    jwtVerify,
    type JWTPayload,
    type JWSHeaderParameters,
    type KeyLike,
    errors,
    type JWTVerifyGetKey,
    type JWTVerifyOptions,
    type JWTVerifyResult,
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
     */
    secret: string | Uint8Array | KeyLike | JWTVerifyGetKey
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

const verifier = (key: Uint8Array | KeyLike | JWTVerifyGetKey): {
    (jwt: string, options?: JWTVerifyOptions): Promise<JWTVerifyResult>
} => {
    return typeof key === 'function'
        ? (jwt, options) => jwtVerify<any>(jwt, key, options)
        : (jwt, options) => jwtVerify(jwt, key, options)
        ;
}

export const jwt = <
    const Name extends string = 'jwt',
    const Schema extends TSchema | undefined = undefined
>({
    name = 'jwt' as Name,
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
    JWTOption<Name, Schema>
) => (app: Elysia) => {
    if (!secret) throw new Error("Secret can't be empty")

    const key =
        typeof secret === 'string' ? new TextEncoder().encode(secret) : secret
    const verifyKey = verifier(key);
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

        // return new Elysia({
        //     name: '@elysiajs/jwt',
        //     seed: {
        //         name,
        //         secret,
        //         alg,
        //         crit,
        //         schema,
        //         nbf,
        //         exp,
        //         ...payload
        //     }
        // })
    return app.decorate(name as Name extends string ? Name : 'jwt', {
        sign: (
            morePayload: UnwrapSchema<Schema, Record<string, string | number>> &
                JWTPayloadSpec
        ) => {
            if (typeof key === 'function') {
                throw new TypeError('Cannot use that secret to sign, likely only verify.');
            }

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
            jwt?: string,
            options?: JWTVerifyOptions,
        ): Promise<
            | (UnwrapSchema<Schema, Record<string, string | number>> &
                JWTPayloadSpec)
            | false
        > => {
            if (!jwt) return false

            try {
                // note: this is to satisfy typescript.
                const data: any = (
                    await (verifyKey(jwt, options)
                        .catch(async (error) => {
                            if (error?.code === 'ERR_JWKS_MULTIPLE_MATCHING_KEYS') {
                                for await (const publicKey of error) {
                                    try {
                                        return await jwtVerify(jwt, publicKey, options)
                                    }
                                    catch (innerError: any) {
                                        if ('code' in innerError && innerError?.code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') {
                                            continue;
                                        }

                                        throw innerError
                                    }
                                }

                                throw new errors.JWSSignatureVerificationFailed()
                            }

                            throw error
                        }))
                ).payload

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
