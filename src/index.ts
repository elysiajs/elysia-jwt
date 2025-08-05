import {
	Elysia,
	ValidationError,
	getSchemaValidator,
	type TSchema,
	type UnwrapSchema as Static
} from 'elysia'

import {
	SignJWT,
	jwtVerify,
	type CryptoKey,
	type JWK,
	type KeyObject,
	type JoseHeaderParameters
} from 'jose'

import { Type as t } from '@sinclair/typebox'

type UnwrapSchema<
	Schema extends TSchema | undefined,
	Fallback = unknown
> = Schema extends TSchema ? Static<NonNullable<Schema>> : Fallback

type AllowClaimValue = string | number | boolean | null | undefined | AllowClaimValue[] | { [key: string]: AllowClaimValue }
type ClaimType = Record<string, AllowClaimValue>

/**
 * This interface is a specific, strongly-typed representation of the
 * standard claims found in a JWT payload.
 *
 * It is re-declared here to override potentially generic definitions from
 * third-party libraries, ensuring the compiler knows every expected field.
 *
 * This interface can be modified as needed within the plugin to easily
 * accommodate custom claims for specific use cases.
 */
export interface JWTPayloadSpec {
	/**
	 * JWT Issuer
	 *
	 * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1 RFC7519#section-4.1.1}
	 */
	iss?: string

	/**
	 * JWT Subject
	 *
	 * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2 RFC7519#section-4.1.2}
	 */
	sub?: string

	/**
	 * JWT Audience
	 *
	 * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3 RFC7519#section-4.1.3}
	 */
	aud?: string | string[]

	/**
	 * JWT ID
	 *
	 * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7 RFC7519#section-4.1.7}
	 */
	jti?: string

	/**
	 * JWT Not Before
	 *
	 * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5 RFC7519#section-4.1.5}
	 */
	nbf?: string | number

	/**
	 * JWT Expiration Time
	 *
	 * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4 RFC7519#section-4.1.4}
	 */
	exp?: string | number

	/**
	 * JWT Issued At
	 *
	 * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6 RFC7519#section-4.1.6}
	 */
	iat?: boolean
}
/**
 * Defines the types for the header parameters of a JWS.
 *
 * Much like `JWTPayloadSpec`, this interface is declared to provide strong,
 * explicit typing, allowing TypeScript to validate the header's structure
 * and provide accurate autocompletion.
 *
 * It can also be modified within the plugin to handle custom header
 * parameters required for specific development scenarios.
 */
export interface JWTHeaderParameters extends JoseHeaderParameters {
	/**
	 * JWS "alg" (Algorithm) Header Parameter
	 *
	 * @see {@link https://github.com/panva/jose/issues/210#jws-alg Algorithm Key Requirements}
	 */
	alg?: string

	/**
	 * This JWS Extension Header Parameter modifies the JWS Payload representation and the JWS Signing
	 * Input computation as per {@link https://www.rfc-editor.org/rfc/rfc7797 RFC7797}.
	 */
	b64?: true

	/** JWS "crit" (Critical) Header Parameter */
	crit?: string[]
}

export interface JWTOption<
	Name extends string | undefined = 'jwt',
	Schema extends TSchema | undefined = undefined
> extends JWTHeaderParameters,
		JWTPayloadSpec {
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
	secret: string | Uint8Array | CryptoKey | JWK | KeyObject
	/**
	 * Type strict validation for JWT payload
	 */
	schema?: Schema
}

export const jwt = <
	const Name extends string = 'jwt',
	const Schema extends TSchema | undefined = undefined
>({
	name = 'jwt' as Name,
	secret,
	schema,
	...defaultValues
}: // End JWT Payload
JWTOption<Name, Schema>) => {
	if (!secret) throw new Error("Secret can't be empty")

	const key =
		typeof secret === 'string' ? new TextEncoder().encode(secret) : secret

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
						iat: t.Optional(t.Union([t.Number(), t.String()]))
					})
				]),
				{
					modules: t.Module({})
				}
			)
		: undefined

	return new Elysia({
		name: '@elysiajs/jwt',
		seed: {
			name,
			secret,
			schema,
			...defaultValues
		}
	}).decorate(name as Name extends string ? Name : 'jwt', {
		sign(
			data: UnwrapSchema<Schema, ClaimType> &
				JWTPayloadSpec
		) {
			/**
			 * @summary Creates the JWS (JSON Web Signature) header object.
			 *
			 * @description
			 * This constant builds the header part of the JWT, populating it with values
			 * from a `defaultValues` source object.
			 *
			 * It ensures essential fields have safe defaults by using the nullish
			 * coalescing operator (`??`):
			 * - `alg` (Algorithm) defaults to 'HS256' if not provided.
			 * - `typ` (Type) defaults to 'JWT' if not provided.
			 *
			 * The final object is type-asserted as `JWTHeaderParameters` to align with
			 * the expected JWS header structure.
			 *
			 * @property alg - The signing algorithm (e.g., 'HS256', 'RS256').
			 * @property [b64] - Indicates if the payload is Base64url-encoded.
			 * @property [crit] - A list of critical header parameters that must be understood.
			 * @property [cty] - The content type of the payload.
			 * @property [jku] - URL for the JSON Web Key Set.
			 * @property [jwk] - The JSON Web Key corresponding to the key used to sign.
			 * @property [kid] - A hint indicating which key was used to sign the JWT.
			 * @property typ - The type of the token, typically 'JWT'.
			 * @property [x5c] - The X.509 certificate chain.
			 * @property [x5t] - The X.509 certificate SHA-1 thumbprint.
			 * @property [x5u] - URL for the X.509 certificate chain.
			 */
			const JWTHeader = {
				alg: defaultValues.alg ?? 'HS256',
				b64: defaultValues.b64,
				crit: defaultValues.crit,
				cty: defaultValues.cty,
				jku: defaultValues.jku,
				jwk: defaultValues.jwk,
				kid: defaultValues.kid,
				typ: defaultValues.typ ?? 'JWT',
				x5c: defaultValues.x5c,
				x5t: defaultValues.x5t,
				x5u: defaultValues.x5u
			} as JWTHeaderParameters

			/**
			 * @summary Constructs a JWT payload object from a given data source.
			 *
			 * @description
			 * This constant assembles the final payload for a JWT by combining standard
			 * RFC 7519 claims with any other custom data present in the `data` object.
			 * * The initial properties (`aud`, `iss`, etc.) are explicitly defined for clarity,
			 * while the spread operator (`...data`) ensures all other properties from the
			 * source are included.
			 * * @warning
			 * The type assertion (`as ...`) is used to satisfy TypeScript but has significant
			 * trade-offs. By including `Record<string, unknown>`, the object effectively loses
			 * strong type safety for custom claims, treating them all as potentially unknown.
			 * This approach should be handled with care, as it bypasses stricter type checking
			 * in favor of flexibility.
			 */
			const JWTPayload = {
				/**
				 * Audience (aud): Identifies the recipients that the JWT is intended for.
				 */
				aud: data.aud ?? defaultValues.aud,

				/**
				 * Issuer (iss): Identifies the principal that issued the JWT.
				 */
				iss: data.iss ?? defaultValues.iss,

				/**
				 * JWT ID (jti): Provides a unique identifier for the JWT.
				 */
				jti: data.jti ?? defaultValues.jti,

				/**
				 * Subject (sub): Identifies the principal that is the subject of the JWT.
				 */
				sub: data.sub ?? defaultValues.sub,

				// Includes all other properties from the data source, both standard and custom.
				...data
			} as
				| Omit<JWTPayloadSpec, 'nbf' | 'exp' | 'iat'>
				| Record<string, unknown>

			let jwt = new SignJWT({ ...JWTPayload }).setProtectedHeader({
				alg: JWTHeader.alg!,
				...JWTHeader
			})

			/**
			 * Sets the time-based claims (nbf, exp, iat) on the JWT.
			 * The logic prioritizes values from the 'data' object (from the sign function)
			 * over the 'defaultValues'.
			 */

			// Define 'nbf' (Not Before) if a value exists in either data or defaults.
			// The value from 'data' has priority over 'defaultValues'.
			if (data.nbf !== undefined || defaultValues.nbf !== undefined) {
				jwt = jwt.setNotBefore(data.nbf ?? defaultValues.nbf!)
			}

			// Define 'exp' (Expiration Time) using the same priority logic.
			if (data.exp !== undefined || defaultValues.exp !== undefined) {
				jwt = jwt.setExpirationTime(data.exp ?? defaultValues.exp!)
			}

			// Define 'iat' (Issued At). If a specific value is provided, use it.
			// Otherwise, if the claim is just marked as true, set it to the current time.
			if (defaultValues.iat !== false || data.iat !== false) {
				jwt = jwt.setIssuedAt(new Date())
			}

			return jwt.sign(key)
		},
		async verify(
			jwt?: string
		): Promise<
			| (UnwrapSchema<Schema, ClaimType> &
					JWTPayloadSpec)
			| false
		> {
			if (!jwt) return false

			try {
				const data: any = (await jwtVerify(jwt, key)).payload

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
