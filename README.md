# @elysiajs/static

Plugin for [Elysia](https://github.com/elysiajs/elysia) for using JWT Authentication.

## Installation

```bash
bun add @elysiajs/jwt
```

## Example

```typescript
import { Elysia, t } from 'elysia';
import { jwt } from '@elysiajs/jwt';
import { cookie } from '@elysiajs/cookie';

const app = new Elysia()
  .use(
    jwt({
      name: 'jwt',
      // This should be Environment Variable
      secret: 'MY_SECRETS',
    })
  )
  .use(cookie())
  .get('/sign/:name', async ({ jwt, cookie, setCookie, params }) => {
    setCookie('auth', await jwt.sign(params), {
      httpOnly: true,
    });

    return `Sign in as ${params.name}`;
  })
  .get('/profile', async ({ jwt, set, cookie: { auth } }) => {
    const profile = await jwt.verify(auth);

    if (!profile) {
      set.status = 401;
      return 'Unauthorized';
    }

    return `Hello ${profile.name}`;
  })
  .listen(8080);
```

## Config

This package extends [jose](https://github.com/panva/jose), most config is inherited from Jose.

Below are configurable properties for using JWT plugin

### name

Name to decorate method as:

For example, `jwt` will decorate Context with `Context.jwt`

### secret

JWT secret key

### schema

Type strict validation for JWT payload

## Jose's config

Below is the config inherits from [jose](https://github.com/panva/jose)

### alg

@default 'HS256'

Algorithm to sign JWT with

### crit

Critical Header Parameter.

### iss

JWT Issuer

@see [RFC7519#section-4.1.1](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1)

### sub

JWT Subject

@see [RFC7519#section-4.1.2](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2)

### aud

JWT Audience

@see [RFC7519#section-4.1.3](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3)

### jti

JWT ID

@see [RFC7519#section-4.1.7](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7)

### nbf

JWT Not Before

@see [RFC7519#section-4.1.5](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5)

### exp

JWT Expiration Time

@see [RFC7519#section-4.1.4](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4)

### iat

JWT Issued At

@see [RFC7519#section-4.1.6](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6)
