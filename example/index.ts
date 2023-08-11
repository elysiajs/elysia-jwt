import { Elysia, t } from 'elysia'
import { cookie } from '@elysiajs/cookie'
import { jwt } from '../src'

const app = new Elysia()
    .use(
        jwt({
            secret: 'aawdaowdoj',
            sub: 'auth',
            iss: 'saltyaom.com',
            exp: '7d',
            schema: t.Object({
                name: t.String()
            })
        })
    )
    .use(cookie())
    .get('/sign/:name', async ({ jwt, cookie, setCookie, params }) => {
        setCookie('auth', await jwt.sign(params), {
            httpOnly: true,
            maxAge: 7 * 86400
        })

        return `Sign in as ${cookie.auth}`
    })
    .get('/profile', async ({ jwt, set, cookie: { auth } }) => {
        const profile = await jwt.verify(auth)

        if (!profile) {
            set.status = 401
            return 'Unauthorized'
        }

        return `Hello ${profile.name}`
    })
    .listen(8080)
