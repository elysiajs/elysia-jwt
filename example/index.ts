import { Elysia, t } from 'elysia'
import { jwt } from '../src'

const app = new Elysia()
    .use(
        jwt({
            name: 'jwt2',
            secret: 'aawdaowdoj',
            sub: 'auth',
            iss: 'saltyaom.com',
            exp: '7d',
            schema: t.Object({
                name: t.String()
            })
        })
    )
    .get('/sign/:name', async ({ jwt2, cookie: { auth }, params }) => {
        auth.set({
            value: await jwt2.sign(params),
            httpOnly: true,
            maxAge: 7 * 86400
        })

        return `Sign in as ${auth.value}`
    })
    .get('/profile', async ({ jwt2, set, cookie: { auth } }) => {
        const profile = await jwt2.verify(auth.value)

        if (!profile) {
            set.status = 401
            return 'Unauthorized'
        }

        return `Hello ${profile.name}`
    })
    .listen(8080)
