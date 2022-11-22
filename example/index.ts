import KingWorld, { t } from 'kingworld'
import { cookie } from '@kingworldjs/cookie'

import jwt from '../src/index'

const app = new KingWorld()
    .use(
        jwt({
            name: 'jwt',
            secret: 'aawdaowdoj',
            sub: 'auth',
            iss: 'saltyaom.com',
            nbf: '2h',
            schema: t.Object({
                name: t.String()
            })
        })
    )
    .use(cookie)
    .get('/', () => 'JWT Example')
    .get('/sign/:name', async ({ jwt, cookie, setCookie, params }) => {
        setCookie('auth', await jwt.sign(params))

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
