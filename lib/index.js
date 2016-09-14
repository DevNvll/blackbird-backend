import express from 'express'
import bodyParser from 'body-parser'
import jwt from 'jsonwebtoken'
import _ from 'lodash'
import config from './config.json'
import db from './db.json'
const port = process.env.PORT || 3000

let app = express()
app.set('secret', config.secret)
app.use(bodyParser.urlencoded({
    extended: false
}))
app.use(bodyParser.json())
const routes = express.Router()

let users = db

app.get('/', (req, res) => {
    res.send('API path is http://localhost:' + port + '/api')
})

routes.post('/auth', (req, res) => {
    let user = _.find(users, {
        username: req.body.user || req.query.user
    })
    if (!user) {
        res.status(403).json({
            success: false,
            message: 'Authentication failed. User not found.'
        })
    } else if (user) {
        if (user.password !== req.body.password && user.password !== req.query.password) {
            res.status(403).json({
                success: false,
                message: 'Authentication failed. Wrong password.'
            })
        } else {
            let token = jwt.sign(user, app.get('secret'))
            res.header('token', token)
            res.json({
                success: true,
                message: 'Success!',
                token: token
            })
        }

    }
})

routes.use((req, res, next) => {
    let token = req.body.token || req.query.token || req.headers['x-access-token']
    if (token) {
        jwt.verify(token, app.get('secret'), (err, decoded) => {
            if (err) {
                return res.json({
                    success: false,
                    message: 'Failed to authenticate token.'
                });
            } else {
                req.decoded = decoded
                next()
            }
        })
    } else {
        return res.status(403).send({
            success: false,
            message: 'No token provided.'
        })
    }
})

routes.get('/', (req, res) => {
    res.json({
        message: 'Welcome to the API. Available paths: /users'
    })
})

routes.get('/users', (req, res) => {
    res.json(users)
})

app.use('/api', routes)

app.listen(port)
