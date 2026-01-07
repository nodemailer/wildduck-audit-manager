'use strict';

const config = require('wild-config');
const express = require('express');
const logger = require('./logger');
const shortid = require('shortid');
const cookieParser = require('cookie-parser');
const path = require('path');
const hbs = require('hbs');
const csurf = require('csurf');
const db = require('./db');
const bodyParser = require('body-parser');
const session = require('express-session');
const RedisStore = require('connect-redis')(session);
const flash = require('connect-flash');
const pinoHttp = require('pino-http');
const passport = require('./passport');

const routesRoot = require('../routes/root');

module.exports.start = async () => {
    await new Promise((resolve, reject) => {
        const app = express();
        const expressPino = pinoHttp({
            logger: logger.child({ component: 'web' }),
            genReqId: () => shortid.generate()
        });

        const csrf = csurf({
            cookie: true
        });

        // logger
        app.use(expressPino);

        // view engine setup
        app.set('views', path.join(__dirname, '..', 'views'));
        app.set('view engine', 'hbs');
        hbs.registerPartials(path.join(__dirname, '..', 'views', 'partials'), err => {
            if (err) {
                logger.error({ msg: 'Failed to load partials', err });
            }
        });

        hbs.registerHelper('csrf_token', function () {
            // eslint-disable-next-line no-invalid-this
            const _csrf = this._csrf;
            if (!_csrf) {
                return '';
            }
            return new hbs.handlebars.SafeString(`<input type="hidden" name="_csrf" value="${_csrf}" />`);
        });

        /**
         * We need this helper to make sure that we consume flash messages only
         * when we are able to actually display these. Otherwise we might end up
         * in a situation where we consume a flash messages but then comes a redirect
         * and the message is never displayed
         */
        hbs.registerHelper('flash_messages', function () {
            // eslint-disable-next-line no-invalid-this
            const flash = this._flash;

            if (typeof flash !== 'function') {
                return '';
            }

            let messages = flash(); // eslint-disable-line no-invalid-this
            let response = [];

            // group messages by type
            Object.keys(messages).forEach(key => {
                let rows = [];
                messages[key].forEach(message => {
                    rows.push(hbs.handlebars.escapeExpression(message));
                });
                const elm = `<div class="alert alert-${key} alert-dismissible fade show mt-1" role="alert">
            ${rows.length > 1 ? `<div>${rows.join('</div>\n<div class="mt-1">')}</div>` : rows.join('')}
            <button type="button" class="close" data-dismiss="alert" aria-label="Close">
                <span aria-hidden="true">&times;</span>
            </button>
        </div>`;
                response.push(elm);
            });

            if (!response.length) {
                return '';
            }

            return new hbs.handlebars.SafeString(`<div class="flash-messages">${response.join('\n')}</div>`);
        });

        // Handle proxies. Needed to resolve client IP
        if (config.web.proxy) {
            app.set('trust proxy', config.web.proxy);
        }

        // Do not expose software used
        app.disable('x-powered-by');

        app.use(cookieParser());
        app.use(express.static(path.join(__dirname, '..', 'public')));

        app.use(
            session({
                name: config.web.cookie.name,
                store: new RedisStore({
                    client: db.redis.duplicate()
                }),
                secret: config.web.cookie.secret,
                saveUninitialized: false,
                resave: false,
                cookie: {
                    secure: !!config.web.cookie.secure
                }
            })
        );

        app.use(flash());

        app.use(
            bodyParser.urlencoded({
                extended: true,
                limit: config.web.postSize
            })
        );

        app.use(
            bodyParser.json({
                limit: config.web.postSize
            })
        );

        passport.setup(app);

        app.use(csrf);
        app.use((req, res, next) => {
            if (req.user && !req.user.username) {
                return req.logout(err => {
                    if (err) {
                        return next(err);
                    }
                    req.flash('danger', 'Session expired, please log in');
                    return res.redirect('/');
                });
            }

            res.locals.appName = config.app.name;
            res.locals.clientUrl = config.app.clientUrl;

            res.locals.user = req.user;
            res.locals.hasAccount = !!(req.user && req.user._id);

            res.locals._flash = req.flash.bind(req);
            res.locals._csrf = req.csrfToken();
            next();
        });

        // route handling
        app.use('/', routesRoot);

        // catch 404 and forward to error handler
        app.use((req, res, next) => {
            let err = new Error('Not Found');
            err.status = 404;
            next(err);
        });

        app.use((err, req, res, next) => {
            if (!err) {
                return next();
            }

            let message;
            switch (err.restCode) {
                case 'AuthFailed':
                    message = 'Authentication failed';
                    break;

                default:
                    message = err.message;
                    break;
            }

            const code = err.status || 500;
            res.status(code);
            res.render('error', {
                code,
                message,
                error: app.get('env') !== 'production' ? err : false,
                layout: 'layouts/main'
            });
        });

        app.listen(config.web.port, config.web.host, () => {
            logger.info({ msg: 'Web server listening', port: config.web.port, host: config.web.host });
            resolve();
        });
        app.on('error', reject);
    });
};
