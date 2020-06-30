'use strict';

const config = require('wild-config');
const logger = require('./logger').child({ component: 'passport' });
const util = require('util');
const crypto = require('crypto');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const prepareUserData = (username, userData) => {
    return Object.assign(Object.assign({ username }, userData), { passwordHash: false });
};

const authenticate = async (username, password, session, ip) => {
    let userData = config.users[username];

    if (!userData || !userData.enabled || !userData.passwordHash) {
        logger.info({ msg: 'Authentication', result: 'invalid_username', username, session, ip });
        return false;
    }

    if (crypto.createHash('sha256').update(password).digest('hex').toLowerCase().trim() === userData.passwordHash.toLowerCase().trim()) {
        logger.info({ msg: 'Authentication', result: 'success', username, session, ip });
        return prepareUserData(username, userData);
    }

    logger.info({ msg: 'Authentication', result: 'fail', username, password, session, ip });
    return false;
};

module.exports.setup = app => {
    app.use(passport.initialize());
    app.use(passport.session());
};

module.exports.logout = (req, res) => {
    if (req.user) {
        req.flash('success', `${req.user.username} logged out`);
        req.logout();
    }
    res.redirect('/');
};

module.exports.login = (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            logger.error({ msg: 'Authentication failed', username: req.body.username, err });
            req.flash('danger', 'Authentication error');
            return next(err);
        }

        if (!user) {
            req.flash('danger', (info && info.message) || 'Failed to authenticate user');
            return res.redirect(`/login`);
        }

        req.logIn(user, err => {
            if (err) {
                return next(err);
            }

            if (req.body.remember) {
                // Cookie expires after 30 days
                req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
            } else {
                // Cookie expires at end of session
                req.session.cookie.expires = false;
            }

            req.flash('success', util.format('Logged in as %s', user.username));
            return res.redirect('/account');
        });
    })(req, res, next);
};

module.exports.requireLogin = (req, res, next) => {
    if (!req.user) {
        return res.redirect(`/login`);
    }
    next();
};

passport.use(
    new LocalStrategy(
        {
            passReqToCallback: true
        },
        (req, username, password, next) => {
            req.session.regenerate(() => {
                authenticate(username, password, req.session.id, req.ip)
                    .then(user => {
                        if (!user) {
                            return next(null, false, {
                                message: 'Incorrect username or password'
                            });
                        }
                        next(null, user);
                    })
                    .catch(next);
            });
        }
    )
);

passport.serializeUser((user, next) => {
    next(null, user.username);
});

passport.deserializeUser((username, next) => {
    let userData = config.users[username];

    if (!userData || !userData.enabled) {
        return next(false);
    }

    return next(null, prepareUserData(username, userData));
});
