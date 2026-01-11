'use strict';

const openpgp = require('openpgp');
const addressparser = require('nodemailer/lib/addressparser');
const libmime = require('libmime');
const punycode = require('punycode');
const config = require('wild-config');
const pkg = require('../package.json');
const fs = require('fs');

const formatFingerprint = fingerprint => {
    if (typeof fingerprint === 'string') {
        return fingerprint.match(/.{1,2}/g).join(':');
    }

    let out = [];
    for (let nr of fingerprint) {
        out.push((nr < 0x10 ? '0' : '') + nr.toString(16).toLowerCase());
    }
    return out.join(':');
};

const signingKeyFile = fs.readFileSync(config.app.pgp.sign.key, 'utf-8');
let signFinger;
let signingKey;
let signPubKey;
openpgp
    .readKey({ armoredKey: signingKeyFile })
    .then(key => {
        if (!config.app.pgp.sign.password) {
            return key;
        }

        return openpgp.decryptKey({
            privateKey: key,
            passphrase: config.app.pgp.sign.password
        });
    })
    .then(key => {
        signingKey = key;
        signPubKey = key.toPublic().armor();
        signFinger = key.getFingerprint().substr(-16).toUpperCase();
    })
    .catch(err => {
        throw err;
    });

openpgp.config.commentString = config.app.pgp.comment || 'https://wildduck.email';
openpgp.config.versionString = config.app.pgp.version || `WildDuck Audit v${pkg.version}`;

const asyncifyRequest = middleware => async (req, res, next) => {
    try {
        await middleware(req, res, next);
    } catch (err) {
        req.log.error({ msg: 'Failed to process request', req, res, err });
        next(err);
    }
};

const asyncifyJson = middleware => async (req, res, next) => {
    try {
        await middleware(req, res, next);
    } catch (err) {
        let data = {
            error: err.message
        };

        if (err.responseCode) {
            res.status(err.responseCode);
        }

        if (err.code) {
            data.code = err.code;
        }

        req.log.error({ msg: 'Failed to process request', req, res, err });

        res.charSet('utf-8');
        res.json(data);
        return next();
    }
};

const validationErrors = validationResult => {
    const errors = {};
    if (validationResult.error && validationResult.error.details) {
        validationResult.error.details.forEach(detail => {
            if (!errors[detail.path]) {
                errors[detail.path] = detail.message;
            }
        });
    }
    return errors;
};

function normalizeDomain(domain) {
    domain = (domain || '').toLowerCase().trim();
    try {
        if (/^xn--/.test(domain)) {
            domain = punycode.toUnicode(domain).normalize('NFC').toLowerCase().trim();
        }
    } catch (E) {
        // ignore
    }

    return domain;
}

function normalizeAddress(address) {
    let user = address.substr(0, address.lastIndexOf('@')).normalize('NFC').toLowerCase().trim();
    let domain = normalizeDomain(address.substr(address.lastIndexOf('@') + 1));

    return `${user}@${domain}`;
}

async function getKeyInfo(pubKeyArmored) {
    if (!pubKeyArmored) {
        return false;
    }

    // try to encrypt something with that key
    let pubKey;
    try {
        pubKey = await openpgp.readKey({ armoredKey: prepareArmoredPubKey(pubKeyArmored), config: { tolerant: true } });
    } catch (err) {
        return false;
    }
    if (!pubKey) {
        return false;
    }

    let fingerprint = pubKey.getFingerprint();

    let { name, address } = getUserId(pubKey);

    return {
        name,
        address,
        fingerprint
    };
}

function prepareArmoredPubKey(pubKey) {
    pubKey = (pubKey || '').toString().replace(/\r?\n/g, '\n').trim();
    if (/^-----[^-]+-----\n/.test(pubKey) && !/\n\n/.test(pubKey)) {
        // header is missing, add blank line after first newline
        pubKey = pubKey.replace(/\n/, '\n\n');
    }
    return pubKey;
}

function getUserId(pubKey) {
    let name = '';
    let address = '';

    if (!pubKey || !pubKey.users || !pubKey.users.length) {
        return { name, address };
    }

    let userData = pubKey.users.find(u => u && u.userID && (u.userID.userID || u.userID.name || u.userID.email));
    if (!userData) {
        return { name, address };
    }

    name = userData.userID.name || '';
    address = userData.userID.address || '';

    if (!name || !address) {
        let user = addressparser(userData.userID.userID);
        if (user && user.length) {
            if (!address && user[0].address) {
                address = normalizeAddress(user[0].address);
            }
            if (!name && user[0].name) {
                try {
                    name = libmime.decodeWords(user[0].name || '').trim();
                } catch (E) {
                    // failed to parse value
                    name = user[0].name || '';
                }
            }
        }
    }

    return { name, address };
}

async function checkPubKey(pubKeyArmored) {
    if (!pubKeyArmored) {
        return false;
    }

    // try to encrypt something with that key
    let pubKey = await openpgp.readKey({ armoredKey: prepareArmoredPubKey(pubKeyArmored), config: { tolerant: true } });
    if (!pubKey) {
        throw new Error('Did not find key information');
    }

    let fingerprint = pubKey.getFingerprint();

    let { name, address } = getUserId(pubKey);

    let ciphertext = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: 'Hello, World!' }),
        encryptionKeys: pubKey, // for encryption
        signingKeys: signingKey, // for signing (optional)
        format: 'armored'
    });

    if (/^-----BEGIN PGP MESSAGE/.test(ciphertext)) {
        // everything checks out
        return {
            name,
            address,
            fingerprint: formatFingerprint(fingerprint)
        };
    }

    throw new Error('Unexpected message');
}

const encrypt = async (pubKeyArmored, data) => {
    if (!pubKeyArmored) {
        return false;
    }

    if (typeof data === 'string') {
        data = Buffer.from(data);
    }

    // try to encrypt something with that key
    let pubKey = await openpgp.readKey({ armoredKey: prepareArmoredPubKey(pubKeyArmored), config: { tolerant: true } });
    if (!pubKey) {
        throw new Error('Did not find key information');
    }

    return await openpgp.encrypt({
        message: await openpgp.createMessage({ binary: data }),
        encryptionKeys: pubKey, // for encryption
        signingKeys: signingKey, // for signing (optional)
        format: 'armored',
        config: { preferredCompressionAlgorithm: openpgp.enums.compression.zlib }
    });
};

module.exports = {
    asyncifyRequest,
    asyncifyJson,
    validationErrors,
    getKeyInfo,
    checkPubKey,
    encrypt,
    signFinger: () => signFinger,
    signPubKey: () => signPubKey
};
