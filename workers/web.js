'use strict';

/* eslint global-require: 0 */

const cluster = require('cluster');
const logger = require('../lib/logger');
const config = require('wild-config');
const audits = require('../lib/audits');

const workerName = 'web';

let closing = false;
const closeProcess = code => {
    if (closing) {
        return;
    }
    closing = true;
    setTimeout(() => {
        process.exit(code);
    }, 10);
};

process.on('uncaughtException', () => closeProcess(1));
process.on('unhandledRejection', () => closeProcess(2));
process.on('SIGTERM', () => closeProcess(0));
process.on('SIGINT', () => closeProcess(0));

if (cluster.isMaster) {
    logger.warn({ msg: 'Master process running', workerName });

    const fork = () => {
        if (closing) {
            return;
        }
        let worker = cluster.fork();
        worker.on('online', () => {
            logger.warn({ msg: 'Worker came online', workerName, worker: worker.process.pid });
        });
    };

    for (let i = 0; i < config.web.workers; i++) {
        fork();
    }

    cluster.on('exit', (worker, code, signal) => {
        if (closing) {
            return;
        }
        logger.warn({ msg: 'Worker died', workerName, worker: worker.process.pid, code, signal });
        setTimeout(() => fork(), 2000).unref();
    });
} else {
    const config = require('wild-config');
    process.title = `${config.process.title}:${workerName}`;
    const logger = require('../lib/logger').child({ component: 'web' });
    const db = require('../lib/db');
    const webApp = require('../lib/web-app');

    const init = async () => {
        await db.connect();
        audits.init();
        await webApp.start();
    };

    init().catch(err => {
        logger.error(err);
        closeProcess(3);
    });
}
