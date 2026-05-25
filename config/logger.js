// config/logger.js
// Week 4: Real-time Security Monitoring with Winston
const { createLogger, format, transports } = require('winston');
const path = require('path');

const fmt = format.printf(({ level, message, timestamp, ...meta }) => {
  let log = `[${timestamp}] [${level.toUpperCase()}] ${message}`;
  if (Object.keys(meta).length) log += ' | ' + JSON.stringify(meta);
  return log;
});

const logger = createLogger({
  level: 'info',
  format: format.combine(format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), fmt),
  transports: [
    new transports.Console({ format: format.combine(format.colorize(), format.timestamp({ format: 'HH:mm:ss' }), fmt) }),
    new transports.File({ filename: path.join(__dirname, '../logs/combined.log') }),
    new transports.File({ filename: path.join(__dirname, '../logs/error.log'), level: 'error' })
  ]
});

const securityLogger = createLogger({
  level: 'warn',
  format: format.combine(format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), fmt),
  transports: [
    new transports.Console({ format: format.combine(format.colorize(), format.timestamp({ format: 'HH:mm:ss' }), fmt) }),
    new transports.File({ filename: path.join(__dirname, '../logs/security.log') })
  ]
});

module.exports = { logger, securityLogger };
