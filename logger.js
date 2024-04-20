const winston = require('winston');

// Configure Winston logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.json()
    ),
    transports: [
      new winston.transports.Console(),
      new winston.transports.File({ filename: 'combined.log' })
    ]
  });

// Handle uncaught exceptions
process.on('uncaughtException', (ex) => {
    logger.error('An uncaught exception occurred: ', ex);
    process.exit(1);
  });
  
  // Handle unhandled promise rejections
  process.on('unhandledRejection', (ex) => {
    logger.error('An unhandled rejection occurred: ', ex);
    process.exit(1);
});

module.exports ={
    logger,
}