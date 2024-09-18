export default () => ({
    port: parseInt(process.env.PORT, 10) || 5007,
    environment: process.env.NODE_ENV || 'development',
    databaseUrl: process.env.DATABASE_URL || '',
    logLevel: process.env.LOG_LEVEL,
    kafkaBroker: process.env.KAFKA_BROKER,
    kafkaBrokers: process.env.KAFKA_BROKERS,
    kafkaClientId: process.env.KAFKA_CLIENT_ID,
    secretKey: process.env.SECRET_KEY,
    kafkaGroupId: process.env.KAFKA_GROUP_ID,
    jwtIssuer: process.env.JWT_ISSUER,
    jwtAudience: process.env.JWT_AUDIENCE,
    secretRefreshKey: process.env.SECRET_REFRESH_KEY,
    queueName: process.env.QUEUE_NAME,
    redisPort: process.env.REDIS_PORT,
    redisHost: process.env.REDIS_HOST,
    redisSecret: process.env.REDIS_SECRET,
    redisUrl: process.env.REDIS_URL
});
