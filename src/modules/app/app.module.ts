import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { DatabaseModule } from '../database/database.module';
import { WinstonModule } from 'nest-winston';
import { winstonConfig } from '../../config/winston.config';
import configuration from 'src/config/configuration';
import { APP_INTERCEPTOR, Reflector } from '@nestjs/core';
import { LoggingInterceptor } from 'src/common/interceptors/LoggingInterceptor';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { AuthModule } from '../auth/auth.module';
import { JwtModule } from '@nestjs/jwt';
import { CacheModule } from '@nestjs/cache-manager';
// import * as redisStore from 'cache-manager-redis-store';
import { RedisClientOptions } from '@redis/client';

const configService = new ConfigService();
const KAFKA_BROKERS = configService.get<string>('KAFKA_BROKERS');
const SECRET_KEY = configService.get<string>('SECRET_KEY');
const JWT_ISSUER = configService.get<string>('JWT_ISSUER');
const JWT_AUDIENCE = configService.get<string>('JWT_AUDIENCE');

@Module({
    imports: [
        DatabaseModule,
        AuthModule,
        JwtModule.register({
            global: true,
            secret: SECRET_KEY,
            signOptions: {
                issuer: JWT_ISSUER,
                audience: JWT_AUDIENCE,
                expiresIn: '4d'
              },
        }),
        CacheModule.register<RedisClientOptions>({
            store: 'redis',
            url: 'redis://localhost:6378/',
          }),
        ConfigModule.forRoot({
            isGlobal: true,
            load: [configuration]
        }),
        WinstonModule.forRoot({
            transports: winstonConfig.transports,
            format: winstonConfig.format,
            level: winstonConfig.level
        }),
        ClientsModule.register([
            {
                name: 'USER_MOBILE_SERVICE',
                transport: Transport.KAFKA,
                options: {
                    client: {
                        clientId: 'user_mobile-service',
                        brokers: [KAFKA_BROKERS]
                    },
                    consumer: {
                        groupId: 'user_mobile-consumer-6',
                        retry: {
                            retries: 5,
                            restartOnFailure: async () => {
                                console.error('Consumer crashed, restarting...');
                                return true;
                              },
                        }
                    },
                }
            },
            {
                name: 'USER_ADMIN_SERVICE',
                transport: Transport.KAFKA,
                options: {
                    client: {
                        clientId: 'user_admin-service',
                        brokers: [KAFKA_BROKERS]
                    },
                    consumer: {
                        groupId: 'user_admin-consumer-2',
                        retry: {
                            retries: 5,
                            restartOnFailure: async () => {
                                console.error('Consumer crashed, restarting...');
                                return true;
                              },
                        }
                    }
                }
            }
        ])
    ],
    providers: [
        Reflector,
        { provide: APP_INTERCEPTOR, useClass: LoggingInterceptor }
    ]
})
export class AppModule {}
