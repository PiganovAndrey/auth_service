import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { DatabaseModule } from '../database/database.module';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { ConfigService } from '@nestjs/config';
import { CacheModule } from '@nestjs/cache-manager';
// import * as redisStore from 'cache-manager-redis-store';
import { RedisClientOptions } from '@redis/client';

const configService = new ConfigService();
const KAFKA_BROKERS = configService.get<string>('KAFKA_BROKERS');

@Module({
  imports: [
    DatabaseModule,
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
                }
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
    ]),
    CacheModule.register<RedisClientOptions>({
        store: 'redis',
        url: 'redis://@localhost:6378/',
      }),
  ],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}
