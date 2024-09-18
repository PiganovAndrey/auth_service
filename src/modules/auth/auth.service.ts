import {
    BadRequestException,
    Inject,
    Injectable,
    LoggerService,
    NotFoundException,
    UnauthorizedException
} from '@nestjs/common';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';
import { DatabaseService } from '../database/database.service';
import { ClientKafka } from '@nestjs/microservices';
import { JwtService } from '@nestjs/jwt';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { VerifyTokenDto } from './dto/verifyt.dto';
import ITokenData from 'src/common/interfaces/token.data';
import { LoginMobileDto } from './dto/login.mobile.dto';
import { UserCreateDto } from './dto/user.create.dto';
import { LoginAdminDto } from './dto/login.admin.dto';
import { UserAdminData } from 'src/common/interfaces/user.admin.data';
import { CheckMobileDto } from './dto/check.mobile.dto';
import { CheckMailDto } from './dto/check.mail.dto';
import { CheckMailCodeDto } from './dto/check.mail.code.dto';
import IRefreshTokenData from 'src/common/interfaces/refreshToken.data';
import { lastValueFrom } from 'rxjs';

@Injectable()
export class AuthService {
    constructor(
        private readonly prisma: DatabaseService,
        @Inject(WINSTON_MODULE_NEST_PROVIDER) private readonly logger: LoggerService,
        @Inject('USER_MOBILE_SERVICE') private readonly clientUser: ClientKafka,
        @Inject('USER_ADMIN_SERVICE') private readonly clientAdmin: ClientKafka,
        private readonly jwtService: JwtService,
        @Inject(CACHE_MANAGER) private cacheManager: Cache
    ) {}

    async verifyToken(dto: VerifyTokenDto) {
        try {
            this.logger.log(`Verifying token for user: ${dto.accessToken}`);
            const decoded = this.jwtService.decode(dto.accessToken) as ITokenData;
            const userKey = await this.cacheManager.get(`user_${decoded.userUid}_${decoded.clientId}`);
            const expiration = decoded.exp * 1000;

            if (expiration < Date.now()) {
                const tokens = await this.refreshToken(dto.refreshToken, decoded.role);
                this.logger.log(`Token refreshed for user: ${decoded.userUid}`);
                return tokens;
            }

            if (userKey !== 'valid') {
                throw new UnauthorizedException('Invalid userUid or client ID in access token');
            }

            return decoded;
        } catch (error) {
            this.logger.error(`Error verifying token: ${error}`, error);
            throw new UnauthorizedException('Error access token');
        }
    }

    async login(loginDto: LoginMobileDto) {
        try {
            this.logger.log(`Logging in user with phone number: ${loginDto.phone_number}`);
            if (!loginDto.phone_number || !loginDto.sms_code) {
                throw new BadRequestException('Phone number or SMS code not provided');
            }
            const user = await lastValueFrom(this.clientUser.send('user.login', JSON.stringify(loginDto)));

            if (!user) {
                throw new UnauthorizedException('Failed to retrieve user data');
            }

            if (!(await this.checkSmsCode(loginDto))) {
                throw new UnauthorizedException('Invalid SMS code');
            }

            const tokens = await this.generateTokens(user.userUid, user.role);

            return tokens;
        } catch (error) {
            this.logger.error(`Error logging in user: ${error}`, error);
            throw new UnauthorizedException('Login error');
        }
    }

    async generateTokens(userUid: string, role: string) {
        try {
            this.logger.log(`Generating tokens for user: ${userUid}`);
            const clientId = userUid
                .split('')
                .filter((_, index) => index % 2 === 1)
                .join('');
            const tokenData: ITokenData = { userUid, role, timestampt: Date.now().toString(), clientId };

            const accessToken = this.jwtService.sign(tokenData, {expiresIn: '4d'});
            const refreshToken = this.jwtService.sign(tokenData, { expiresIn: '7d' });

            await this.cacheManager.set(`user_${userUid}_${clientId}`, 'valid', 60 * 60 * 24 * 14);
            await this.cacheManager.set(
                `refresh_${refreshToken}`,
                JSON.stringify({ userUid, clientId, expiration: Date.now() + 7 * 24 * 60 * 60 * 1000 }),
                60 * 60 * 24 * 14
            );

            this.logger.log(`Tokens generated for user: ${userUid}`);
            return { accessToken, refreshToken, ext: 60 * 60 * 24 * 7 };
        } catch (error) {
            this.logger.error(`Error generating tokens: ${error}`);
            throw new UnauthorizedException('Token generation error');
        }
    }

    async refreshToken(refreshToken: string, role: string | null = null): Promise<VerifyTokenDto> {
        if (!refreshToken) {
            throw new UnauthorizedException('No refresh token provided');
        }

        try {
            this.logger.log(`Refreshing token`);
            const decoded = this.jwtService.decode(refreshToken) as IRefreshTokenData;
            const storedRefreshToken = await this.cacheManager.get(`refresh_${refreshToken}`);

            if (!storedRefreshToken) {
                throw new UnauthorizedException('Invalid refresh token');
            }

            const { userUid, clientId, expiration } = JSON.parse(storedRefreshToken as string);
            if (Date.now() > expiration) {
                throw new UnauthorizedException('Refresh token expired');
            }

            const userKey = await this.cacheManager.get(`user_${userUid}_${clientId}`);
            if (userKey !== 'valid') {
                throw new UnauthorizedException('Invalid userUid or client ID');
            }

            const tokens = await this.generateTokens(userUid, role || decoded.role);
            await this.cacheManager.del(`refresh_${refreshToken}`);

            this.logger.log(`Token refreshed for user: ${userUid}`);
            return tokens;
        } catch (error) {
            this.logger.error(`Error refreshing token: ${error}`);
            throw new UnauthorizedException('Error refreshing token');
        }
    }

    async createUserMobile(dto: UserCreateDto) {
        try {
            this.logger.log(`Creating mobile user: ${dto}`);
            const user = await lastValueFrom(this.clientUser.send('user.register', JSON.stringify(dto)));

            if(!user) {
                throw new BadRequestException('Registration Error');
            }

            this.logger.log(`User created with UID: ${user.userUid}`);
            return this.generateTokens(user.userUid, user.role);
        } catch (error) {
            this.logger.error(`Error registering mobile user: ${JSON.stringify(error)}`);
            throw new BadRequestException('Registration error');
        }
    }

    async loginAdmin(loginDto: LoginAdminDto) {
        try {
            this.logger.log(`Logging in admin with email: ${loginDto.email}`);
            if (!loginDto.email || !loginDto.password) {
                throw new BadRequestException('Email or password not provided');
            }
            const data : UserAdminData= await lastValueFrom(this.clientAdmin.send('admin.login', loginDto));

            if (!data) {
                throw new UnauthorizedException('Failed to retrieve user data');
            }

            this.logger.log(`Admin logged in: ${data.uid}`);
            return this.generateTokens(data.uid, data.role);
        } catch (error) {
            this.logger.error(`Error logging in admin: ${error}`);
            throw new UnauthorizedException('Admin login error');
        }
    }

    async checkPhone(dto: CheckMobileDto): Promise<string> {
        try {
            this.logger.log(`Checking phone number: ${dto.phone_number}`);
            const user = await lastValueFrom(this.clientUser.send('user.exists', JSON.stringify(dto)));
            if (!user.result) {
                throw new NotFoundException('Phone number not registered');
            }

            this.logger.log(`Phone number valid: ${dto.phone_number}`);
            return this.sendSmsCode(dto);
        } catch (error) {
            this.logger.error(`Error checking phone number: ${error}`);
            throw new BadRequestException('Error checking phone');
        }
    }

    async checkMail(dto: CheckMailDto): Promise<string> {
        try {
            this.logger.log(`Checking email: ${dto.mail}`);
            const response = await lastValueFrom(this.clientAdmin.send('admin.exists', dto));

            if (!response.result) {
                throw new NotFoundException('Email not registered');
            }

            this.logger.log(`Email valid: ${dto.mail}`);
            return this.sendMailCode(dto);
        } catch (error) {
            this.logger.error(`Error checking email: ${error}`);
            throw new BadRequestException('Error checking email');
        }
    }

    async sendSmsCode(dto: CheckMobileDto): Promise<string> {
        const code = '111111'; // Генерация кода

        try {
            this.logger.log(`Sending SMS code to phone number: ${dto.phone_number}`);
            await this.prisma.sms_codes.upsert({
                where: { phone_number: dto.phone_number },
                update: { sms_code: code },
                create: { phone_number: dto.phone_number, sms_code: code }
            });

            this.logger.log(`SMS code sent to phone number: ${dto.phone_number}`);
            return code;
        } catch (error) {
            this.logger.error(`Error sending SMS code: ${error}`);
            throw new BadRequestException('Error sending SMS code');
        }
    }

    async checkSmsCode(dto: LoginMobileDto): Promise<boolean> {
        try {
            this.logger.log(`Checking SMS code for phone number: ${dto.phone_number}`);
            const code = await this.prisma.sms_codes.findUnique({
                where: { phone_number: dto.phone_number }
            });

            const isValid = code && code.sms_code === dto.sms_code;
            this.logger.log(`SMS code valid: ${isValid}`);
            return isValid;
        } catch (error) {
            this.logger.error(`Error checking SMS code: ${error}`);
            throw new BadRequestException('Error checking SMS code');
        }
    }

    async sendMailCode(dto: CheckMailDto): Promise<string> {
        const code = '111111'; // Генерация кода

        try {
            this.logger.log(`Sending mail code to email: ${dto.mail}`);
            await this.prisma.mail_codes.upsert({
                where: { mail: dto.mail },
                update: { code },
                create: { mail: dto.mail, code }
            });

            this.logger.log(`Mail code sent to email: ${dto.mail}`);
            return code;
        } catch (error) {
            this.logger.error(`Error sending mail code: ${error}`);
            throw new BadRequestException('Error sending mail code');
        }
    }

    async checkMailCode(dto: CheckMailCodeDto): Promise<boolean> {
        try {
            this.logger.log(`Checking mail code for email: ${dto.email}`);
            const mailCode = await this.prisma.mail_codes.findUnique({
                where: { mail: dto.email }
            });

            if (mailCode && mailCode.code === dto.code) {
                if (dto.newEmail) {
                    await this.prisma.mail_codes.update({
                        where: { mail: dto.email },
                        data: { mail: dto.newEmail }
                    });
                }
                this.logger.log(`Mail code valid`);
                return true;
            }

            this.logger.log(`Mail code invalid`);
            return false;
        } catch (error) {
            this.logger.error(`Error checking mail code: ${error}`);
            throw new BadRequestException('Error checking mail code');
        }
    }
}
