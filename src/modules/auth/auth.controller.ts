import {
    Controller,
    Get,
    Post,
    Body,
    UseInterceptors,
    Inject,
    LoggerService,
    OnModuleInit,
    HttpException,
    HttpStatus,
    UseGuards,
    Req
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoggingInterceptor } from 'src/common/interceptors/LoggingInterceptor';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';
import { ClientKafka, KafkaRetriableException, MessagePattern, Payload } from '@nestjs/microservices';
import { CheckMobileDto } from './dto/check.mobile.dto';
import { CheckMailDto } from './dto/check.mail.dto';
import { CheckMailCodeDto } from './dto/check.mail.code.dto';
import { VerifyTokenDto } from './dto/verifyt.dto';
import { LoginMobileDto } from './dto/login.mobile.dto';
import { UserCreateDto } from './dto/user.create.dto';
import { LoginAdminDto } from './dto/login.admin.dto';
import { SessionGuard } from 'src/guards/session.guard';
import ITokenData from 'src/common/interfaces/token.data';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { Roles } from 'src/common/decorators/roles.decorator';
import { Role } from 'src/common/enums/roles.enums';
import { SessionData } from './dto/session.data';
import { JwtService } from '@nestjs/jwt';
import { ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';

@ApiTags('auth')
@Controller()
@UseInterceptors(LoggingInterceptor)
export class AuthController implements OnModuleInit {
    constructor(
        private readonly authService: AuthService,
        @Inject(WINSTON_MODULE_NEST_PROVIDER) private readonly logger: LoggerService,
        @Inject('USER_MOBILE_SERVICE') private readonly clientUser: ClientKafka,
        @Inject('USER_ADMIN_SERVICE') private readonly clientAdmin: ClientKafka,
        @Inject(CACHE_MANAGER) private cacheManager: Cache,
        private readonly jwtService: JwtService,
    ) {}

    async onModuleInit() {
        this.clientUser.subscribeToResponseOf('user.get');
        this.clientUser.subscribeToResponseOf('user.exists');
        this.clientUser.subscribeToResponseOf('user.exists.uid');
        this.clientUser.subscribeToResponseOf('user.login');
        this.clientUser.subscribeToResponseOf('user.register');
        this.clientAdmin.subscribeToResponseOf('admin.login');
        this.clientAdmin.subscribeToResponseOf('admin.exists');

        await this.clientUser.connect();
        await this.clientAdmin.connect()
    }

    @Post('/check')
    @Roles(Role.ALL)
    @ApiOperation({summary: 'Позволяет получить смс код, по которому входить в приложене'})
    @ApiBody({type: CheckMobileDto, description: 'Пример данных'})
    @ApiResponse({status: 200, description: 'Возвращает смс код', type: String})
    async checkPhone(@Body() checkMobile: CheckMobileDto) {
        try {
            const result = await this.authService.checkPhone(checkMobile);
            return result;
        } catch (error) {
            this.logger.error(`Error in AuthController, checkPhone: ${error}`);
            throw new HttpException(error, HttpStatus.BAD_REQUEST);
        }
    }

    @Post('/admin/check')
    @Roles(Role.ALL)
    @ApiOperation({summary: 'Позволяет проверить email адрес админа, получить код на email'})
    @ApiBody({type: CheckMailDto, description: 'Пример данных'})
    @ApiResponse({status: 200, description: 'Возвращает mail code', type: String})
    async checkMail(@Body() checkAdmin: CheckMailDto) {
        try {
            const result = await this.authService.checkMail(checkAdmin);
            return result;
        } catch (error) {
            this.logger.error(`Error in AuthController, checkMail: ${error}`);
            throw new HttpException(error, HttpStatus.BAD_REQUEST);
        }
    }

    @MessagePattern('auth.admin.check')
    @Roles(Role.ALL)
    async kafkaCheckMail(@Payload() data: CheckMailDto) {
        try{
            const result = await this.authService.checkMail(data);
            return result;
        } catch (error) {
            this.logger.error(`Error in AuthController, checkMail: ${error}`);
            throw new KafkaRetriableException('Error check mail');
        }
    }

    @Post('/admin/code')
    @Roles(Role.ALL)
    @ApiOperation({summary: 'Позволяет проверить email code'})
    @ApiBody({type: CheckMailCodeDto, description: 'Пример данных'})
    @ApiResponse({status: 200, description: 'Возвращает true или false, подошел код или нет', type: Boolean})
    async checkMailCode(@Body() dto: CheckMailCodeDto) {
        try {
            const result = await this.authService.checkMailCode(dto);
            return result;
        } catch (error) {
            this.logger.error(`Error in AuthController, checkMailCode: ${error}`);
            throw new HttpException(error, HttpStatus.BAD_REQUEST);
        }
    }

    
    @MessagePattern('auth.admin.code')
    @Roles(Role.ALL)
    async kafkaCheckMailCode(@Payload() data: CheckMailCodeDto) {
        try{
            const result = await this.authService.checkMailCode(data);
            return result;
        } catch (error) {
            this.logger.error(`Error in AuthController, checkMailCode: ${error}`);
            throw new KafkaRetriableException('Error checkMailCode');
        }
    }

    @Post('/verify-token')
    @Roles(Role.ALL)
    @ApiOperation({summary: 'Позволяет проверить токен jwt'})
    @ApiBody({type: VerifyTokenDto, description: 'Пример данных'})
    @ApiResponse({status: 200, description: 'Возвращает валидность токена и декодерует этот токен'})
    async verifyToken(@Body() dto: VerifyTokenDto) {
        try {
            const result = await this.authService.verifyToken(dto);
            if (!result) {
                return { valid: false, error: 'Invalid token' };
            }
            return { valid: true, decoded: result };
        } catch (error) {
            this.logger.error(`Error in AuthController, verifyToken: ${error}`, error);
            throw new HttpException(error, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Post('/login')
    @Roles(Role.ALL)
    @ApiOperation({summary: 'Метод позволяет залогиниться и получить токены для входа в приложение'})
    @ApiBody({type: LoginMobileDto, description: 'Пример данных'})
    @ApiResponse({status: 200, description: 'Возвращает refreshToken и accessToken'})
    async login(@Body() loginDto: LoginMobileDto) {
        try {
            const result = await this.authService.login(loginDto);
            return result;
        } catch (error) {
            this.logger.error(`Error in AuthController, login: ${error}`);
            throw new HttpException(error, HttpStatus.BAD_REQUEST);
        }
    }

    @Post('/refresh')
    @Roles(Role.ALL)
    @ApiOperation({summary: 'Метод позволяет получить новые токены на основе refreshToken'})
    @ApiBody({type: String, description: 'Принимает refreshToken'})
    @ApiResponse({status: 200, description: 'Возвращает новые токены - refreshToken и accessToken'})
    async refresh(@Body('refreshToken') refreshToken: string) {
        try {
            const result = await this.authService.refreshToken(refreshToken);
            return result;
        } catch (error) {
            this.logger.error(`Error in AuthController, refresh: ${error}`);
            throw new HttpException('Internal Server Error', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Post('/register')
    @Roles(Role.ALL)
    @ApiOperation({summary: 'Позволяет зарегистрировать нового пользователя'})
    @ApiBody({type: UserCreateDto, description: 'Пример данных создания пользователя'})
    @ApiResponse({status: 200, description: 'Возвращает данные созданного пользователя'})
    async register(@Body() userDto: UserCreateDto) {
        try {
            const result = await this.authService.createUserMobile(userDto);
            return result;
        } catch (error) {
            this.logger.error(`Error in AuthController, register: ${error}`);
            throw new HttpException('Internal Server Error', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Post('/admin/login')
    @Roles(Role.ALL)
    @ApiOperation({summary: 'Позволяет войти админ пользователю'})
    @ApiBody({type: LoginAdminDto, description: 'Пример данны для входа в админ панель'})
    @ApiResponse({status: 200, description: 'Возвращает токены acceessToken и refreshToken для входа в админ панель'})
    async loginAdmin(@Body() loginDto: LoginAdminDto) {
        try {
            const result = await this.authService.loginAdmin(loginDto);
            return result;
        } catch (error) {
            this.logger.error(`Error in AuthController, loginAdmin: ${error}`);
            throw new HttpException(error, HttpStatus.BAD_REQUEST);
        }
    }

    @Get('/logout')
    @Roles(Role.ALL)
    @ApiOperation({summary: 'Позволяет выйти из приложения'})
    @ApiResponse({status: 200, description: 'Возвращает сообщение об успешном выходе'})
    @UseGuards(SessionGuard)
    async logout(@Req() req: Request) {
        try {
            const user: ITokenData = req['sessionData'];
            if (user) {
                await this.cacheManager.del(`user_${user.userUid}_${user.clientId}`);
            }
            return { message: 'Logout successful' };
        } catch (error) {
            this.logger.error(`Error in AuthController, logout: ${error}`);
            throw new HttpException('Internal Server Error', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @MessagePattern('auth.session')
    @Roles(Role.ALL)
    async kafkaSession(@Payload() data: SessionData) {
        const {accessToken, refreshToken} = data.authorization;
        if (!accessToken && refreshToken) {
            throw new KafkaRetriableException('Пользователь не авторизован');
        }
        const user = this.jwtService.verify<ITokenData>(accessToken);
        if (user) {
            return user;
        }
        return null;
    }

    @Get('/session')
    @ApiOperation({summary: 'Позволяет получить данные из своей сессии'})
    @ApiResponse({status: 200, description: 'Возвращает данные вашей сессии'})
    @UseGuards(SessionGuard)
    @Roles(Role.ALL)
    async session(@Req() req: Request) {
        const user = req['sessionData'];
        if(!user) {
            return null;
        }
        return user;
    }
}
