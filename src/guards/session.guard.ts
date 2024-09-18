import {
    Injectable,
    CanActivate,
    ExecutionContext,
    HttpException,
    HttpStatus,
    ForbiddenException
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { JwtService } from '@nestjs/jwt';
import ITokenData from 'src/common/interfaces/token.data';

@Injectable()
export class SessionGuard implements CanActivate {
    constructor(
        private readonly jwtService: JwtService,
        private readonly reflector: Reflector
    ) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest<Request>();
        const authHeader = request.headers.authorization;

        if (!authHeader) {
            throw new HttpException('Пользователь не авторизован', HttpStatus.UNAUTHORIZED);
        }

        const token = this.extractToken(authHeader);
        if (!token) {
            throw new HttpException('Пользователь не авторизован', HttpStatus.UNAUTHORIZED);
        }

        try {
            const decodedToken = this.jwtService.verify<ITokenData>(token);
            request['sessionData'] = decodedToken; // Добавляем данные пользователя в запрос
            const requiredRoles = this.reflector.get<string[]>('roles', context.getHandler());

            if (
                requiredRoles &&
                !this.hasRequiredRole(decodedToken.role, requiredRoles) &&
                !requiredRoles.includes('all')
            ) {
                throw new ForbiddenException('You do not have the required role to access this resource');
            }

            return true;
        } catch (error) {
            throw new HttpException('Пользователь не авторизован', HttpStatus.UNAUTHORIZED);
        }
    }

    private extractToken(authHeader: string): string | null {
        const parts = authHeader.split(' ');
        return parts[1]
    }

    private hasRequiredRole(userRole: string, requiredRoles: string[]): boolean {
        return requiredRoles.includes(userRole);
    }
}
