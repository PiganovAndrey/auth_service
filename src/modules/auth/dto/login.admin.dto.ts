import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsNotEmpty, IsOptional, IsString } from "class-validator";

export class LoginAdminDto {
    @IsEmail()
    @IsNotEmpty()
    @ApiProperty({example: 'persnf.tstat@mail.ru', description: 'Ваше email для входа'})
    email: string;
    @IsString()
    @IsNotEmpty()
    @ApiProperty({example: 'password', description: 'Ваш пароль для входа'})
    password: string;
    @IsOptional()
    @IsString()
    code?: string;
    @IsEmail()
    @IsOptional()
    newEmail?: string;
}
