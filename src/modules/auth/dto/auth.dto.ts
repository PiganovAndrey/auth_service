import { ApiProperty } from "@nestjs/swagger";
import { IsJWT, IsNotEmpty } from "class-validator";

export class AuthDto {
    @IsJWT()
    @IsNotEmpty()
    @ApiProperty({example: 'JWT token', description: 'Токен JWT'})
    accessToken: string;
    @IsJWT()
    @IsNotEmpty()
    @ApiProperty({example: 'JWT token', description: 'Токен JWT'})
    refreshToken: string;
}
