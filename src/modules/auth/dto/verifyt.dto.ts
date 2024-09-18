import { IsInt, IsJWT, IsNotEmpty, IsOptional } from "class-validator";

export class VerifyTokenDto {
    @IsJWT()
    @IsNotEmpty()
    accessToken: string;
    @IsJWT()
    @IsNotEmpty()
    refreshToken: string;
    @IsInt()
    @IsOptional()
    ext?: number
}
