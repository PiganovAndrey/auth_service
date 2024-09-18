import { Type } from "class-transformer";
import { IsNotEmpty } from "class-validator";
import { AuthDto } from "./auth.dto";

export class SessionData {
    @IsNotEmpty()
    @Type(() => AuthDto)
    authorization: AuthDto
}
