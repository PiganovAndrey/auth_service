import { ApiProperty } from "@nestjs/swagger";
import { IsMobilePhone, IsNotEmpty, IsString } from "class-validator";

export class LoginMobileDto {
    @IsMobilePhone()
    @IsNotEmpty()
    @ApiProperty({example: '+7911111111111', description: 'Валидный номер телефона для входа в приложение'})
    phone_number: string;
    @IsString()
    @IsNotEmpty()
    @ApiProperty({example: 1111, description: 'Код для входа в приложение'})
    sms_code: string;
}
