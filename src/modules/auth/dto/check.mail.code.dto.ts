import { PickType } from "@nestjs/mapped-types";
import { LoginAdminDto } from "./login.admin.dto";
import { IsEmail, IsNotEmpty } from "class-validator";
import { ApiProperty } from "@nestjs/swagger";

export class CheckMailCodeDto extends PickType(LoginAdminDto, ['email', 'code']){
    @IsEmail()
    @IsNotEmpty()
    @ApiProperty({example: 'pup.pupov@mail.ru', description: 'Новый email пользователя, не старый!'})
    newEmail: string;
}
