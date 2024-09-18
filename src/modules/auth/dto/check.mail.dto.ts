import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsNotEmpty } from "class-validator";

export class CheckMailDto {
    @IsEmail()
    @IsNotEmpty()
    @ApiProperty({example: 'puper.super@mail.ru', description: 'Ваше email для входа'})
    mail: string;
}
