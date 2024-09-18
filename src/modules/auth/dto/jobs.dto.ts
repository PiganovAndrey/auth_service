import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';

export class JobsDto {
    @IsOptional()
    @IsString()
    @ApiProperty({example: 'Programmer', description: 'Любая профессия, необязательное поле'})
    profession?: string;
    @IsString()
    @IsOptional()
    @ApiProperty({example: 'IT', description: 'Ваша сфера деятельности, необязательно'})
    industry?: string;
}
