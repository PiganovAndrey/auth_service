import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsNumber } from 'class-validator';

export class LocationDto {
    @IsNumber()
    @IsNotEmpty()
    @ApiProperty({example: 13, description: 'lat локации'})
    lat: number;
    @IsNumber()
    @IsNotEmpty()
    @ApiProperty({example: 150, description: 'long локации'})
    long: number;
}
