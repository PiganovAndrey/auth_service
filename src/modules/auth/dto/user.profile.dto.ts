import { JobsDto } from './jobs.dto';
import { GenderEnum } from './enums/gender.enums';
import { LocationDto } from './location.dto';
import { UserBadHabitDto } from './user-bad-habit.dto';
import {
    IsArray,
    IsDateString,
    IsEnum,
    IsInt,
    IsNotEmpty,
    IsOptional,
    IsString,
    ValidateNested
} from 'class-validator';
import { Type } from 'class-transformer';

export class UserProfileDto {
    @IsString()
    @IsNotEmpty()
    name: string;
    @IsArray()
    @IsInt({ each: true })
    @IsNotEmpty()
    tags: number[];
    @IsArray()
    @IsInt({ each: true })
    @IsNotEmpty()
    bad_habits: number[];
    @IsArray()
    @ValidateNested({ each: true })
    @Type(() => UserBadHabitDto)
    user_bad_habits: UserBadHabitDto[];
    @IsString()
    @IsNotEmpty()
    description: string;
    @IsEnum(GenderEnum, { message: 'Gender must be either MALE, FEMALE, or OTHER' })
    @IsNotEmpty()
    gender: GenderEnum;
    @IsDateString()
    @IsNotEmpty()
    birthday: Date;
    @IsInt()
    @IsNotEmpty()
    height: number;
    @IsInt()
    @IsNotEmpty()
    weight: number;
    @IsInt()
    @IsNotEmpty()
    kidsStatus: number;
    @Type(() => LocationDto)
    @IsNotEmpty()
    location: LocationDto;
    @IsInt()
    @IsNotEmpty()
    cityId: number;
    @Type(() => JobsDto)
    @IsOptional()
    jobs?: JobsDto;
    @IsNotEmpty()
    @IsInt()
    education: number;
    @IsInt()
    @IsNotEmpty()
    religion: number;
}
