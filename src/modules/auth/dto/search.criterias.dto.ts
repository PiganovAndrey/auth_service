import { IsEnum, IsInt, IsNotEmpty } from 'class-validator';
import { FindGenderEnum } from './enums/find.gender';

export class SearchCriteriasDto {
    @IsInt()
    @IsNotEmpty()
    relationshipId: number;
    @IsEnum(FindGenderEnum, { message: 'Gender must be either MALE, FEMALE, or ALL' })
    @IsNotEmpty()
    findGender: FindGenderEnum;
    @IsNotEmpty()
    @IsInt()
    distanceLimit: number;
    @IsNotEmpty()
    @IsInt()
    fromAge: number;
    @IsNotEmpty()
    @IsInt()
    toAge: number;
}
