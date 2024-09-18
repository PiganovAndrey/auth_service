import { IsNotEmpty, IsNumber } from 'class-validator';

export class UserBadHabitDto {
    @IsNotEmpty()
    @IsNumber()
    badHabitId: number;
    @IsNumber()
    @IsNotEmpty()
    badHabitRelationShipId: number;
}
