import { UserProfileDto } from './user.profile.dto';
import { SearchCriteriasDto } from './search.criterias.dto';
import { Type } from 'class-transformer';
import { IsInt, IsMobilePhone, IsNotEmpty, IsOptional } from 'class-validator';
// import { CountryCode } from 'libphonenumber-js';
// import { IsPhoneNumberInLocales } from 'src/common/constratints/isPhoneNumberInLocales';
// import { cisdLocales } from 'src/utils/locales';

export class UserCreateDto {
    // @IsPhoneNumberInLocales(cisdLocales as CountryCode[])
    @IsMobilePhone()
    @IsNotEmpty()
    phoneNumber: string;
    @Type(() => UserProfileDto)
    @IsNotEmpty()
    profile: UserProfileDto;
    @Type(() => SearchCriteriasDto)
    @IsNotEmpty()
    searchCriterias: SearchCriteriasDto;
    @IsOptional()
    @IsInt()
    promoId: number | null;
}
