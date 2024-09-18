import { PickType } from "@nestjs/mapped-types";
import { LoginMobileDto } from "./login.mobile.dto";

export class CheckMobileDto extends PickType(LoginMobileDto, ['phone_number']) {}
