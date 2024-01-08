import { RegisterDto } from "@auth/dto";
import { ValidationArguments, ValidatorConstraint, ValidatorConstraintInterface } from "class-validator";

@ValidatorConstraint({name: 'IsPasswordMatching', async: false})
export class IsPasswordMatchingConstraint implements ValidatorConstraintInterface {
    validate(passwordRepeat: string, args: ValidationArguments): boolean | Promise<boolean> {
        const obj = args.object as RegisterDto;
        return obj.password === passwordRepeat;
    }

    defaultMessage(validationArguments?: ValidationArguments): string {
        return "Password doesn't match"
    }
}