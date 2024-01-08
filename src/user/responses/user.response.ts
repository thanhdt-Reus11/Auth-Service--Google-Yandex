import { $Enums, Role, User, Provider} from "@prisma/client";
import { Exclude } from "class-transformer";


export class UserResponse implements User {
    id: string;
    email: string;

    @Exclude()
    password: string;

    @Exclude()
    provider: Provider;

    @Exclude()
    createdAt: Date;

    updatedAt: Date;
    roles: Role[];

    @Exclude()
    isBlocked: boolean;

    constructor(user: User) {
        Object.assign(this, user);
    }
}