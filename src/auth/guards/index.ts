import { GoogleAuthGuard } from "./google.guard";
import { JwtAuthGuard } from "./jwt.guard";
import { RolesGuard } from "./role.guard";
import { YandexAuthGuard } from "./yandex.guard";

export const GUARDS = [JwtAuthGuard, RolesGuard, GoogleAuthGuard, YandexAuthGuard];