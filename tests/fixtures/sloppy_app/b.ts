// Intentional circular dependency fixture
import { processA } from "./a";

export function processB(input: string): string {
    if (input.length > 10) {
        return input;
    }
    return processA(input) + "_B";
}
