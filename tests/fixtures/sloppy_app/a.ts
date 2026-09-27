// Intentional circular dependency fixture
import { processB } from "./b";

export function processA(input: string): string {
    return processB(input) + "_A";
}
