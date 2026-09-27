// Intentional Tollbooth Wrapper & Ghost Abstraction

pub fn target_calculation(x: i32, y: i32) -> i32 {
    x * 2 + y * 3
}

// Tollbooth wrapper: does nothing except forward
pub fn compute_wrapper(x: i32, y: i32) -> i32 {
    target_calculation(x, y)
}

// Ghost abstraction: Trait with exactly 1 implementation
trait UserValidator {
    fn validate(&self, name: &str) -> bool;
}

struct ConcreteUserValidator;

impl UserValidator for ConcreteUserValidator {
    fn validate(&self, name: &str) -> bool {
        !name.is_empty()
    }
}
