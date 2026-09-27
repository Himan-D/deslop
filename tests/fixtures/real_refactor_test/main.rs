mod math;
use math::wrapper_add;

fn main() {
    let res = wrapper_add(10, 20);
    println!("Result: {}", res);
}
