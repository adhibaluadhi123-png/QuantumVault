unsafe extern "C" {
    fn add_numbers(a: i32, b: i32) -> i32;
}

fn main() {
    let result = unsafe {
        add_numbers(10, 20)
    };

    println!("Result from C function: {}", result);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c_add_numbers() {
        let result = unsafe {
            add_numbers(10, 20)
        };

        assert_eq!(result, 30);
    }

    #[test]
    fn test_negative_numbers() {
        let result = unsafe {
            add_numbers(-5, 2)
        };

        assert_eq!(result, -3);
    }

    #[test]
    fn test_zero_values() {
        let result = unsafe {
            add_numbers(0, 0)
        };

        assert_eq!(result, 0);
    }
}
