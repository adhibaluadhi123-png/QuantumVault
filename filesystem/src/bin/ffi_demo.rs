use rust_ffi::safe::safe_add;

fn main() {
    let result = safe_add(10, 20);

    println!("Result from C function through safe Rust API: {}", result);
}

#[cfg(test)]
mod tests {
    use rust_ffi::safe::safe_add;

    #[test]
    fn test_c_add_numbers() {
        assert_eq!(safe_add(10, 20), 30);
    }

    #[test]
    fn test_negative_numbers() {
        assert_eq!(safe_add(-5, 2), -3);
    }

    #[test]
    fn test_zero_values() {
        assert_eq!(safe_add(0, 0), 0);
    }
}
