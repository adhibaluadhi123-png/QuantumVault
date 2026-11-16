/// Safely calls the C crypto_add function.
pub fn safe_add(a: i32, b: i32) -> i32 {
    unsafe { crate::ffi::crypto_add(a, b) }
}

/// Applies XOR to a mutable byte buffer using C.
pub fn xor_buffer(data: &mut [u8], key: u8) -> Result<(), i32> {
    let status = unsafe { crate::ffi::crypto_xor_buffer(data.as_mut_ptr(), data.len(), key) };

    if status == 0 { Ok(()) } else { Err(status) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c_function_through_rust() {
        assert_eq!(safe_add(10, 20), 30);
        assert_eq!(safe_add(-5, 2), -3);
        assert_eq!(safe_add(0, 0), 0);
    }

    #[test]
    fn test_c_buffer_processing() {
        let mut data = [0x10, 0x20, 0x30];

        let result = xor_buffer(&mut data, 0xFF);

        assert_eq!(result, Ok(()));
        assert_eq!(data, [0xEF, 0xDF, 0xCF]);
    }

    #[test]
    fn test_empty_buffer() {
        let mut data: [u8; 0] = [];

        let result = xor_buffer(&mut data, 0xFF);

        assert_eq!(result, Ok(()));
        assert_eq!(data.len(), 0);
    }

    #[test]
    fn test_null_pointer_error_handling() {
        let result = unsafe { crate::ffi::crypto_xor_buffer(std::ptr::null_mut(), 1, 0xFF) };

        assert_eq!(result, -1);
    }
}
