/// Combines multiple byte arrays into a single buffer with length prefixes.
/// Each byte array is prefixed with its length as a u32 in big-endian format.
///
/// # Arguments
/// * `byte_arrays` - A slice of byte arrays to combine
///
/// # Returns
/// A Vec<u8> containing all byte arrays with their length prefixes
pub fn combine_byte_arrays(byte_arrays: &[Vec<u8>]) -> Vec<u8> {
    let total_size = byte_arrays.len() * 4 + byte_arrays.iter().map(|arr| arr.len()).sum::<usize>();
    let mut buffer = Vec::with_capacity(total_size);

    for arr in byte_arrays {
        buffer.extend_from_slice(&(arr.len() as u32).to_be_bytes());
        buffer.extend_from_slice(arr);
    }

    buffer
}

/// Splits a combined buffer back into its original byte arrays.
/// Expects each array to be prefixed with its length as a u32 in big-endian format.
///
/// # Arguments
/// * `buffer` - The combined buffer to split
///
/// # Returns
/// A Result containing a Vec of the split byte arrays, or an error if the buffer is invalid
pub fn split_byte_arrays(buffer: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    let mut arrays = Vec::new();
    let mut pos = 0;

    while pos + 4 <= buffer.len() {
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&buffer[pos..pos + 4]);
        let length = u32::from_be_bytes(len_bytes) as usize;
        pos += 4;

        if pos + length > buffer.len() {
            return Err("Buffer is truncated");
        }

        let array = buffer[pos..pos + length].to_vec();
        arrays.push(array);
        pos += length;
    }

    if pos != buffer.len() {
        return Err("Buffer contains extra bytes");
    }

    Ok(arrays)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_combine_and_split() {
        let arrays = vec![vec![1, 2, 3], vec![4, 5], vec![6, 7, 8, 9]];

        let combined = combine_byte_arrays(&arrays);
        let split = split_byte_arrays(&combined).unwrap();

        assert_eq!(split.len(), 3);
        assert_eq!(split[0], vec![1, 2, 3]);
        assert_eq!(split[1], vec![4, 5]);
        assert_eq!(split[2], vec![6, 7, 8, 9]);
    }

    #[test]
    fn test_empty_arrays() {
        let arrays = vec![Vec::<u8>::new(), vec![1]];

        let combined = combine_byte_arrays(&arrays);
        let split = split_byte_arrays(&combined).unwrap();

        assert_eq!(split.len(), 2);
        assert_eq!(split[0], Vec::<u8>::new());
        assert_eq!(split[1], vec![1]);
    }

    #[test]
    fn test_invalid_buffer() {
        let invalid = vec![0, 0, 0, 5, 1, 2];
        assert!(split_byte_arrays(&invalid).is_err());

        let invalid = vec![0, 0, 0, 1, 1, 0];
        assert!(split_byte_arrays(&invalid).is_err());
    }
}
