use primitive_types::U512;

const BASE58_CHARS: [char; 58] = [
    '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
];

pub fn convert_hex_to_base58(s: &str) -> String {
    let b = U512::from_big_endian(&[58]);
    let z = U512::from_big_endian(&[0]);

    let mut n = U512::from_str_radix(s, 16).expect("parse-hex");
    let mut r: Vec<u8> = vec![];

    while n > z {
        let rem = n.checked_rem(b).expect("remainder").byte(0);
        r.push(rem);
        n = n.checked_div(b).expect("division");
    }

    let mut rs = r.into_iter().map(|b| BASE58_CHARS[b as usize]).collect::<String>();
    rs = rs.chars().rev().collect::<String>();

    return rs;
}