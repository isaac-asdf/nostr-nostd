use heapless::{String, Vec};

use crate::{errors, Note};

fn get_end_index<const N: usize>(
    locs: Vec<usize, N>,
    this_pos: usize,
    max_len: usize,
    is_string: bool,
) -> usize {
    if this_pos == locs.len() - 1 {
        max_len - if is_string { 2 } else { 1 }
    } else {
        locs[this_pos + 1] - if is_string { 2 } else { 1 }
    }
}

fn remove_whitespace<const N: usize>(value: &str) -> String<N> {
    let mut output = String::new();
    let space_char = char::from(32_u8);
    let quote_char = char::from(34_u8);
    // keep track of when we are between quotes
    // remove whitespace when we are not between quotes
    let mut remove_whitespace = true;
    value.chars().for_each(|c| {
        if c == quote_char {
            remove_whitespace = !remove_whitespace;
        };
        if c == space_char && !remove_whitespace {
            output.push(c).unwrap();
        } else if c != space_char {
            output.push(c).unwrap();
        };
    });
    output
}

fn remove_array_chars<const N: usize>(value: &str) -> String<N> {
    let mut output = String::new();
    let left_char = char::from(91_u8);
    let right_char = char::from(93_u8);
    value.chars().for_each(|c| {
        if c != left_char && c != right_char {
            output.push(c).unwrap();
        }
    });
    output
}

impl TryFrom<&str> for Note {
    type Error = errors::Error;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        // set up each var we will search for
        let content_str = r#""content":""#;
        let created_at_str = r#""created_at":"#;
        let kind_str = r#""kind":"#;
        let id_str = r#""id":""#;
        let pubkey_str = r#""pubkey":""#;
        let sig_str = r#""sig":""#;
        let tags_str = r#""tags":"#;

        // find indices matching start locations for each key
        let (content_loc, _) = value.match_indices(content_str).next().unwrap();
        let (created_at_loc, _) = value.match_indices(created_at_str).next().unwrap();
        let (kind_loc, _) = value.match_indices(kind_str).next().unwrap();
        let (id_loc, _) = value.match_indices(id_str).next().unwrap();
        let (pubkey_loc, _) = value.match_indices(pubkey_str).next().unwrap();
        let (sig_loc, _) = value.match_indices(sig_str).next().unwrap();
        let (tags_loc, _) = value.match_indices(tags_str).next().unwrap();

        // sort order of occurences of variables
        let mut locs: Vec<usize, 7> = Vec::new();
        locs.push(content_loc);
        locs.push(created_at_loc);
        locs.push(kind_loc);
        locs.push(id_loc);
        locs.push(pubkey_loc);
        locs.push(sig_loc);
        locs.push(tags_loc);
        locs.sort_unstable();

        // get content data
        let content_order_pos = locs.iter().position(|&x| x == content_loc).unwrap();
        let content_start = content_loc + content_str.len();
        let content_end_index = get_end_index(locs, content_order_pos, value.len(), true);
        let content_data = &value[content_start..content_end_index];
        let content = if content_data.len() > 0 {
            Some(content_data.into())
        } else {
            None
        };

        // get kind data
        let kind_order_pos = locs.iter().position(|&x| x == kind_loc).unwrap();
        let kind_start = kind_loc + kind_str.len();
        let kind_end_index = get_end_index(locs, kind_order_pos, value.len(), true);
        let kind_data = &value[kind_start..kind_end_index];
        let kind =
            u16::from_str_radix(kind_data, 10).map_err(|_| errors::Error::MalformedContent)?;

        // get tags
        let mut tags = Vec::new();
        let tags_order_pos = locs.iter().position(|&x| x == tags_loc).unwrap();
        let tags_start = tags_loc + tags_str.len();
        let tags_end_index = get_end_index(locs, tags_order_pos, value.len(), true);
        let tags_data = &value[tags_start..tags_end_index];
        // splits tags for full array
        tags_data.split("],").for_each(|tag| {
            let tag = remove_array_chars(tag);
            tags.push(tag).unwrap();
        });

        Ok(Note {
            id: unimplemented!(),
            pubkey: unimplemented!(),
            created_at: unimplemented!(),
            kind: kind.try_into()?,
            tags,
            content,
            sig: unimplemented!(),
        })
    }
}
