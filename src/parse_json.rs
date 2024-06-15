use heapless::{String, Vec};

use crate::{errors, Note};

fn get_end_index<const N: usize>(
    locs: &Vec<usize, N>,
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

fn find_index<const N: usize>(locs: &Vec<usize, N>, search_element: usize) -> usize {
    // can't fail because locs is filled with all search_elements
    locs.binary_search(&search_element).expect("infallible")
}

fn remove_whitespace<const N: usize>(value: &str) -> Result<String<N>, errors::Error> {
    let mut output = String::new();
    let space_char = char::from(32_u8);
    let quote_char = char::from(34_u8);
    // keep track of when we are between quotes
    // remove whitespace when we are not between quotes
    let mut remove_whitespace = true;
    value.chars().try_for_each(|c| {
        if c == quote_char {
            remove_whitespace = !remove_whitespace;
        };
        if c == space_char && !remove_whitespace {
            output.push(c).map_err(|_| errors::Error::ContentOverflow)?
        } else if c != space_char {
            output.push(c).map_err(|_| errors::Error::ContentOverflow)?
        }
        Ok(())
    })?;
    Ok(output)
}

fn remove_array_chars<const N: usize>(value: &str) -> Result<String<N>, errors::Error> {
    let mut output = String::new();
    let left_char = char::from(91_u8);
    let right_char = char::from(93_u8);
    let quote_char = char::from(34_u8);
    value.chars().try_for_each(|c| {
        if c != left_char && c != right_char && c != quote_char {
            output.push(c).map_err(|_| errors::Error::ContentOverflow)?
        }
        Ok(())
    })?;
    Ok(output)
}

impl TryFrom<&str> for Note {
    type Error = errors::Error;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let value: String<1000> = remove_whitespace(value)?;
        // set up each var we will search for, including the leading " character for strings
        let content_str = r#""content":""#;
        let created_at_str = r#""created_at":"#;
        let kind_str = r#""kind":"#;
        let id_str = r#""id":""#;
        let pubkey_str = r#""pubkey":""#;
        let sig_str = r#""sig":""#;
        let tags_str = r#""tags":"#;

        // find indices matching start locations for each key
        let (content_loc, _) = if let Some(val) = value.match_indices(content_str).next() {
            val
        } else {
            return Err(errors::Error::EventMissingField);
        };
        let (created_at_loc, _) = if let Some(val) = value.match_indices(created_at_str).next() {
            val
        } else {
            return Err(errors::Error::EventMissingField);
        };
        let (kind_loc, _) = if let Some(val) = value.match_indices(kind_str).next() {
            val
        } else {
            return Err(errors::Error::EventMissingField);
        };
        let (id_loc, _) = if let Some(val) = value.match_indices(id_str).next() {
            val
        } else {
            return Err(errors::Error::EventMissingField);
        };
        let (pubkey_loc, _) = if let Some(val) = value.match_indices(pubkey_str).next() {
            val
        } else {
            return Err(errors::Error::EventMissingField);
        };
        let (sig_loc, _) = if let Some(val) = value.match_indices(sig_str).next() {
            val
        } else {
            return Err(errors::Error::EventMissingField);
        };
        let (tags_loc, _) = if let Some(val) = value.match_indices(tags_str).next() {
            val
        } else {
            return Err(errors::Error::EventMissingField);
        };

        // sort order of occurences of variables
        let mut locs: Vec<usize, 7> = Vec::new();
        locs.push(content_loc).expect("infallible");
        locs.push(created_at_loc).expect("infallible");
        locs.push(kind_loc).expect("infallible");
        locs.push(id_loc).expect("infallible");
        locs.push(pubkey_loc).expect("infallible");
        locs.push(sig_loc).expect("infallible");
        locs.push(tags_loc).expect("infallible");
        locs.sort_unstable();

        // get content data
        let content_order_pos = find_index(&locs, content_loc);
        let content_start = content_loc + content_str.len();
        let content_end_index = get_end_index(&locs, content_order_pos, value.len(), true);
        let content_data = &value[content_start..content_end_index];
        let content = if content_data.len() > 0 {
            Some(content_data.into())
        } else {
            None
        };

        // get id data
        let id_order_pos = find_index(&locs, id_loc);
        let id_start = id_loc + id_str.len();
        let id_end_index = get_end_index(&locs, id_order_pos, value.len(), true);
        let id_data = &value[id_start..id_end_index];
        let mut id = [0; 64];
        let mut count = 0;
        id_data.as_bytes().iter().for_each(|b| {
            id[count] = *b;
            count += 1;
        });

        // get pubkey data
        let pubkey_order_pos = find_index(&locs, pubkey_loc);
        let pubkey_start = pubkey_loc + pubkey_str.len();
        let pubkey_end_index = get_end_index(&locs, pubkey_order_pos, value.len(), true);
        let pubkey_data = &value[pubkey_start..pubkey_end_index];
        let mut pubkey = [0; 64];
        count = 0;
        pubkey_data.as_bytes().iter().for_each(|b| {
            pubkey[count] = *b;
            count += 1;
        });

        // get sig data
        let sig_order_pos = find_index(&locs, sig_loc);
        let sig_start = sig_loc + sig_str.len();
        let sig_end_index = get_end_index(&locs, sig_order_pos, value.len(), true);
        let sig_data = &value[sig_start..sig_end_index];
        let mut sig = [0; 128];
        count = 0;
        sig_data.as_bytes().iter().for_each(|b| {
            sig[count] = *b;
            count += 1;
        });

        // get kind data
        let kind_order_pos = find_index(&locs, kind_loc);
        let kind_start = kind_loc + kind_str.len();
        let kind_end_index = get_end_index(&locs, kind_order_pos, value.len(), false);
        let kind_data = &value[kind_start..kind_end_index];
        let kind =
            u16::from_str_radix(kind_data, 10).map_err(|_| errors::Error::MalformedContent)?;

        // get created_at data
        let created_at_order_pos = find_index(&locs, created_at_loc);
        let created_at_start = created_at_loc + created_at_str.len();
        let created_at_end_index = get_end_index(&locs, created_at_order_pos, value.len(), false);
        let created_at_data = &value[created_at_start..created_at_end_index];
        let created_at = u32::from_str_radix(created_at_data, 10)
            .map_err(|_| errors::Error::MalformedContent)?;

        // get tags
        let mut tags = Vec::new();
        let tags_order_pos = find_index(&locs, tags_loc);
        let tags_start = tags_loc + tags_str.len();
        let tags_end_index = get_end_index(&locs, tags_order_pos, value.len(), true);
        let tags_data = &value[tags_start..tags_end_index];
        // splits tags for full array
        tags_data.split("],").try_for_each(|tag| {
            if tag.len() > 0 {
                let tag = remove_array_chars(tag)?;
                if let Err(_) = tags.push(tag) {
                    return Err(errors::Error::TooManyTags);
                }
            }
            Ok(())
        })?;

        // todo: need to add signature verification
        let note = Note {
            id,
            pubkey,
            created_at,
            kind: kind.into(),
            tags,
            content,
            sig,
        };
        note.validate_signature()?;
        Ok(note)
    }
}
