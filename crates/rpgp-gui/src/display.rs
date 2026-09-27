//! What the window shows of text written by someone other than the user.
//!
//! A user ID is whatever its certificate carries, and a revocation's note is
//! whatever whoever signed the revocation typed. Both reach the window from
//! outside: from a keyserver, from a file someone sent, from a certificate's
//! own holder. Slint lays text out through parley, which applies the Unicode
//! bidirectional algorithm in full, explicit overrides included, and starts a
//! new line at every newline and line or paragraph separator. So a user ID
//! carrying U+202E drew its address backwards, and one that left its override
//! open reversed the app's own words after it: the notepad's "(unverified)"
//! came out as "(deifirevnu)", between the name and the address. A newline
//! made one user ID look like two in the details pane, and a note start a line
//! of its own inside the revocation banner.
//!
//! [`text`] is applied wherever such text becomes something the window shows
//! or announces, and nowhere else. The strings kept for matching, lookups and
//! signing stay as the certificate has them: a user ID is found, certified and
//! revoked by its exact text, and a rewritten one would no longer match the
//! certificate it came from.

use std::fmt::Write as _;

/// `untrusted`, with every character that is drawn as nothing, or that moves
/// or breaks the text around it, written out as its code point: `[U+202E]`.
///
/// Those are the C0 and C1 controls, newline and tab among them; the format
/// characters, Unicode's general category Cf, which holds the bidirectional
/// embeddings, overrides, isolates and marks, the zero-width space and
/// joiners, the byte order mark, the soft hyphen and the tag characters; and
/// the line and paragraph separators, at which Slint starts a new line.
///
/// Written out rather than removed, so that the reader can see that something
/// is there, and so that two user IDs differing only there do not look alike,
/// which in the Certify dialog would leave the user unable to tell which one
/// they were signing. Nothing is removed, so what is shown is still the whole
/// of what the certificate says.
///
/// The zero-width joiner and non-joiner are kept where both of their
/// neighbours are outside ASCII and shown: there they may be spelling a word,
/// as they do in Persian and in the Indic scripts, or joining an emoji, and
/// writing them out would break a name that means no harm. Beside ASCII, or at
/// either end, they join nothing and would only hide. The test is ASCII and
/// not the script, so one is kept between two Cyrillic or accented Latin
/// letters too, where it draws nothing, and two user IDs differing only by
/// such a one still look alike. Two on one certificate are both its holder's
/// own, and wherever a certificate is chosen its key ID is shown beside it.
///
/// Right-to-left letters are left as they are, and read right to left, as they
/// should. With every explicit control written out, what their direction can
/// still do to the text beside them is what any name in Hebrew or Arabic does:
/// settle where the punctuation and digits next to it go, and, at the start of
/// a line, which end it reads from. It cannot turn the app's words round.
///
/// Applying it twice changes nothing more, since what it writes is ASCII: a
/// message built from text that has been through it can go through again.
pub(crate) fn text(untrusted: &str) -> String {
    // Most text has nothing to write out, and this runs for every row on every
    // keystroke in the search field, so that case is one pass and one copy.
    if !untrusted.chars().any(hidden) {
        return untrusted.to_owned();
    }
    let mut shown = String::with_capacity(untrusted.len() + 16);
    let mut previous = None;
    let mut rest = untrusted.chars().peekable();
    while let Some(c) = rest.next() {
        let spelling = matches!(c, '\u{200C}' | '\u{200D}')
            && previous.is_some_and(spells)
            && rest.peek().copied().is_some_and(spells);
        if hidden(c) && !spelling {
            let _ = write!(shown, "[U+{:04X}]", u32::from(c));
        } else {
            shown.push(c);
        }
        previous = Some(c);
    }
    shown
}

/// Drawn as nothing, or moves or breaks the text around it: what [`text`]
/// writes out, but for a joiner it keeps.
pub(crate) fn hidden(c: char) -> bool {
    c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') || format(c)
}

/// A neighbour a joiner may be spelling with.
fn spells(c: char) -> bool {
    !c.is_ascii() && !hidden(c)
}

/// Unicode's general category Cf, as of Unicode 16.0. A few of these are
/// drawn, the Arabic number signs among them; they are written out all the
/// same, since they mark up the text after them, and no name needs them.
fn format(c: char) -> bool {
    matches!(
        c,
        '\u{AD}'
            | '\u{600}'..='\u{605}'
            | '\u{61C}'
            | '\u{6DD}'
            | '\u{70F}'
            | '\u{890}'..='\u{891}'
            | '\u{8E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

/// The number of the smartcard `serial` names, as `gpg -K` prints it.
///
/// gpg-agent reports a card by its serial, which for an OpenPGP card is the
/// card's whole application identifier: 32 hex digits, of which the card's own
/// number is the manufacturer's four and the serial's eight in the middle,
/// `D2760001240103040006181329630000` for `0006 18132963`. The details pane
/// showed all 32 in a pill beside the validity one, about 310px wide in a
/// pane 288px wide inside its margins, so the pane scrolled sideways and its
/// edge cut off the digits that tell one card from another. Any other card's
/// serial is shown as the agent gave it.
pub(crate) fn card_number(serial: &str) -> String {
    const OPENPGP: &str = "D27600012401";
    let is_openpgp = serial.len() == 32
        && serial.bytes().all(|b| b.is_ascii_hexdigit())
        && serial[..OPENPGP.len()].eq_ignore_ascii_case(OPENPGP);
    if is_openpgp {
        format!(
            "{} {}",
            serial[16..20].to_ascii_uppercase(),
            serial[20..28].to_ascii_uppercase()
        )
    } else {
        text(serial)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Everything that is drawn as nothing, or that reorders or breaks the
    /// text around it, is written out, and what is written out is the code
    /// point, so different characters stay different.
    #[test]
    fn what_would_move_or_hide_text_is_written_out_as_its_code_point() {
        for (raw, shown) in [
            // An override and the pop that closes it: an address drawn
            // backwards.
            (
                "Mallory <\u{202E}gro.elpmaxe@ecila\u{202C}>",
                "Mallory <[U+202E]gro.elpmaxe@ecila[U+202C]>",
            ),
            // Isolates, embeddings and the implicit marks.
            (
                "a\u{2066}b\u{2067}c\u{2068}d\u{2069}",
                "a[U+2066]b[U+2067]c[U+2068]d[U+2069]",
            ),
            ("a\u{202A}b\u{202B}c\u{202D}", "a[U+202A]b[U+202B]c[U+202D]"),
            ("a\u{200E}b\u{200F}c\u{61C}", "a[U+200E]b[U+200F]c[U+061C]"),
            // What starts a new line.
            ("one\ntwo", "one[U+000A]two"),
            ("one\r\ntwo", "one[U+000D][U+000A]two"),
            ("one\u{2028}two\u{2029}", "one[U+2028]two[U+2029]"),
            ("one\u{85}two", "one[U+0085]two"),
            // Other controls, which draw as a gap or nothing.
            ("tab\there", "tab[U+0009]here"),
            ("bell\u{7}\u{7F}\u{9B}", "bell[U+0007][U+007F][U+009B]"),
            // What is drawn as nothing at all.
            ("alice@exa\u{200B}mple.org", "alice@exa[U+200B]mple.org"),
            ("\u{FEFF}Alice", "[U+FEFF]Alice"),
            ("Al\u{AD}ice", "Al[U+00AD]ice"),
            ("Alice\u{2060}", "Alice[U+2060]"),
            ("tag\u{E0041}", "tag[U+E0041]"),
            // A joiner between ASCII letters, or at an end, joins nothing.
            ("ali\u{200D}ce", "ali[U+200D]ce"),
            ("ali\u{200C}ce", "ali[U+200C]ce"),
            ("\u{200D}\u{5E9}", "[U+200D]\u{5E9}"),
            ("\u{5E9}\u{200D}", "\u{5E9}[U+200D]"),
            // Nor beside another character that is written out.
            (
                "\u{5E9}\u{200D}\u{200D}\u{5E9}",
                "\u{5E9}[U+200D][U+200D]\u{5E9}",
            ),
        ] {
            assert_eq!(text(raw), shown, "for {raw:?}");
        }
    }

    /// Text that has nothing to hide is shown exactly as it is, the scripts
    /// that need a joiner to spell with among it.
    #[test]
    fn a_name_that_hides_nothing_is_shown_as_it_is() {
        for raw in [
            "Alice <alice@example.org>",
            "José Müller (work) <jose@example.org>",
            // Hebrew and Arabic, read right to left with no control at all.
            "\u{5E9}\u{5DC}\u{5D5}\u{5DD} <shalom@example.org>",
            "\u{645}\u{62D}\u{645}\u{62F}",
            // Persian spells "Alireza" with a non-joiner between two letters.
            "\u{639}\u{644}\u{6CC}\u{200C}\u{631}\u{636}\u{627}",
            // Devanagari, with a joiner after the virama.
            "\u{915}\u{94D}\u{200D}\u{937}",
            // An emoji sequence joined into one picture.
            "\u{1F469}\u{200D}\u{1F4BB} Dev",
            // U+FFFD is what an invalid byte in a user ID already reads as.
            "Alice \u{FFFD}",
            "",
        ] {
            assert_eq!(text(raw), raw);
        }
    }

    /// Applying it twice changes nothing more, so a message built from text
    /// that has already been through it can be put through again.
    #[test]
    fn writing_out_twice_is_writing_out_once() {
        for raw in [
            "Mallory <\u{202E}gro.elpmaxe@ecila\u{202C}>\n(verified)",
            "\u{639}\u{644}\u{6CC}\u{200C}\u{631}\u{200B}",
            "ali\u{200D}ce",
        ] {
            assert_eq!(text(&text(raw)), text(raw), "for {raw:?}");
        }
    }

    /// An OpenPGP card is named by its manufacturer and serial, as `gpg -K`
    /// names it, and any other serial is shown as the agent gave it.
    #[test]
    fn a_card_is_named_by_the_number_gpg_gives_it() {
        assert_eq!(
            card_number("D2760001240103040006181329630000"),
            "0006 18132963"
        );
        assert_eq!(
            card_number("d2760001240103040006181329630000"),
            "0006 18132963"
        );
        // Not an OpenPGP card's: another application, a short serial, or
        // not hex at all.
        assert_eq!(
            card_number("D2760001240200000006181329630000"),
            "D2760001240200000006181329630000"
        );
        assert_eq!(card_number("D2760001240100000006"), "D2760001240100000006");
        assert_eq!(
            card_number("D27600012401030400061813296300Z0"),
            "D27600012401030400061813296300Z0"
        );
        // And one that is not an OpenPGP card's is still only shown.
        assert_eq!(card_number("CARD\u{202E}1"), "CARD[U+202E]1");
    }
}
