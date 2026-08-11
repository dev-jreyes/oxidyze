//! Minimal left-aligned text table.

/// Renders a table, sizing each column to its widest cell.
///
/// Ragged rows are tolerated: a row with fewer cells than there are headers
/// is padded, and extra cells beyond the header count get their own columns
/// rather than panicking. The original version indexed a `widths` vec sized
/// from the headers alone, so any row wider than the header list was an
/// index-out-of-bounds panic waiting for the next column to be added.
pub fn render(headers: &[&str], rows: &[Vec<String>]) -> String {
    let columns = headers
        .len()
        .max(rows.iter().map(|r| r.len()).max().unwrap_or(0));

    let mut widths = vec![0usize; columns];
    for (i, h) in headers.iter().enumerate() {
        widths[i] = widths[i].max(display_width(h));
    }
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(display_width(cell));
        }
    }

    let render_row = |cells: &[String]| -> String {
        let mut line = String::new();
        for (i, width) in widths.iter().enumerate() {
            let cell = cells.get(i).map(String::as_str).unwrap_or("");
            if i > 0 {
                line.push_str("  ");
            }
            line.push_str(cell);
            // Pad by display width, not byte length, so non-ASCII hostnames
            // don't skew the columns.
            for _ in 0..width.saturating_sub(display_width(cell)) {
                line.push(' ');
            }
        }
        // Trailing padding on the last column is noise; drop it.
        line.trim_end().to_string()
    };

    let mut out = String::new();
    let header_cells: Vec<String> = headers.iter().map(|h| (*h).to_string()).collect();
    out.push_str(&render_row(&header_cells));
    out.push('\n');
    out.push_str(
        &widths
            .iter()
            .map(|w| "-".repeat(*w))
            .collect::<Vec<_>>()
            .join("  "),
    );
    for row in rows {
        out.push('\n');
        out.push_str(&render_row(row));
    }
    out
}

pub fn print(headers: &[&str], rows: &[Vec<String>]) {
    println!("{}", render(headers, rows));
}

/// Character count, which is a good enough stand-in for terminal width here.
fn display_width(s: &str) -> usize {
    s.chars().count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(cells: &[&str]) -> Vec<String> {
        cells.iter().map(|c| (*c).to_string()).collect()
    }

    #[test]
    fn columns_size_to_widest_cell() {
        let out = render(
            &["IP", "HOSTNAME"],
            &[row(&["192.168.1.1", "router.lan"]), row(&["10.0.0.1", "-"])],
        );
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "IP           HOSTNAME");
        // The rule spans the widest cell in each column, so the second
        // column is sized to "router.lan" (10) rather than "HOSTNAME" (8).
        assert_eq!(lines[1], "-----------  ----------");
        assert_eq!(lines[2], "192.168.1.1  router.lan");
        assert_eq!(lines[3], "10.0.0.1     -");
    }

    // Regression: this panicked with "index out of bounds: the len is 2 but
    // the index is 2" in the original implementation.
    #[test]
    fn row_wider_than_headers_does_not_panic() {
        let out = render(&["ONE", "TWO"], &[row(&["a", "b", "c"])]);
        assert!(out.contains('c'), "extra cell should still be rendered");
    }

    #[test]
    fn row_narrower_than_headers_is_padded() {
        let out = render(&["ONE", "TWO", "THREE"], &[row(&["a"])]);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[2], "a");
    }

    #[test]
    fn handles_no_rows() {
        let out = render(&["IP", "PORTS"], &[]);
        assert_eq!(out.lines().count(), 2);
    }

    #[test]
    fn non_ascii_cells_align_by_character_count() {
        let out = render(&["NAME"], &[row(&["café"]), row(&["ab"])]);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[1], "----");
    }
}
