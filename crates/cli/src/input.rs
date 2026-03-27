//! Shared crossterm → PTY byte conversion for keyboard and mouse events.
//!
//! Used by both PTY takeover and API takeover modes. All mouse events are
//! encoded as SGR (mode 1006) escape sequences, which is what modern TUI
//! frameworks (Bubbletea, Ink, crossterm, etc.) expect.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

/// Convert a crossterm `KeyEvent` into the byte sequence a PTY child expects.
///
/// Returns `None` for keys that have no standard terminal encoding (e.g.
/// bare modifier presses like Shift alone, media keys, etc.).
pub fn key_to_bytes(key: &KeyEvent) -> Option<Vec<u8>> {
    let mods = key.modifiers;
    let ctrl = mods.contains(KeyModifiers::CONTROL);
    let alt = mods.contains(KeyModifiers::ALT);
    let shift = mods.contains(KeyModifiers::SHIFT);

    let bytes = match key.code {
        // ── Characters ──
        KeyCode::Char(c) => {
            if ctrl && alt {
                // Ctrl+Alt+letter: ESC + control code
                let ctrl_code = c as u8 & 0x1f;
                vec![0x1b, ctrl_code]
            } else if ctrl {
                // Ctrl+letter → ASCII control code (0x01..0x1a).
                // Works for a-z and some symbols like Ctrl+[ (0x1b), Ctrl+] (0x1d).
                let code = c as u8;
                if code.is_ascii_lowercase() {
                    vec![code - b'a' + 1]
                } else if code.is_ascii_uppercase() {
                    vec![code - b'A' + 1]
                } else {
                    // Ctrl with non-alpha: Ctrl+[ = ESC, Ctrl+\ = 0x1c, etc.
                    match c {
                        '[' | '3' => vec![0x1b],       // Ctrl+[ = ESC
                        '\\' | '4' => vec![0x1c],      // Ctrl+\
                        ']' | '5' => vec![0x1d],       // Ctrl+]
                        '^' | '6' => vec![0x1e],       // Ctrl+^
                        '_' | '7' => vec![0x1f],       // Ctrl+_
                        '/' => vec![0x1f],             // Ctrl+/
                        '@' | '2' | ' ' => vec![0x00], // Ctrl+@ / Ctrl+Space = NUL
                        _ => return None,
                    }
                }
            } else if alt {
                // Alt+letter: ESC prefix + character
                let mut buf = vec![0x1b];
                let mut char_buf = [0u8; 4];
                let s = c.encode_utf8(&mut char_buf);
                buf.extend_from_slice(s.as_bytes());
                buf
            } else {
                // Plain character (possibly with shift, which is implicit in the char value).
                let mut buf = [0u8; 4];
                let s = c.encode_utf8(&mut buf);
                s.as_bytes().to_vec()
            }
        }

        // ── Whitespace / editing keys ──
        KeyCode::Enter => vec![b'\r'],
        KeyCode::Backspace => {
            if alt {
                vec![0x1b, 0x7f] // Alt+Backspace (delete word)
            } else {
                vec![0x7f]
            }
        }
        KeyCode::Tab => {
            if shift {
                b"\x1b[Z".to_vec() // Shift+Tab (backtab / reverse tab)
            } else {
                vec![b'\t']
            }
        }
        KeyCode::Delete => {
            if ctrl {
                b"\x1b[3;5~".to_vec()
            } else if shift {
                b"\x1b[3;2~".to_vec()
            } else if alt {
                b"\x1b[3;3~".to_vec()
            } else {
                b"\x1b[3~".to_vec()
            }
        }
        KeyCode::Insert => {
            if shift {
                b"\x1b[2;2~".to_vec()
            } else {
                b"\x1b[2~".to_vec()
            }
        }

        // ── Arrow keys (with modifiers) ──
        KeyCode::Up => arrow_with_modifiers(b'A', ctrl, alt, shift),
        KeyCode::Down => arrow_with_modifiers(b'B', ctrl, alt, shift),
        KeyCode::Right => arrow_with_modifiers(b'C', ctrl, alt, shift),
        KeyCode::Left => arrow_with_modifiers(b'D', ctrl, alt, shift),

        // ── Navigation keys ──
        KeyCode::Home => {
            if ctrl {
                b"\x1b[1;5H".to_vec()
            } else if shift {
                b"\x1b[1;2H".to_vec()
            } else {
                b"\x1b[H".to_vec()
            }
        }
        KeyCode::End => {
            if ctrl {
                b"\x1b[1;5F".to_vec()
            } else if shift {
                b"\x1b[1;2F".to_vec()
            } else {
                b"\x1b[F".to_vec()
            }
        }
        KeyCode::PageUp => {
            if ctrl {
                b"\x1b[5;5~".to_vec()
            } else if shift {
                b"\x1b[5;2~".to_vec()
            } else {
                b"\x1b[5~".to_vec()
            }
        }
        KeyCode::PageDown => {
            if ctrl {
                b"\x1b[6;5~".to_vec()
            } else if shift {
                b"\x1b[6;2~".to_vec()
            } else {
                b"\x1b[6~".to_vec()
            }
        }

        // ── Function keys (F1–F12, with modifier support) ──
        KeyCode::F(n) => f_key_bytes(n, ctrl, alt, shift),

        // ── Esc is handled by the caller (double-tap detection) ──
        KeyCode::Esc => vec![0x1b],

        // ── Anything else: no standard encoding ──
        _ => return None,
    };

    Some(bytes)
}

/// Convert a crossterm `MouseEvent` into an SGR (mode 1006) escape sequence.
///
/// SGR format: `ESC [ < Cb ; Cx ; Cy M` (press) or `ESC [ < Cb ; Cx ; Cy m` (release)
/// where Cb is the button code, Cx/Cy are 1-based column/row.
///
/// Returns `None` for mouse events that don't have a standard encoding
/// (e.g. `MouseEventKind::Moved` without button state on some platforms).
pub fn mouse_to_bytes(mouse: &MouseEvent) -> Option<Vec<u8>> {
    let col = mouse.column + 1; // SGR uses 1-based coordinates
    let row = mouse.row + 1;

    let (button_code, suffix) = match mouse.kind {
        // ── Scroll ──
        MouseEventKind::ScrollUp => (64, 'M'),
        MouseEventKind::ScrollDown => (65, 'M'),
        MouseEventKind::ScrollLeft => (66, 'M'),
        MouseEventKind::ScrollRight => (67, 'M'),

        // ── Button press ──
        MouseEventKind::Down(button) => {
            let code = match button {
                MouseButton::Left => 0,
                MouseButton::Middle => 1,
                MouseButton::Right => 2,
            };
            (apply_mouse_modifiers(code, mouse), 'M')
        }

        // ── Button release ──
        MouseEventKind::Up(button) => {
            let code = match button {
                MouseButton::Left => 0,
                MouseButton::Middle => 1,
                MouseButton::Right => 2,
            };
            (apply_mouse_modifiers(code, mouse), 'm') // lowercase 'm' = release
        }

        // ── Drag (button held + move) ──
        MouseEventKind::Drag(button) => {
            let code = match button {
                MouseButton::Left => 32,   // 0 + 32 (motion flag)
                MouseButton::Middle => 33, // 1 + 32
                MouseButton::Right => 34,  // 2 + 32
            };
            (apply_mouse_modifiers(code, mouse), 'M')
        }

        // ── Move (no button held) ──
        MouseEventKind::Moved => {
            // Button 35 = motion with no button (requires mode 1003 — any-event tracking)
            (apply_mouse_modifiers(35, mouse), 'M')
        }
    };

    Some(format!("\x1b[<{button_code};{col};{row}{suffix}").into_bytes())
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Build an arrow key escape sequence with modifier support.
///
/// Plain: `ESC [ X`
/// With modifiers: `ESC [ 1 ; mod X` where mod = 1 + (shift | alt<<1 | ctrl<<2)
fn arrow_with_modifiers(direction: u8, ctrl: bool, alt: bool, shift: bool) -> Vec<u8> {
    let modifier = modifier_param(ctrl, alt, shift);
    if modifier > 1 {
        format!("\x1b[1;{modifier}{}", direction as char).into_bytes()
    } else {
        vec![0x1b, b'[', direction]
    }
}

/// Compute the xterm modifier parameter: 1 + (shift | alt<<1 | ctrl<<2).
/// Returns 1 when no modifiers are active (meaning "no modifier param needed").
fn modifier_param(ctrl: bool, alt: bool, shift: bool) -> u8 {
    let mut m = 0u8;
    if shift {
        m |= 1;
    }
    if alt {
        m |= 2;
    }
    if ctrl {
        m |= 4;
    }
    m + 1
}

/// Encode an F-key (F1–F12) with optional modifier support.
fn f_key_bytes(n: u8, ctrl: bool, alt: bool, shift: bool) -> Vec<u8> {
    let modifier = modifier_param(ctrl, alt, shift);
    let has_mod = modifier > 1;

    match n {
        // F1-F4 use the SS3 / CSI O format without modifiers, CSI 1;mod P-S with.
        1 => {
            if has_mod {
                format!("\x1b[1;{modifier}P").into_bytes()
            } else {
                b"\x1bOP".to_vec()
            }
        }
        2 => {
            if has_mod {
                format!("\x1b[1;{modifier}Q").into_bytes()
            } else {
                b"\x1bOQ".to_vec()
            }
        }
        3 => {
            if has_mod {
                format!("\x1b[1;{modifier}R").into_bytes()
            } else {
                b"\x1bOR".to_vec()
            }
        }
        4 => {
            if has_mod {
                format!("\x1b[1;{modifier}S").into_bytes()
            } else {
                b"\x1bOS".to_vec()
            }
        }
        // F5-F12 use CSI number ~ format.
        5 => tilde_key(15, modifier, has_mod),
        6 => tilde_key(17, modifier, has_mod),
        7 => tilde_key(18, modifier, has_mod),
        8 => tilde_key(19, modifier, has_mod),
        9 => tilde_key(20, modifier, has_mod),
        10 => tilde_key(21, modifier, has_mod),
        11 => tilde_key(23, modifier, has_mod),
        12 => tilde_key(24, modifier, has_mod),
        _ => Vec::new(), // F13+ are non-standard
    }
}

/// Encode a tilde-style key: `ESC [ number ~` or `ESC [ number ; mod ~`.
fn tilde_key(number: u8, modifier: u8, has_mod: bool) -> Vec<u8> {
    if has_mod {
        format!("\x1b[{number};{modifier}~").into_bytes()
    } else {
        format!("\x1b[{number}~").into_bytes()
    }
}

/// Apply keyboard modifier flags to an SGR mouse button code.
/// SGR adds: +4 for shift, +8 for alt, +16 for ctrl.
fn apply_mouse_modifiers(base_code: u8, mouse: &MouseEvent) -> u8 {
    let mut code = base_code;
    if mouse
        .modifiers
        .contains(crossterm::event::KeyModifiers::SHIFT)
    {
        code += 4;
    }
    if mouse
        .modifiers
        .contains(crossterm::event::KeyModifiers::ALT)
    {
        code += 8;
    }
    if mouse
        .modifiers
        .contains(crossterm::event::KeyModifiers::CONTROL)
    {
        code += 16;
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState};

    fn make_key(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: mods,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    #[test]
    fn plain_char() {
        let bytes = key_to_bytes(&make_key(KeyCode::Char('a'), KeyModifiers::NONE)).unwrap();
        assert_eq!(bytes, b"a");
    }

    #[test]
    fn ctrl_c() {
        let bytes = key_to_bytes(&make_key(KeyCode::Char('c'), KeyModifiers::CONTROL)).unwrap();
        assert_eq!(bytes, vec![3]); // ASCII ETX
    }

    #[test]
    fn alt_letter() {
        let bytes = key_to_bytes(&make_key(KeyCode::Char('d'), KeyModifiers::ALT)).unwrap();
        assert_eq!(bytes, vec![0x1b, b'd']); // ESC + d
    }

    #[test]
    fn shift_tab() {
        let bytes = key_to_bytes(&make_key(KeyCode::Tab, KeyModifiers::SHIFT)).unwrap();
        assert_eq!(bytes, b"\x1b[Z");
    }

    #[test]
    fn plain_arrow_keys() {
        assert_eq!(
            key_to_bytes(&make_key(KeyCode::Up, KeyModifiers::NONE)).unwrap(),
            b"\x1b[A"
        );
        assert_eq!(
            key_to_bytes(&make_key(KeyCode::Down, KeyModifiers::NONE)).unwrap(),
            b"\x1b[B"
        );
    }

    #[test]
    fn ctrl_arrow() {
        // Ctrl modifier param = 1 + 4 = 5
        let bytes = key_to_bytes(&make_key(KeyCode::Right, KeyModifiers::CONTROL)).unwrap();
        assert_eq!(bytes, b"\x1b[1;5C");
    }

    #[test]
    fn shift_arrow() {
        // Shift modifier param = 1 + 1 = 2
        let bytes = key_to_bytes(&make_key(KeyCode::Left, KeyModifiers::SHIFT)).unwrap();
        assert_eq!(bytes, b"\x1b[1;2D");
    }

    #[test]
    fn alt_backspace() {
        let bytes = key_to_bytes(&make_key(KeyCode::Backspace, KeyModifiers::ALT)).unwrap();
        assert_eq!(bytes, vec![0x1b, 0x7f]);
    }

    #[test]
    fn f_keys_plain() {
        assert_eq!(
            key_to_bytes(&make_key(KeyCode::F(1), KeyModifiers::NONE)).unwrap(),
            b"\x1bOP"
        );
        assert_eq!(
            key_to_bytes(&make_key(KeyCode::F(5), KeyModifiers::NONE)).unwrap(),
            b"\x1b[15~"
        );
        assert_eq!(
            key_to_bytes(&make_key(KeyCode::F(12), KeyModifiers::NONE)).unwrap(),
            b"\x1b[24~"
        );
    }

    #[test]
    fn page_up_down() {
        assert_eq!(
            key_to_bytes(&make_key(KeyCode::PageUp, KeyModifiers::NONE)).unwrap(),
            b"\x1b[5~"
        );
        assert_eq!(
            key_to_bytes(&make_key(KeyCode::PageDown, KeyModifiers::NONE)).unwrap(),
            b"\x1b[6~"
        );
    }

    #[test]
    fn insert_key() {
        assert_eq!(
            key_to_bytes(&make_key(KeyCode::Insert, KeyModifiers::NONE)).unwrap(),
            b"\x1b[2~"
        );
    }

    #[test]
    fn mouse_scroll_up() {
        let mouse = MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 9,
            row: 4,
            modifiers: KeyModifiers::NONE,
        };
        assert_eq!(mouse_to_bytes(&mouse).unwrap(), b"\x1b[<64;10;5M");
    }

    #[test]
    fn mouse_left_click() {
        let mouse = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        };
        assert_eq!(mouse_to_bytes(&mouse).unwrap(), b"\x1b[<0;1;1M");
    }

    #[test]
    fn mouse_left_release() {
        let mouse = MouseEvent {
            kind: MouseEventKind::Up(MouseButton::Left),
            column: 5,
            row: 10,
            modifiers: KeyModifiers::NONE,
        };
        // Lowercase 'm' for release
        assert_eq!(mouse_to_bytes(&mouse).unwrap(), b"\x1b[<0;6;11m");
    }

    #[test]
    fn mouse_right_click() {
        let mouse = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Right),
            column: 3,
            row: 7,
            modifiers: KeyModifiers::NONE,
        };
        assert_eq!(mouse_to_bytes(&mouse).unwrap(), b"\x1b[<2;4;8M");
    }

    #[test]
    fn mouse_drag() {
        let mouse = MouseEvent {
            kind: MouseEventKind::Drag(MouseButton::Left),
            column: 1,
            row: 2,
            modifiers: KeyModifiers::NONE,
        };
        // Drag = button 0 + 32 (motion flag) = 32
        assert_eq!(mouse_to_bytes(&mouse).unwrap(), b"\x1b[<32;2;3M");
    }

    #[test]
    fn mouse_ctrl_click() {
        let mouse = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 0,
            row: 0,
            modifiers: KeyModifiers::CONTROL,
        };
        // Button 0 + 16 (ctrl) = 16
        assert_eq!(mouse_to_bytes(&mouse).unwrap(), b"\x1b[<16;1;1M");
    }

    #[test]
    fn mouse_move() {
        let mouse = MouseEvent {
            kind: MouseEventKind::Moved,
            column: 10,
            row: 20,
            modifiers: KeyModifiers::NONE,
        };
        // Move = button 35 (no button + motion)
        assert_eq!(mouse_to_bytes(&mouse).unwrap(), b"\x1b[<35;11;21M");
    }
}
