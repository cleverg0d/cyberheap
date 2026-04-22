package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/cleverg0d/cyberheap/internal/scanner"
)

// ANSI escape sequences.
const (
	cReset     = "\x1b[0m"
	cBold      = "\x1b[1m"
	cDim       = "\x1b[2m"
	cUnderline = "\x1b[4m"

	// Base 8 colors.
	cRed     = "\x1b[31m"
	cGreen   = "\x1b[32m"
	cYellow  = "\x1b[33m"
	cBlue    = "\x1b[34m"
	cMagenta = "\x1b[35m"
	cCyan    = "\x1b[36m"
	cGrey    = "\x1b[90m"

	// Bright variants — better contrast on dark terminals.
	cBRed     = "\x1b[91m"
	cBGreen   = "\x1b[92m"
	cBYellow  = "\x1b[93m"
	cBBlue    = "\x1b[94m"
	cBMagenta = "\x1b[95m"
	cBCyan    = "\x1b[96m"
)

// sevStyle picks the open+close ANSI pair for a severity.
//
// CRITICAL : bright magenta, bold — the "you must look at this" color.
// HIGH     : red.
// MEDIUM   : yellow.
// LOW      : green.
// INFO     : blue.
func sevStyle(sev scanner.Severity, noColor bool) (string, string) {
	if noColor {
		return "", ""
	}
	switch sev {
	case scanner.SeverityCritical:
		return cBold + cBMagenta, cReset
	case scanner.SeverityHigh:
		return cBRed, cReset
	case scanner.SeverityMedium:
		return cBYellow, cReset
	case scanner.SeverityLow:
		return cBGreen, cReset
	case scanner.SeverityInfo:
		return cDim, cReset
	default:
		return cDim, cReset
	}
}

// sevBullet returns a colored filled circle for the summary line.
func sevBullet(sev scanner.Severity, noColor bool) string {
	open, close := sevStyle(sev, noColor)
	return open + "●" + close
}

// termWidth reads COLUMNS from the environment or falls back to 100.
// Avoids pulling in golang.org/x/term just to ask the tty size — good enough
// for CLI output and lets the user resize via `COLUMNS=140 cyberheap ...`.
func termWidth() int {
	if s := os.Getenv("COLUMNS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 40 && n < 500 {
			return n
		}
	}
	return 100
}

// bannerArt is the figlet "cybermedium" rendering of CYBERHEAP.
// Backslashes are escaped ("\\") because we use regular, not raw, strings.
var bannerArt = []string{
	` ____ _   _ ___  ____ ____ _  _ ____ ____ ___ `,
	`|     \_/  |__] |___ |__/ |__| |___ |__| |__]`,
	`|___   |   |__] |___ |  \ |  | |___ |  | |   `,
}

// banner returns a multi-line framed banner: the CyberHeap ASCII art, a
// blank spacer, and the version/tagline centered underneath.
//
// All width math is in runes so box-drawing characters and the middle-dot
// separator don't throw the right edge off.
func banner(version string, noColor bool) string {
	art := make([]string, len(bannerArt))
	artWidth := 0
	for i, line := range bannerArt {
		if n := utf8.RuneCountInString(line); n > artWidth {
			artWidth = n
		}
		art[i] = line
	}
	// Normalize ASCII-art lines to the widest one.
	for i, line := range art {
		if diff := artWidth - utf8.RuneCountInString(line); diff > 0 {
			art[i] = line + strings.Repeat(" ", diff)
		}
	}

	tagline := fmt.Sprintf("v%s  ·  HPROF secret scanner  ·  by clevergod", version)
	tagWidth := utf8.RuneCountInString(tagline)

	// Pick the widest of {art, tagline} and add a small horizontal margin.
	inner := artWidth
	if tagWidth > inner {
		inner = tagWidth
	}
	inner += 4 // 2-space left & right padding

	top := "╔" + strings.Repeat("═", inner) + "╗"
	bot := "╚" + strings.Repeat("═", inner) + "╝"

	// center pads s to exactly `width` runes.
	center := func(s string, width int) string {
		n := utf8.RuneCountInString(s)
		if n >= width {
			return s
		}
		left := (width - n) / 2
		right := width - n - left
		return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
	}

	var lines []string
	lines = append(lines, top)
	for _, a := range art {
		lines = append(lines, "║"+center(a, inner)+"║")
	}
	lines = append(lines, "║"+center("", inner)+"║")
	lines = append(lines, "║"+center(tagline, inner)+"║")
	lines = append(lines, bot)

	if noColor {
		return strings.Join(lines, "\n") + "\n"
	}

	frame := cBold + cBCyan
	var sb strings.Builder
	for _, line := range lines {
		sb.WriteString(frame)
		sb.WriteString(line)
		sb.WriteString(cReset)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// sectionDivider prints an ANSI-colored rule with the severity name centered.
// Example:  ────── HIGH ───────────────────────────────────────────
func sectionDivider(sev scanner.Severity, noColor bool) string {
	label := " " + sev.String() + " "
	full := termWidth()
	if full > 80 {
		full = 80
	}
	side := (full - len(label)) / 2
	if side < 3 {
		side = 3
	}
	open, close := sevStyle(sev, noColor)
	return open + strings.Repeat("─", side) + label + strings.Repeat("─", full-side-len(label)) + close
}

// kvLine renders a "Key   value" row used in the header block.
func kvLine(key, val string, noColor bool) string {
	k := key
	if !noColor {
		k = cDim + key + cReset
	}
	return fmt.Sprintf("  %-10s  %s", k, val)
}
