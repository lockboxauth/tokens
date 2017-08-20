package pqarrays

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	eof        = -1
	leftDelim  = "{"
	rightDelim = "}"
	separator  = ','
)

type tokenType int

const (
	tokenError tokenType = iota
	tokenWhitespace
	tokenArrayStart
	tokenString
	tokenNull
	tokenSeparator
	tokenArrayEnd
	tokenEOF
)

func (t tokenType) String() string {
	switch t {
	case tokenError:
		return "error"
	case tokenWhitespace:
		return "whitespace"
	case tokenArrayStart:
		return "array start"
	case tokenString:
		return "string"
	case tokenNull:
		return "null"
	case tokenSeparator:
		return "separator"
	case tokenArrayEnd:
		return "array end"
	case tokenEOF:
		return "eof"
	default:
		return "unknown token"
	}
}

type stateFunc func(*lexer) stateFunc

type lexer struct {
	tokens     chan token
	input      string
	start      int
	pos        int
	omitted    []int
	width      int
	state      stateFunc
	arrayDepth int
}

type token struct {
	typ tokenType
	val string
}

func (t token) String() string {
	return fmt.Sprintf("%s: %s", t.typ.String(), t.val)
}

func lex(input string) *lexer {
	l := &lexer{
		input:  input,
		tokens: make(chan token),
	}
	go l.run()
	return l
}

func (l *lexer) nextToken() token {
	return <-l.tokens
}

func (l *lexer) run() {
	for l.state = lexStart; l.state != nil; {
		l.state = l.state(l)
	}
}

func (l *lexer) emit(t tokenType) {
	var val string
	if len(l.omitted) < 1 {
		val = l.input[l.start:l.pos]
	} else {
		start := l.start
		for _, pos := range l.omitted {
			val += l.input[start:pos]
			start = pos + 1
		}
		if l.pos > start {
			val += l.input[start:l.pos]
		}
	}
	l.tokens <- token{typ: t, val: val}
	l.start = l.pos
	l.omitted = l.omitted[0:0]
}

func (l *lexer) next() rune {
	if l.pos >= len(l.input) {
		l.width = 0
		return eof
	}
	var r rune
	r, l.width = utf8.DecodeRuneInString(l.input[l.pos:])
	l.pos += l.width
	return r
}

func (l *lexer) omit() {
	l.omitted = append(l.omitted, l.pos-1)
}

func (l *lexer) ignore() {
	l.start = l.pos
}

func (l *lexer) backup() {
	l.pos -= l.width
}

func (l *lexer) peek() rune {
	r := l.next()
	l.backup()
	return r
}

func (l *lexer) accept(valid string) bool {
	if strings.IndexRune(valid, l.next()) >= 0 {
		return true
	}
	l.backup()
	return false
}

func (l *lexer) acceptRun(valid string) {
	for strings.IndexRune(valid, l.next()) >= 0 {
	}
	l.backup()
}

func (l *lexer) errorf(format string, args ...interface{}) stateFunc {
	l.tokens <- token{tokenError, fmt.Sprintf(format, args...)}
	return nil
}

func (l *lexer) consumeWhitespace() {
	for unicode.IsSpace(l.peek()) {
		l.next()
	}
	if l.pos > l.start {
		l.emit(tokenWhitespace)
	}
}

func lexStart(l *lexer) stateFunc {
	l.consumeWhitespace()
	return lexArrayStart
}

func lexArrayStart(l *lexer) stateFunc {
	if strings.HasPrefix(l.input[l.pos:], leftDelim) {
		return lexLeftDelim
	}
	return l.errorf("expected array to start before %s", l.input[l.pos:])
}

func lexLeftDelim(l *lexer) stateFunc {
	l.pos += len(leftDelim)
	l.emit(tokenArrayStart)
	l.arrayDepth++
	return lexItem
}

func lexRightDelim(l *lexer) stateFunc {
	l.pos += len(rightDelim)
	l.emit(tokenArrayEnd)
	l.arrayDepth--
	return lexSeparator
}

func lexItem(l *lexer) stateFunc {
	l.consumeWhitespace()
	if strings.HasPrefix(l.input[l.pos:], rightDelim) {
		return lexRightDelim
	}
	if strings.HasPrefix(l.input[l.pos:], leftDelim) {
		return lexLeftDelim
	}
	switch r := l.peek(); {
	case r == eof:
		return l.errorf("unclosed array")
	case r == separator:
		return l.errorf("empty item in array")
	case unicode.IsSpace(r):
		return lexItem
	case r == '"':
		return lexQuotedString
	default:
		return lexString
	}
}

func lexQuotedString(l *lexer) stateFunc {
	l.next()
	l.ignore() // ignore the open quote
	for {
		switch r := l.next(); {
		case r == eof:
			return l.errorf("unclosed quoted string")
		case r == '"':
			l.backup()
			l.emit(tokenString)
			l.next()
			l.ignore()
			return lexSeparator
		case r == '\\':
			// omit the \ itself
			l.omit()
			// always skip over the character following a \
			l.next()
			if r == eof {
				return l.errorf("unclosed quoted string")
			}
		}
	}
}

func lexString(l *lexer) stateFunc {
	for {
		if strings.HasPrefix(l.input[l.pos:], leftDelim) {
			return l.errorf(leftDelim + " in unquoted string")
		}
		if strings.HasPrefix(l.input[l.pos:], rightDelim) {
			if l.pos <= l.start {
				return l.errorf(rightDelim + " in unquoted string")
			}
			lastNonSpace := -1
			s := l.input[l.start:l.pos]
			for pos, r := range s {
				if !unicode.IsSpace(r) {
					lastNonSpace = l.start + pos + 1
				}
			}
			if lastNonSpace < 0 {
				return l.errorf("unquoted empty string")
			}
			for lastNonSpace < l.pos {
				l.backup()
			}
			if string(l.input[l.start:l.pos]) == "NULL" {
				l.emit(tokenNull)
			} else {
				l.emit(tokenString)
			}
			l.consumeWhitespace()
			return lexRightDelim
		}
		switch r := l.next(); {
		case r == eof:
			return l.errorf("eof while parsing string")
		case r == '"':
			return l.errorf("\" in unquoted string")
		case r == '\\':
			return l.errorf("\\ in unquoted string")
		case r == separator:
			l.backup()
			if l.pos <= l.start {
				return l.errorf("unquoted empty string")
			}
			if string(l.input[l.start:l.pos]) == "NULL" {
				l.emit(tokenNull)
			} else {
				l.emit(tokenString)
			}
			return lexSeparator
		}
	}
}

func lexSeparator(l *lexer) stateFunc {
	l.consumeWhitespace()
	if strings.HasPrefix(l.input[l.pos:], rightDelim) {
		return lexRightDelim
	}
	r := l.next()
	if r == separator {
		l.emit(tokenSeparator)
		return lexItem
	} else if r == eof {
		if l.arrayDepth > 0 {
			return l.errorf("unclosed array")
		}
		l.emit(tokenEOF)
		return nil
	} else {
		l.backup()
		return l.errorf("expected %s, none found before %s\n", string(separator), l.input[l.pos:])
	}
}
