package pqarrays

import (
	"errors"
)

func parse(l *lexer) ([]*string, error) {
	var parsed []*string
	pchan := make(chan *string)
	errchan := make(chan error)
	done := make(chan struct{})
	go runParse(l, pchan, errchan, done)
	for {
		select {
		case err := <-errchan:
			return parsed, err
		case item := <-pchan:
			parsed = append(parsed, item)
		case <-done:
			return parsed, nil
		}
	}
}

func runParse(l *lexer, parsed chan *string, err chan error, done chan struct{}) {
	var state parseFunc = parseStart
	for {
		var e error
		state, e = state(l, parsed)
		if e != nil {
			err <- e
			break
		}
		if state == nil {
			break
		}
	}
	close(done)
}

type parseFunc func(*lexer, chan *string) (parseFunc, error)

func parseEOF(l *lexer, parsed chan *string) (parseFunc, error) {
	tok := l.nextToken()
	if tok.typ == tokenWhitespace {
		return parseEOF, nil
	}
	if tok.typ != tokenEOF {
		return nil, errors.New("expected EOF, got " + tok.String())
	}
	return nil, nil
}

func parseStringOrNull(l *lexer, parsed chan *string) (parseFunc, error) {
	tok := l.nextToken()
	if tok.typ == tokenWhitespace {
		return parseStringOrNull, nil
	} else if tok.typ == tokenString {
		parsed <- &tok.val
		return parseSeparatorOrDelim, nil
	} else if tok.typ == tokenNull {
		parsed <- nil
		return parseSeparatorOrDelim, nil
	}
	return nil, errors.New("expected string, got " + tok.String())
}

func parseStringOrNullOrEnd(l *lexer, parsed chan *string) (parseFunc, error) {
	tok := l.nextToken()
	if tok.typ == tokenWhitespace {
		return parseStringOrNullOrEnd, nil
	} else if tok.typ == tokenString {
		parsed <- &tok.val
		return parseSeparatorOrDelim, nil
	} else if tok.typ == tokenNull {
		parsed <- nil
		return parseSeparatorOrDelim, nil
	} else if tok.typ == tokenArrayEnd {
		return parseEOF, nil
	}
	return nil, errors.New("Expected string or end, got " + tok.String())
}

func parseSeparatorOrDelim(l *lexer, parsed chan *string) (parseFunc, error) {
	tok := l.nextToken()
	if tok.typ == tokenWhitespace {
		return parseSeparatorOrDelim, nil
	} else if tok.typ == tokenSeparator {
		return parseStringOrNull, nil
	} else if tok.typ == tokenArrayEnd {
		return parseEOF, nil
	}
	return nil, errors.New("expected separator or delim, got " + tok.String())
}

func parseStart(l *lexer, parsed chan *string) (parseFunc, error) {
	tok := l.nextToken()
	if tok.typ == tokenWhitespace {
		return parseStart, nil
	} else if tok.typ == tokenArrayStart {
		return parseStringOrNullOrEnd, nil
	}
	return nil, errors.New("expected separator or delim, got " + tok.String())
}
