package goreplay

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// HTTPModifierConfig holds configuration options for built-in traffic modifier
type HTTPModifierConfig struct {
	URLNegativeRegexp      HTTPURLRegexp              `json:"http-disallow-url"`
	URLRegexp              HTTPURLRegexp              `json:"http-allow-url"`
	URLRewrite             URLRewriteMap              `json:"http-rewrite-url"`
	HeaderRewrite          HeaderRewriteMap           `json:"http-rewrite-header"`
	HeaderFilters          HTTPHeaderFilters          `json:"http-allow-header"`
	HeaderNegativeFilters  HTTPHeaderFilters          `json:"http-disallow-header"`
	HeaderBasicAuthFilters HTTPHeaderBasicAuthFilters `json:"http-basic-auth-filter"`
	HeaderHashFilters      HTTPHashFilters            `json:"http-header-limiter"`
	ParamHashFilters       HTTPHashFilters            `json:"http-param-limiter"`
	Params                 HTTPParams                 `json:"http-set-param"`
	Headers                HTTPHeaders                `json:"http-set-header"`
	Methods                HTTPMethods                `json:"http-allow-method"`
}

// Handling of --http-allow-header, --http-disallow-header options
type headerFilter struct {
	name   []byte
	regexp *regexp.Regexp
}

// HTTPHeaderFilters holds list of headers and their regexps
type HTTPHeaderFilters []headerFilter

func (h *HTTPHeaderFilters) String() string {
	return fmt.Sprint(*h)
}

// Set method to implement flags.Value
func (h *HTTPHeaderFilters) Set(value string) error {
	valArr := strings.SplitN(value, ":", 2)
	if len(valArr) < 2 {
		return errors.New("need both header and value, colon-delimited (ex. user_id:^169$)")
	}
	val := strings.TrimSpace(valArr[1])
	r, err := regexp.Compile(val)
	if err != nil {
		return err
	}

	*h = append(*h, headerFilter{name: []byte(valArr[0]), regexp: r})

	return nil
}

// Handling of --http-basic-auth-filter option
type basicAuthFilter struct {
	regexp *regexp.Regexp
}

// HTTPHeaderBasicAuthFilters holds list of regxp to match basic Auth header values
type HTTPHeaderBasicAuthFilters []basicAuthFilter

func (h *HTTPHeaderBasicAuthFilters) String() string {
	return fmt.Sprint(*h)
}

// Set method to implement flags.Value
func (h *HTTPHeaderBasicAuthFilters) Set(value string) error {
	r, err := regexp.Compile(value)
	if err != nil {
		return err
	}

	*h = append(*h, basicAuthFilter{regexp: r})

	return nil
}

// Handling of --http-allow-header-hash and --http-allow-param-hash options
type hashFilter struct {
	name    []byte
	percent uint32
}

// HTTPHashFilters represents a slice of header hash filters
type HTTPHashFilters []hashFilter

func (h *HTTPHashFilters) String() string {
	return fmt.Sprint(*h)
}

// Set method to implement flags.Value
func (h *HTTPHashFilters) Set(value string) error {
	valArr := strings.SplitN(value, ":", 2)
	if len(valArr) < 2 {
		return errors.New("need both header and value, colon-delimited (ex. user_id:50%)")
	}

	f := hashFilter{name: []byte(valArr[0])}

	val := strings.TrimSpace(valArr[1])

	if strings.Contains(val, "%") {
		p, _ := strconv.ParseInt(val[:len(val)-1], 0, 0)
		f.percent = uint32(p)
	} else if strings.Contains(val, "/") {
		// DEPRECATED format
		var num, den uint64

		fracArr := strings.Split(val, "/")
		num, _ = strconv.ParseUint(fracArr[0], 10, 64)
		den, _ = strconv.ParseUint(fracArr[1], 10, 64)

		f.percent = uint32((float64(num) / float64(den)) * 100)
	} else {
		return errors.New("Value should be percent and contain '%'")
	}

	*h = append(*h, f)

	return nil
}

// Handling of --http-set-header option
type httpHeader struct {
	Name  string
	Value string
}

// HTTPHeaders is a slice of headers that must appended
type HTTPHeaders []httpHeader

func (h *HTTPHeaders) String() string {
	return fmt.Sprint(*h)
}

// Set method to implement flags.Value
func (h *HTTPHeaders) Set(value string) error {
	v := strings.SplitN(value, ":", 2)
	if len(v) != 2 {
		return errors.New("Expected `Key: Value`")
	}

	header := httpHeader{
		strings.TrimSpace(v[0]),
		strings.TrimSpace(v[1]),
	}

	*h = append(*h, header)
	return nil
}

// Handling of --http-set-param option
type httpParam struct {
	Name  []byte
	Value []byte
}

// HTTPParams filters for --http-set-param
type HTTPParams []httpParam

func (h *HTTPParams) String() string {
	return fmt.Sprint(*h)
}

// Set method to implement flags.Value
func (h *HTTPParams) Set(value string) error {
	v := strings.SplitN(value, "=", 2)
	if len(v) != 2 {
		return errors.New("Expected `Key=Value`")
	}

	param := httpParam{
		[]byte(strings.TrimSpace(v[0])),
		[]byte(strings.TrimSpace(v[1])),
	}

	*h = append(*h, param)
	return nil
}

//
// Handling of --http-allow-method option
//

// HTTPMethods holds values for method allowed
type HTTPMethods [][]byte

func (h *HTTPMethods) String() string {
	return fmt.Sprint(*h)
}

// Set method to implement flags.Value
func (h *HTTPMethods) Set(value string) error {
	*h = append(*h, []byte(value))
	return nil
}

type replaceSegment struct {
	literal []byte
	group   int
	name    string
}

type replaceTemplate struct {
	segments []replaceSegment
}

func parseReplaceTemplate(template []byte) (*replaceTemplate, error) {
	rt := &replaceTemplate{}
	var literal []byte
	i := 0
	for i < len(template) {
		if template[i] == '$' && i+1 < len(template) {
			j := i + 1
			if template[j] == '$' {
				literal = append(literal, '$')
				i += 2
				continue
			}
			if len(literal) > 0 {
				rt.segments = append(rt.segments, replaceSegment{literal: append([]byte(nil), literal...)})
				literal = literal[:0]
			}
			if template[j] == '{' {
				end := bytes.IndexByte(template[j+1:], '}')
				if end < 0 {
					return nil, fmt.Errorf("unclosed ${ in replacement template")
				}
				name := template[j+1 : j+1+end]
				if len(name) > 0 && name[0] >= '0' && name[0] <= '9' {
					n, err := strconv.Atoi(string(name))
					if err != nil {
						return nil, fmt.Errorf("invalid capture group reference ${%s}: %w", name, err)
					}
					rt.segments = append(rt.segments, replaceSegment{group: n})
				} else {
					rt.segments = append(rt.segments, replaceSegment{name: string(name)})
				}
				i = j + 1 + end + 1
				continue
			}
			numStart := j
			for j < len(template) && template[j] >= '0' && template[j] <= '9' {
				j++
			}
			if j == numStart {
				literal = append(literal, '$')
				i++
				continue
			}
			n, err := strconv.Atoi(string(template[numStart:j]))
			if err != nil {
				return nil, fmt.Errorf("invalid capture group reference: %w", err)
			}
			rt.segments = append(rt.segments, replaceSegment{group: n})
			i = j
			continue
		}
		literal = append(literal, template[i])
		i++
	}
	if len(literal) > 0 {
		rt.segments = append(rt.segments, replaceSegment{literal: append([]byte(nil), literal...)})
	}
	return rt, nil
}

func (rt *replaceTemplate) expand(src []byte, match []int, re *regexp.Regexp) []byte {
	var result []byte
	for _, seg := range rt.segments {
		if seg.literal != nil {
			result = append(result, seg.literal...)
			continue
		}
		groupIdx := seg.group
		if seg.name != "" {
			for i, name := range re.SubexpNames() {
				if name == seg.name {
					groupIdx = i
					break
				}
			}
		}
		if groupIdx*2+1 < len(match) && match[groupIdx*2] >= 0 {
			result = append(result, src[match[groupIdx*2]:match[groupIdx*2+1]]...)
		}
	}
	return result
}

// Handling of --http-rewrite-url option
type urlRewrite struct {
	src    *regexp.Regexp
	tmpl   *replaceTemplate
}

// URLRewriteMap holds regexp and data to modify URL
type URLRewriteMap []urlRewrite

func (r *URLRewriteMap) String() string {
	return fmt.Sprint(*r)
}

// Set method to implement flags.Value
func (r *URLRewriteMap) Set(value string) error {
	var pattern, replacement string

	if strings.HasPrefix(value, "s/") {
		parts := strings.SplitN(value[2:], "/", 3)
		if len(parts) < 3 {
			return fmt.Errorf("invalid s/pattern/replacement/ format: %q. Expected: s/pattern/replacement/", value)
		}
		pattern = parts[0]
		replacement = parts[1]
	} else {
		valArr := strings.SplitN(value, ":", 2)
		if len(valArr) < 2 {
			return errors.New("need both src and target, colon-delimited (ex. /a:/b) or s/pattern/replacement/ format")
		}
		pattern = valArr[0]
		replacement = valArr[1]
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("failed to compile regexp %q: %w", pattern, err)
	}
	tmpl, err := parseReplaceTemplate([]byte(replacement))
	if err != nil {
		return fmt.Errorf("failed to parse replacement %q: %w", replacement, err)
	}
	*r = append(*r, urlRewrite{src: re, tmpl: tmpl})
	return nil
}

// Handling of --http-rewrite-header option
type headerRewrite struct {
	header []byte
	src    *regexp.Regexp
	tmpl   *replaceTemplate
}

// HeaderRewriteMap holds regexp and data to rewrite headers
type HeaderRewriteMap []headerRewrite

func (r *HeaderRewriteMap) String() string {
	return fmt.Sprint(*r)
}

// Set method to implement flags.Value
func (r *HeaderRewriteMap) Set(value string) error {
	headerArr := strings.SplitN(value, ":", 2)
	if len(headerArr) < 2 {
		return errors.New("need both header, regexp and rewrite target, colon-delimited (ex. Header: regexp,target)")
	}

	header := headerArr[0]
	valArr := strings.SplitN(strings.TrimSpace(headerArr[1]), ",", 2)

	if len(valArr) < 2 {
		return errors.New("need both header, regexp and rewrite target, colon-delimited (ex. Header: regexp,target)")
	}

	re, err := regexp.Compile(valArr[0])
	if err != nil {
		return err
	}
	tmpl, err := parseReplaceTemplate([]byte(valArr[1]))
	if err != nil {
		return err
	}
	*r = append(*r, headerRewrite{header: []byte(header), src: re, tmpl: tmpl})
	return nil
}

// Handling of --http-allow-url option
type urlRegexp struct {
	regexp *regexp.Regexp
}

// HTTPURLRegexp a slice of regexp to match URLs
type HTTPURLRegexp []urlRegexp

func (r *HTTPURLRegexp) String() string {
	return fmt.Sprint(*r)
}

// Set method to implement flags.Value
func (r *HTTPURLRegexp) Set(value string) error {
	regexp, err := regexp.Compile(value)

	*r = append(*r, urlRegexp{regexp: regexp})

	return err
}
