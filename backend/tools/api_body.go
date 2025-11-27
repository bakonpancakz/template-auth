package tools

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
)

// Use Built-in Validator against Request Body
func ValidateBody(w http.ResponseWriter, r *http.Request, b any) bool {
	structErrors, err := ValidateStruct(b)
	if err != nil {
		SendServerError(w, r, err)
		return false
	}
	if len(structErrors) > 0 {
		SendJSON(w, r, ERROR_BODY_INVALID_FIELD.Status, map[string]any{
			"code":    ERROR_BODY_INVALID_FIELD.Code,
			"message": ERROR_BODY_INVALID_FIELD.Message,
			"errors":  structErrors,
		})
		return false
	}
	return true
}

// Decode Incoming JSON Request
func BindJSON(w http.ResponseWriter, r *http.Request, b any) bool {

	// Additional Validation
	header := strings.ToLower(r.Header.Get("Content-Type"))
	if !strings.HasPrefix(header, "application/json") {
		SendClientError(w, r, ERROR_BODY_INVALID_TYPE)
		return false
	}
	defer r.Body.Close()

	// Decode as stream, lower memory usage and earlier returns
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(b); err != nil {
		SendClientError(w, r, ERROR_BODY_INVALID_DATA)
		return false
	}

	return true
}

// Decode and Validate Incoming JSON Request
func ValidateJSON(w http.ResponseWriter, r *http.Request, b any) bool {
	if !BindJSON(w, r, b) {
		return false
	}
	return ValidateBody(w, r, b)
}

// Decode Incoming Query Parameters
func BindQuery(w http.ResponseWriter, r *http.Request, b any) bool {
	// Read Incoming Field
	var query url.Values
	switch r.Method {

	// Read Query String from URI
	case http.MethodGet:
		query = r.URL.Query()

	// Read Query String from Body
	case http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete:

		// Validate Content Type Header
		header := strings.ToLower(r.Header.Get("Content-Type"))
		if !strings.HasPrefix(header, "application/x-www-form-urlencoded") {
			SendClientError(w, r, ERROR_BODY_INVALID_TYPE)
			return false
		}
		defer r.Body.Close()

		// Read and Parse Incoming Query Body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			SendClientError(w, r, ERROR_BODY_INVALID_DATA)
			return false
		}
		values, err := url.ParseQuery(string(body))
		if err != nil {
			SendClientError(w, r, ERROR_BODY_INVALID_DATA)
			return false
		}
		query = values

	// Other request methods should not contain a body
	default:
		SendClientError(w, r, ERROR_BODY_INVALID_TYPE)
		return false
	}

	// Fill struct using Query values
	ptrValue := reflect.ValueOf(b)
	if ptrValue.Kind() != reflect.Ptr || ptrValue.IsNil() {
		panic("destination must be a non-nil pointer")
	}
	structValue := ptrValue.Elem()
	structType := structValue.Type()

	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)
		fieldTag := field.Tag.Get("query")
		if fieldTag == "" {
			continue
		}
		fieldValue := structValue.Field(i)

		val := query.Get(fieldTag)
		if val == "" || !fieldValue.CanSet() {
			continue
		}
		target := fieldValue
		isPtr := false

		if fieldValue.Kind() == reflect.Ptr {
			isPtr = true
			elemType := fieldValue.Type().Elem()
			// allocate new value if nil
			if fieldValue.IsNil() {
				fieldValue.Set(reflect.New(elemType))
			}
			target = fieldValue.Elem()
		}

		switch target.Kind() {
		case reflect.String:
			target.SetString(val)
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if n, err := strconv.ParseInt(val, 10, 64); err == nil {
				target.SetInt(n)
			}
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			if n, err := strconv.ParseUint(val, 10, 64); err == nil {
				target.SetUint(n)
			}
		case reflect.Bool:
			if b, err := strconv.ParseBool(val); err == nil {
				target.SetBool(b)
			}
		default:
			if isPtr {
				// If pointer to unsupported type, set to nil
				fieldValue.Set(reflect.Zero(fieldValue.Type()))
			}
		}
	}

	return true
}

// Decode and Validate Incoming Query Parameters
func ValidateQuery(w http.ResponseWriter, r *http.Request, b any) bool {
	if !BindQuery(w, r, b) {
		return false
	}
	return ValidateBody(w, r, b)
}

// Encode and Compress Outgoing Body
func SendJSON(w http.ResponseWriter, r *http.Request, s int, b any) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	// Setup Compression
	var wr io.Writer = w
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		wr = gz
	}
	w.WriteHeader(s)

	// Encode Content
	enc := json.NewEncoder(wr)
	enc.SetEscapeHTML(false)
	return enc.Encode(b)
}
