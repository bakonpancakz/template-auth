package tests

import (
	"encoding/base64"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/bakonpancakz/template-auth/tools"
)

var (
	TEST_ID_INVALID                                   = tools.GenerateSnowflake()
	TEST_ID_INVALID_STRING                            = strconv.FormatInt(TEST_ID_INVALID, 10)
	TEST_ID_PRIMARY                                   = tools.GenerateSnowflake()
	TEST_ID_PRIMARY_STRING                            = strconv.FormatInt(TEST_ID_PRIMARY, 10)
	TEST_ID_SECONDARY                                 = tools.GenerateSnowflake()
	TEST_ID_SECONDARY_STRING                          = strconv.FormatInt(TEST_ID_SECONDARY, 10)
	TEST_TOKEN_INVALID                                = "token"
	TEST_TOKEN_PRIMARY                                = tools.GenerateSignedString()
	TEST_TOKEN_SECONDARY                              = tools.GenerateSignedString()
	TEST_TOKEN_EXPIRES_FUTURE                         = time.Now().AddDate(10, 0, 0)
	TEST_TOKEN_EXPIRES_PAST                           = time.Now().AddDate(-10, 0, 0)
	TEST_EMAIL_INVALID                                = "invalid@email..org"
	TEST_EMAIL_PRIMARY                                = "primary@email.org"
	TEST_EMAIL_SECONDARY                              = "secondary@email.org"
	TEST_USERNAME_INVALID                             = "USER NAME"
	TEST_USERNAME_PRIMARY                             = "bakonpancakz"
	TEST_USERNAME_SECONDARY                           = "bakonwafflecakz"
	TEST_DISPLAYNAME_INVALID                          = "adisplaynamethatissupposedlytoolongtosubmit"
	TEST_DISPLAYNAME_PRIMARY                          = "bakonpancakz!"
	TEST_DISPLAYNAME_SECONDARY                        = "dotpwp?"
	TEST_SUBTITLE_INVALID                             = "asubtitlethatissupposedlytoolongtosubmit"
	TEST_SUBTITLE_PRIMARY                             = "pronouns: they/them"
	TEST_SUBTITLE_SECONDARY                           = "><> .o( blub blub )"
	TEST_BIOGRAPHY_INVALID                            = base64.StdEncoding.EncodeToString(make([]byte, 1024))
	TEST_BIOGRAPHY_PRIMARY                            = "this is my super awesome bio\n\nnotice how it has multiple lines?"
	TEST_BIOGRAPHY_SECONDARY                          = "this one is not as awesome. I keep it all inline B)"
	TEST_COLOR_INVALID                                = -1
	TEST_COLOR_PRIMARY                                = 10594559 // #A1A8FF
	TEST_COLOR_SECONDARY                              = 16711771 // #FF005B
	TEST_PASSWORD_INVALID                             = "weakpassword"
	TEST_PASSWORD_PRIMARY                             = "PearsAndPearsAnd1MorePear!"
	TEST_PASSWORD_PRIMARY_HASH                        = mustHashPassword(TEST_PASSWORD_PRIMARY)
	TEST_PASSWORD_SECONDARY                           = "SicklySweet1273?"
	TEST_PASSWORD_SECONDARY_HASH                      = mustHashPassword(TEST_PASSWORD_SECONDARY)
	TEST_REDIRECT_URI_INVALID                         = "peebs"
	TEST_REDIRECT_URI_PRIMARY                         = "https://example.org/oauth2-callback"
	TEST_REDIRECT_URI_SECONDARY                       = "https://email.org/callback"
	TEST_REDIRECT_INVALID                             = make([]string, 16)
	TEST_REDIRECT_PRIMARY                             = []string{TEST_REDIRECT_URI_PRIMARY}
	TEST_REDIRECT_SECONDARY                           = []string{TEST_REDIRECT_URI_SECONDARY}
	TEST_TOTP_PASSCODE_INVALID                        = "000000" // sobbing
	TEST_TOTP_SECRET                                  = tools.GenerateTOTPSecret()
	TEST_TOTP_RECOVERY_CODE_INVALID                   = "AAAAAAAA" // screaming
	TEST_TOTP_RECOVERY_CODES                          = tools.GenerateRecoveryCodes()
	TEST_OAUTH2_STATE_STRING                          = "awesome-sauce"
	TEST_OAUTH2_SCOPE_STRING_INVALID                  = "cheems"
	TEST_OAUTH2_SCOPE_INTEGER, _                      = tools.OAuth2StringToScopes("email identify")
	TEST_OAUTH2_SCOPE_STRING                          = tools.OAuth2ScopesToString(TEST_OAUTH2_SCOPE_INTEGER)
	TEST_OAUTH2_SECRET_INVALID                        = "test"
	TEST_OAUTH2_SECRET_PLAIN, TEST_OAUTH2_SECRET_HASH = tools.GenerateApplicationSecret()
	TEST_IMAGE_GIF                                    = mustReadFile("images/example.gif")
	TEST_IMAGE_JPEG                                   = mustReadFile("images/example.jpeg")
	TEST_IMAGE_PNG                                    = mustReadFile("images/example.png")
	TEST_IMAGE_WEBP                                   = mustReadFile("images/example.webp")
	TEST_HASH_PRIMARY                                 = tools.GenerateImageHash(TEST_IMAGE_PNG)
	TEST_HASH_SECONDARY                               = tools.GenerateImageHash(TEST_IMAGE_JPEG)
	TEST_IP_ADDRESS                                   = "129.212.166.28"
	TEST_IP_AGENT                                     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
)

func mustReadFile(filename string) []byte {
	b, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalln("cannot read file", filename, err)
	}
	return b
}

func mustHashPassword(plaintext string) string {
	h, err := tools.GeneratePasswordHash(plaintext)
	if err != nil {
		log.Fatalln("cannot hash pass", err)
	}
	return h
}
