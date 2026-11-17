package audit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"agent-guard/internal/policy"
)

// Credential-shaped values are generated at run time from fragments and a fixed-seed generator, so
// no secret-shaped literal exists in the source. Lengths and alphabets follow the real formats.
const (
	alphaNum   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	alphaLower = "abcdefghijklmnopqrstuvwxyz"
	alphaB64   = alphaNum + "+/"
	alphaB64u  = alphaNum + "-_"
	alphaAWSID = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
)

// gen returns n characters of alphabet from a fixed-seed linear congruential generator.
func gen(alphabet string, n int, seed uint32) string {
	x := seed*2654435761 + 1
	b := make([]byte, n)
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = alphabet[int(x>>16)%len(alphabet)]
	}
	return string(b)
}

// frags returns the pieces of a secret whose presence in a preview means it leaked: the whole value
// and its first and last 8 characters. A partial redaction that keeps a tail still fails.
func frags(secret string) []string {
	if len(secret) <= 8 {
		return []string{secret}
	}
	return []string{secret, secret[:8], secret[len(secret)-8:]}
}

func cat(groups ...[]string) []string {
	var out []string
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

func cmdJSON(command string) string {
	b, _ := json.Marshal(map[string]string{"command": command})
	return string(b)
}

func objJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func b64u(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// shapeCase is one row of the redaction table.
//
//	gone  fragments that must not appear in args_preview
//	kept  substrings that must still appear (the benign part of the same input)
type shapeCase struct {
	group string
	name  string
	input string
	gone  []string
	kept  []string
}

func (c shapeCase) id() string { return c.group + "/" + c.name }

func residual(preview string, fragments []string) []string {
	var found []string
	for _, f := range fragments {
		if f != "" && strings.Contains(preview, f) {
			found = append(found, f)
		}
	}
	return found
}

func shapeCases() []shapeCase {
	var (
		akid       = "AK" + "IA" + gen(alphaAWSID, 16, 1)
		asia       = "AS" + "IA" + gen(alphaAWSID, 16, 2)
		slash      = gen(alphaNum, 13, 3) + "/" + gen(alphaNum, 7, 4) + "/" + gen(alphaNum, 18, 5) // 40 chars, two '/'
		flat       = gen(alphaB64[:len(alphaB64)-1], 40, 6)                                        // 40 chars, no '/'
		slashParts = []string{
			slash[:13], slash[14:21], slash[22:],
		}

		ghBody = gen(alphaNum, 36, 7)
		ghp    = "gh" + "p_" + ghBody
		gho    = "gh" + "o_" + gen(alphaNum, 36, 8)
		ghu    = "gh" + "u_" + gen(alphaNum, 36, 9)
		ghs    = "gh" + "s_" + gen(alphaNum, 36, 10)
		ghr    = "gh" + "r_" + gen(alphaNum, 36, 11)
		ghPat  = "github" + "_pat_" + gen(alphaNum, 22, 12) + "_" + gen(alphaNum, 59, 13)

		jwtH   = b64u(`{"alg":"HS256","typ":"JWT"}`)
		jwtP   = b64u(`{"sub":"u-1042","iat":1516239022}`)
		jwtS   = gen(alphaB64u, 43, 14)
		jwt    = jwtH + "." + jwtP + "." + jwtS
		jwtNo  = b64u(`{"alg":"none"}`) + "." + jwtP + "."
		jwtNoH = b64u(`{"alg":"none"}`)
		jwtAll = cat(frags(jwtH), frags(jwtP), frags(jwtS))

		bearer = gen(alphaNum, 32, 15)
		short  = gen(alphaLower+"0123456789", 7, 16)
		apikey = gen(alphaNum, 32, 17)
		letter = gen(alphaLower, 24, 18)
		digest = gen(alphaLower, 32, 26)
		wordA  = gen(alphaLower, 9, 27)
		wordB  = gen(alphaLower, 9, 28)

		pw      = gen(alphaNum, 16, 19)
		pwEnc   = gen(alphaNum, 6, 20) + "%40" + gen(alphaNum, 6, 21)
		pwA     = gen(alphaNum, 8, 22)
		pwB     = gen(alphaLower, 6, 23)
		pwRedis = gen(alphaNum, 16, 24)
		pwWord  = gen(alphaLower, 16, 25)
	)
	pwEncA, pwEncB, _ := strings.Cut(pwEnc, "%40")

	return []shapeCase{
		// AWS access key id
		{group: "aws-key-id", name: "bare AKIA", input: cmdJSON("echo " + akid), gone: frags(akid), kept: []string{"echo"}},
		{group: "aws-key-id", name: "bare ASIA (temporary credentials)", input: cmdJSON("echo " + asia), gone: frags(asia), kept: []string{"echo"}},
		{group: "aws-key-id", name: "AWS_ACCESS_KEY_ID assignment", input: cmdJSON("AWS_ACCESS_KEY_ID=" + akid + " aws s3 ls"), gone: frags(akid), kept: []string{"AWS_ACCESS_KEY_ID", "aws s3 ls"}},
		{group: "aws-key-id", name: "JSON key aws_access_key_id", input: objJSON(map[string]string{"aws_access_key_id": akid, "region": "us-east-1"}), gone: frags(akid), kept: []string{"region", "us-east-1"}},

		// AWS secret access key
		{group: "aws-secret", name: "exported assignment, slashes in value", input: cmdJSON("export AWS_SECRET_ACCESS_KEY=" + slash + " && aws s3 ls"), gone: cat([]string{slash}, slashParts), kept: []string{"AWS_SECRET_ACCESS_KEY", "aws s3 ls"}},
		{group: "aws-secret", name: "double-quoted assignment, slashes in value", input: cmdJSON(`AWS_SECRET_ACCESS_KEY="` + slash + `" aws s3 ls`), gone: cat([]string{slash}, slashParts), kept: []string{"AWS_SECRET_ACCESS_KEY", "aws s3 ls"}},
		{group: "aws-secret", name: "lowercase assignment", input: cmdJSON("aws_secret_access_key=" + slash), gone: cat([]string{slash}, slashParts), kept: []string{"aws_secret_access_key"}},
		{group: "aws-secret", name: "JSON key aws_secret_access_key", input: objJSON(map[string]string{"aws_secret_access_key": slash, "region": "us-east-1"}), gone: cat([]string{slash}, slashParts), kept: []string{"region", "us-east-1"}},
		{group: "aws-secret", name: "bare value, no slash (entropy heuristic only)", input: cmdJSON("echo " + flat), gone: frags(flat), kept: []string{"echo"}},
		{group: "aws-secret", name: "INI form, no slash (entropy heuristic only)", input: cmdJSON("aws_secret_access_key = " + flat), gone: frags(flat), kept: []string{"aws_secret_access_key"}},
		{group: "aws-secret", name: "NAME: value form, no slash (entropy heuristic only)", input: cmdJSON("AWS_SECRET_ACCESS_KEY: " + flat), gone: frags(flat), kept: []string{"AWS_SECRET_ACCESS_KEY"}},
		{group: "aws-secret", name: "bare value, slashes in value", input: cmdJSON("echo " + slash), gone: cat([]string{slash}, slashParts), kept: []string{"echo"}},
		{group: "aws-secret", name: "INI form, slashes in value", input: cmdJSON("aws_secret_access_key = " + slash), gone: cat([]string{slash}, slashParts), kept: []string{"aws_secret_access_key"}},
		{group: "aws-secret", name: "NAME: value form, slashes in value", input: cmdJSON("AWS_SECRET_ACCESS_KEY: " + slash), gone: cat([]string{slash}, slashParts), kept: []string{"AWS_SECRET_ACCESS_KEY"}},

		// GitHub token prefixes
		{group: "github-token", name: "ghp_", input: cmdJSON("echo " + ghp), gone: frags(ghp), kept: []string{"echo"}},
		{group: "github-token", name: "gho_", input: cmdJSON("echo " + gho), gone: frags(gho), kept: []string{"echo"}},
		{group: "github-token", name: "ghu_", input: cmdJSON("echo " + ghu), gone: frags(ghu), kept: []string{"echo"}},
		{group: "github-token", name: "ghs_", input: cmdJSON("echo " + ghs), gone: frags(ghs), kept: []string{"echo"}},
		{group: "github-token", name: "ghr_", input: cmdJSON("echo " + ghr), gone: frags(ghr), kept: []string{"echo"}},
		{group: "github-token", name: "github_pat_", input: cmdJSON("echo " + ghPat), gone: frags(ghPat), kept: []string{"echo"}},
		{group: "github-token", name: "GITHUB_TOKEN assignment", input: cmdJSON("GITHUB_TOKEN=" + ghp + " gh pr list"), gone: frags(ghp), kept: []string{"GITHUB_TOKEN", "gh pr list"}},
		{group: "github-token", name: "x-access-token clone URL", input: cmdJSON("git clone https://x-access-token:" + ghs + "@github.com/example/repo"), gone: frags(ghs), kept: []string{"github.com/example/repo"}},

		// JWT
		{group: "jwt", name: "bare", input: cmdJSON("echo " + jwt), gone: cat(jwtAll, []string{jwt}), kept: []string{"echo"}},
		{group: "jwt", name: "unsigned, empty third part", input: cmdJSON("echo " + jwtNo), gone: cat(frags(jwtNoH), frags(jwtP), []string{jwtNo}), kept: []string{"echo"}},
		{group: "jwt", name: "as a Bearer credential", input: cmdJSON("curl -H 'Authorization: Bearer " + jwt + "' https://api.example.com/v1"), gone: cat(jwtAll, []string{jwt}), kept: []string{"api.example.com"}},
		{group: "jwt", name: "JSON value under a benign key", input: objJSON(map[string]string{"value": jwt, "note": "ok"}), gone: cat(jwtAll, []string{jwt}), kept: []string{"note", "ok"}},

		// Authorization header
		{group: "authorization", name: "Bearer in a curl command", input: cmdJSON("curl -H 'Authorization: Bearer " + bearer + "' https://api.example.com/v1"), gone: frags(bearer), kept: []string{"api.example.com"}},
		{group: "authorization", name: "lower-case bearer", input: cmdJSON("curl -H 'authorization: bearer " + bearer + "' https://api.example.com/v1"), gone: frags(bearer), kept: []string{"api.example.com"}},
		{group: "authorization", name: "JSON Authorization key, nested", input: objJSON(map[string]any{"headers": map[string]string{"Authorization": "Bearer " + bearer}, "url": "https://api.example.com/v1"}), gone: frags(bearer), kept: []string{"headers", "api.example.com"}},
		{group: "authorization", name: "ApiKey scheme, mixed token (entropy heuristic only)", input: cmdJSON("curl -H 'Authorization: ApiKey " + apikey + "' https://api.example.com/v1"), gone: frags(apikey), kept: []string{"api.example.com"}},
		{group: "authorization", name: "Bearer token shorter than 8 characters", input: cmdJSON("curl -H 'Authorization: Bearer " + short + "' https://api.example.com/v1"), gone: []string{short}, kept: []string{"api.example.com"}},
		{group: "authorization", name: "Token scheme, letters-only token", input: cmdJSON("curl -H 'Authorization: Token " + letter + "' https://api.example.com/v1"), gone: frags(letter), kept: []string{"api.example.com"}},

		{group: "authorization", name: "X-Api-Key header, letters-only token", input: cmdJSON("curl -H 'X-Api-Key: " + letter + "' https://api.example.com/v1"), gone: frags(letter), kept: []string{"X-Api-Key", "api.example.com"}},
		{group: "authorization", name: "Digest header with embedded quotes", input: cmdJSON(`curl -H "Authorization: Digest username=\"app\", response=\"` + digest + `\"" https://api.example.com/v1`), gone: frags(digest), kept: []string{"api.example.com"}},

		{group: "authorization", name: "quoted header followed by another header", input: cmdJSON("curl -H 'X-Api-Key: " + letter + "' -H 'Accept: json' https://api.example.com/v1"), gone: frags(letter), kept: []string{"-H 'Accept: json' https://api.example.com/v1"}},

		{group: "authorization", name: "header value continued after an escaped newline", input: cmdJSON("curl -H \"Authorization: Bearer \\\n" + letter + "\" https://api.example.com/v1"), gone: frags(letter), kept: []string{"api.example.com"}},

		// Assignments to secret-looking names
		{group: "assignment", name: "value already redacted by an earlier rule keeps its tail", input: cmdJSON("password=" + redacted + wordA), gone: []string{wordA}},
		{group: "assignment", name: "quoted value with spaces", input: cmdJSON(`password = "` + wordA + ` ` + wordB + `" ./run`), gone: []string{wordA, wordB}, kept: []string{"password", "./run"}},
		{group: "assignment", name: "YAML key with a colon", input: objJSON(map[string]string{"content": "db:\n  password: " + wordA + "\n  host: db.internal"}), gone: []string{wordA}, kept: []string{"host: db.internal"}},

		// Database URL with a password
		{group: "database-url", name: "postgres userinfo", input: cmdJSON("psql postgres://app:" + pw + "@db.internal:5432/prod"), gone: frags(pw), kept: []string{"db.internal:5432/prod"}},
		{group: "database-url", name: "mysql userinfo, tcp() host", input: cmdJSON("mysql://root:" + pw + "@tcp(db.internal:3306)/prod"), gone: frags(pw), kept: []string{"tcp(db.internal:3306)/prod"}},
		{group: "database-url", name: "mongodb+srv userinfo", input: cmdJSON("mongosh mongodb+srv://app:" + pw + "@cluster0.example.net/prod"), gone: frags(pw), kept: []string{"mongosh"}},
		{group: "database-url", name: "percent-encoded @ in password", input: cmdJSON("psql postgres://app:" + pwEnc + "@db.internal/prod"), gone: cat(frags(pwEnc), []string{pwEncA, pwEncB}), kept: []string{"db.internal/prod"}},
		{group: "database-url", name: "DATABASE_URL assignment", input: cmdJSON("DATABASE_URL=postgres://app:" + pw + "@db.internal/prod ./migrate"), gone: frags(pw), kept: []string{"DATABASE_URL", "./migrate"}},
		{group: "database-url", name: "JSON key database_url", input: objJSON(map[string]string{"database_url": "postgres://app:" + pw + "@db.internal/prod", "pool": "5"}), gone: frags(pw), kept: []string{"pool"}},
		{group: "database-url", name: "password in the query string", input: cmdJSON("psql postgresql://db.internal/prod?user=app&password=" + pw), gone: frags(pw), kept: []string{"db.internal/prod?user=app"}},
		{group: "database-url", name: "keyword DSN", input: cmdJSON("psql 'host=db.internal user=app password=" + pw + " dbname=prod'"), gone: frags(pw), kept: []string{"host=db.internal user=app", "dbname=prod"}},
		{group: "database-url", name: "empty user, mixed password, long host", input: cmdJSON("redis-cli --url redis://:" + pwRedis + "@cache.internal:6379/0"), gone: frags(pwRedis), kept: []string{"redis-cli", "cache.internal:6379/0"}},
		{group: "database-url", name: "empty user, mixed password, short host", input: cmdJSON("redis-cli --url redis://:" + pwRedis + "@r:6379/0"), gone: frags(pwRedis), kept: []string{"redis-cli"}},
		{group: "database-url", name: "literal @ in the password", input: cmdJSON("psql postgres://app:" + pwA + "@" + pwB + "@db.internal/prod"), gone: []string{pwA, pwB}, kept: []string{"db.internal/prod"}},
		{group: "database-url", name: "empty user, letters-only password", input: cmdJSON("redis-cli --url redis://:" + pwWord + "@cache.internal:6379/0"), gone: frags(pwWord), kept: []string{"redis-cli"}},

		// Controls: benign text must pass through untouched.
		{group: "control", name: "plain command", input: cmdJSON("ls -la /home/user/projects/agent-guard"), kept: []string{"ls -la /home/user/projects/agent-guard"}},
		{group: "control", name: "url without credentials", input: cmdJSON("curl https://api.example.com/v1/status"), kept: []string{"https://api.example.com/v1/status"}},
		{group: "control", name: "database url without credentials", input: cmdJSON("psql postgres://db.internal:5432/prod"), kept: []string{"postgres://db.internal:5432/prod"}},
		{group: "control", name: "region assignment", input: cmdJSON("AWS_REGION=us-east-1 aws s3 ls"), kept: []string{"AWS_REGION=us-east-1", "aws s3 ls"}},
		{group: "control", name: "url with @ in the path and query", input: cmdJSON("curl 'https://example.com/users/@me/profile?next=a@b.example'"), kept: []string{"https://example.com/users/@me/profile?next=a@b.example"}},
		{group: "control", name: "quoted url followed by an address", input: cmdJSON(`echo "https://example.com" mail me@example.org`), kept: []string{`https://example.com`, "me@example.org"}},
		{group: "control", name: "Go short variable declaration", input: cmdJSON("key := lookup(id)"), kept: []string{"key := lookup(id)"}},
		{group: "control", name: "equality comparison", input: cmdJSON("if key == other { return }"), kept: []string{"if key == other { return }"}},
		{group: "control", name: "prose about headers", input: cmdJSON("echo the Authorization header is required"), kept: []string{"echo the Authorization header is required"}},
	}
}

// previewLimitGuard keeps every raw input well inside the preview limit so truncation can never
// hide a leak or a missing fragment.
const previewLimitGuard = previewMax - 16

func TestRedactionShapes(t *testing.T) {
	cases := shapeCases()
	buf := &lockedBuf{}
	l := NewWriter(buf, Options{})
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	for _, c := range cases {
		if len(c.input) > previewLimitGuard {
			t.Fatalf("%s: input is %d bytes; keep it under %d so the preview is not truncated", c.id(), len(c.input), previewLimitGuard)
		}
		if err := l.Observe(ctx, ev("Bash", "toolu_shape", c.input, policy.Allow, "allow", "no rule matched")); err != nil {
			t.Fatalf("%s: observe: %v", c.id(), err)
		}
	}
	closeOK(t, l)
	recs := lines(t, buf.String())
	if len(recs) != len(cases) {
		t.Fatalf("got %d audit records for %d cases", len(recs), len(cases))
	}
	for i, c := range cases {
		t.Run(c.id(), func(t *testing.T) {
			got, _ := recs[i]["args_preview"].(string)
			if got == "" {
				t.Fatalf("record has no args_preview: %v", recs[i])
			}
			for _, k := range c.kept {
				if !strings.Contains(got, k) {
					t.Errorf("preview lost %q: %s", k, got)
				}
			}
			for _, f := range residual(got, c.gone) {
				t.Errorf("preview leaks %q: %s", f, got)
			}
		})
	}
}

// The oracle must be able to fail: against an input that nothing redacted, every case that lists
// gone fragments must report them. This catches fragments that do not occur in the input.
func TestRedactionShapesOracleDetectsLeaks(t *testing.T) {
	for _, c := range shapeCases() {
		if len(c.gone) == 0 {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(c.input), &doc); err != nil {
			t.Fatalf("%s: input is not JSON: %v", c.id(), err)
		}
		for _, f := range c.gone {
			if !strings.Contains(c.input, f) {
				t.Errorf("%s: fragment %q does not occur in the raw input, so it proves nothing", c.id(), f)
			}
		}
		if len(residual(c.input, c.gone)) != len(c.gone) {
			t.Errorf("%s: oracle did not report every fragment of an unredacted input", c.id())
		}
	}
}

// The bare 40-character pass is exact-length by design. This pins that rule so a change to it is
// deliberate; it is not a claim that a 39 or 41 character secret is safe (those are caught only
// by the other rules, and only some of the time).
func TestBareSecretPassIsExactLength(t *testing.T) {
	piece := func(n int, seed uint32) string { return gen(alphaNum, n, seed) }
	mk := func(last int) string { return piece(13, 40) + "/" + piece(7, 41) + "/" + piece(last, 42) }
	exact := mk(18)
	for _, tc := range []struct {
		name  string
		input string
		want  string
	}{
		{"40 characters, space-bounded", "echo " + exact + " x", "echo [REDACTED] x"},
		{"40 characters, after =", "v=" + exact, "v=[REDACTED]"},
		{"39 characters", "echo " + mk(17) + " x", "echo " + mk(17) + " x"},
		{"41 characters", "echo " + mk(19) + " x", "echo " + mk(19) + " x"},
		{"after a dot", "echo f." + exact + " x", "echo f." + exact + " x"},
		{"followed by a hyphen", "echo " + exact + "- x", "echo " + exact + "- x"},
		{"after a hyphen", "echo x-" + exact, "echo x-" + exact},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactString(tc.input); got != tc.want {
				t.Errorf("redactString(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
