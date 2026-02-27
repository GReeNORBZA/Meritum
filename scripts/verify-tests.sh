#!/usr/bin/env bash
# ============================================================================
# verify-tests.sh — Enforce test file existence and minimum test count
#
# Usage:
#   ./scripts/verify-tests.sh <test-file> <min-test-count> [language]
#   ./scripts/verify-tests.sh apps/api/src/domains/provider/provider.test.ts 9
#   ./scripts/verify-tests.sh apps/api/tests/test_provider.py 9 python
#   ./scripts/verify-tests.sh apps/api/provider_test.go 5 go
#
# Supported languages: typescript (default), python, go, rust, java
#
# Checks:
#   1. Test file exists
#   2. Test file is non-empty
#   3. Contains at least <min-test-count> test cases (language-specific patterns)
#   4. Every test must have at least one assertion (language-specific patterns)
#   5. No trivial assertions (language-specific patterns)
#
# Exit codes:
#   0 = all checks pass
#   1 = file missing, empty, or insufficient test count
#
# This script does NOT run the tests — pair it with your test runner in a
# compound verify command:
#   vitest run file.ts && ./scripts/verify-tests.sh file.ts 9
#   pytest file.py && ./scripts/verify-tests.sh file.py 5 python
#   go test ./... && ./scripts/verify-tests.sh file_test.go 4 go
# ============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TEST_FILE="${1:-}"
MIN_TESTS="${2:-1}"
LANGUAGE="${3:-typescript}"

if [[ -z "$TEST_FILE" ]]; then
  echo -e "${RED}Usage: $0 <test-file> <min-test-count> [language]${NC}"
  echo -e "${RED}Languages: typescript, python, go, rust, java${NC}"
  exit 1
fi

# --- Language Presets ---
# Each language defines:
#   TEST_PATTERN       — regex to count test cases
#   ASSERT_PATTERN     — regex to count assertions
#   TRIVIAL_PATTERN    — regex to detect trivial/meaningless assertions
#   TRIVIAL_EXTRA      — optional second trivial pattern (some languages need it)
#   TEST_LABEL         — human-readable label for test pattern
#   ASSERT_LABEL       — human-readable label for assertion pattern

case "$LANGUAGE" in
  typescript|javascript|ts|js)
    # Matches: it('...'), test('...'), it.only(...), test.skip(...), etc.
    TEST_PATTERN='^\s*(it|test)(\.(only|skip|todo))?\s*\('
    # Matches: expect(...), assert(...)
    ASSERT_PATTERN='(expect|assert)\s*\('
    # Trivial: expect(true), expect(false), expect(1), expect(0), expect(''), expect("")
    TRIVIAL_PATTERN='expect\(\s*(true|false|1|0|'"'"''"'"'|"")\s*\)'
    # Also: expect(null).toBeDefined()
    TRIVIAL_EXTRA='expect\(\s*null\s*\)\.toBeDefined\('
    TEST_LABEL="it(...) or test(...)"
    ASSERT_LABEL="expect(...) or assert(...)"
    ;;

  python|py)
    # Matches: def test_something(, async def test_something(
    TEST_PATTERN='^\s*(async\s+)?def\s+test_'
    # Matches: assert keyword, self.assert*, pytest.raises
    ASSERT_PATTERN='(^\s*assert\s|self\.assert|pytest\.raises)'
    # Trivial: assert True, assert 1, assert ""
    TRIVIAL_PATTERN='^\s*assert\s+(True|False|1|0|""|'"'"''"'"')\s*(,|$|#)'
    TRIVIAL_EXTRA=''
    TEST_LABEL="def test_*()"
    ASSERT_LABEL="assert / self.assert* / pytest.raises"
    ;;

  go|golang)
    # Matches: func TestSomething(t *testing.T)
    TEST_PATTERN='^\s*func\s+Test\w+\s*\('
    # Matches: assert.*, require.*, t.Error, t.Fatal, t.Fail
    ASSERT_PATTERN='(assert\.|require\.|t\.(Error|Fatal|Fail|Log)f?\()'
    # Trivial: assert.True(t, true), require.True(t, true)
    TRIVIAL_PATTERN='(assert|require)\.(True|False)\(\s*t\s*,\s*(true|false)\s*\)'
    TRIVIAL_EXTRA=''
    TEST_LABEL="func Test*(t *testing.T)"
    ASSERT_LABEL="assert.* / require.* / t.Error / t.Fatal"
    ;;

  rust|rs)
    # Matches: #[test] followed by fn (we count #[test] annotations)
    TEST_PATTERN='#\[test\]'
    # Matches: assert!, assert_eq!, assert_ne!, panic! (in should_panic tests)
    ASSERT_PATTERN='(assert!|assert_eq!|assert_ne!|panic!)\s*\('
    # Trivial: assert!(true), assert_eq!(true, true), assert_eq!(1, 1)
    TRIVIAL_PATTERN='assert!\(\s*true\s*\)'
    TRIVIAL_EXTRA='assert_eq!\(\s*(true|1)\s*,\s*(true|1)\s*\)'
    TEST_LABEL="#[test]"
    ASSERT_LABEL="assert! / assert_eq! / assert_ne!"
    ;;

  java|kotlin|jvm)
    # Matches: @Test (JUnit)
    TEST_PATTERN='@Test'
    # Matches: assert*, assertEquals, assertTrue, assertThat, verify(
    ASSERT_PATTERN='(assert\w+\s*\(|verify\s*\(|assertThat\s*\()'
    # Trivial: assertTrue(true), assertEquals(1, 1), assertEquals(true, true)
    TRIVIAL_PATTERN='assertTrue\(\s*true\s*\)'
    TRIVIAL_EXTRA='assertEquals\(\s*(1\s*,\s*1|true\s*,\s*true)\s*\)'
    TEST_LABEL="@Test"
    ASSERT_LABEL="assert* / verify / assertThat"
    ;;

  *)
    echo -e "${RED}Unknown language: ${LANGUAGE}${NC}"
    echo -e "${RED}Supported: typescript, python, go, rust, java${NC}"
    exit 1
    ;;
esac

# --- Check 1: File exists ---
if [[ ! -f "$TEST_FILE" ]]; then
  echo -e "${RED}FAIL: Test file does not exist: ${TEST_FILE}${NC}"
  exit 1
fi

# --- Check 2: File is non-empty ---
if [[ ! -s "$TEST_FILE" ]]; then
  echo -e "${RED}FAIL: Test file is empty: ${TEST_FILE}${NC}"
  exit 1
fi

# --- Check 3: Count test cases ---
TEST_COUNT=$(grep -cE "$TEST_PATTERN" "$TEST_FILE" 2>/dev/null || true)
TEST_COUNT="${TEST_COUNT:-0}"

if [[ "$TEST_COUNT" -lt "$MIN_TESTS" ]]; then
  echo -e "${RED}FAIL: Expected at least ${MIN_TESTS} test(s) in ${TEST_FILE}, found ${TEST_COUNT}${NC}"
  echo -e "${YELLOW}  Missing $((MIN_TESTS - TEST_COUNT)) test(s). The task prompt specifies ${MIN_TESTS} required tests.${NC}"
  echo -e "${YELLOW}  Pattern: ${TEST_LABEL}${NC}"
  exit 1
fi

# --- Check 4: Assertion presence ---
ASSERT_COUNT=$(grep -cE "$ASSERT_PATTERN" "$TEST_FILE" 2>/dev/null || true)
ASSERT_COUNT="${ASSERT_COUNT:-0}"

if [[ "$ASSERT_COUNT" -lt "$TEST_COUNT" ]]; then
  echo -e "${RED}FAIL: Found ${TEST_COUNT} test(s) but only ${ASSERT_COUNT} assertion(s). Each test must contain at least one ${ASSERT_LABEL} call.${NC}"
  exit 1
fi

# --- Check 5: Trivial assertion ban ---
if grep -qE "$TRIVIAL_PATTERN" "$TEST_FILE" 2>/dev/null; then
  echo -e "${RED}FAIL: Trivial assertion detected. Tests must make meaningful assertions.${NC}"
  echo -e "${YELLOW}  Pattern matched: ${TRIVIAL_PATTERN}${NC}"
  exit 1
fi

if [[ -n "$TRIVIAL_EXTRA" ]]; then
  if grep -qE "$TRIVIAL_EXTRA" "$TEST_FILE" 2>/dev/null; then
    echo -e "${RED}FAIL: Trivial assertion detected. Tests must make meaningful assertions.${NC}"
    echo -e "${YELLOW}  Pattern matched: ${TRIVIAL_EXTRA}${NC}"
    exit 1
  fi
fi

echo -e "${GREEN}OK: ${TEST_FILE} contains ${TEST_COUNT} test(s) (minimum: ${MIN_TESTS}) [${LANGUAGE}]${NC}"
echo -e "${GREEN}OK: ${ASSERT_COUNT} assertion(s) found (at least ${TEST_COUNT} required)${NC}"
echo -e "${GREEN}OK: No trivial assertions detected${NC}"
