// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_REGEX_H
#define RZ_REGEX_H

#include <rz_types.h>
#include <rz_list.h>
#include <sys/types.h>

#include <pcre2posix.h>

// Maximum number of matches we count.
#define RZ_REGEX_MAX_MATCH_COUNT 64
#define RZ_REGEX_MATCH_FAIL      -1
#define RZ_REGEX_MATCH_OVERFLOW  -2

typedef int RzRegexFlags; ///< Regex flag bits.
typedef regex_t RzRegex; ///< A compiler regex expression.
typedef regmatch_t RzRegexMatch; ///< A match with its start and end offset.

#define RZ_REGEX_ICASE    REG_ICASE /* Maps to PCRE2_CASELESS */
#define RZ_REGEX_NEWLINE  REG_NEWLINE /* Maps to PCRE2_MULTILINE */
#define RZ_REGEX_NOTBOL   REG_NOTBOL /* Maps to PCRE2_NOTBOL */
#define RZ_REGEX_NOTEOL   REG_NOTEOL /* Maps to PCRE2_NOTEOL */
#define RZ_REGEX_DOTALL   REG_DOTALL /* NOT defined by POSIX; maps to PCRE2_DOTALL */
#define RZ_REGEX_NOSUB    REG_NOSUB /* Do not report what was matched */
#define RZ_REGEX_UTF      REG_UTF /* NOT defined by POSIX; maps to PCRE2_UTF */
#define RZ_REGEX_STARTEND REG_STARTEND /* BSD feature: pass subject string by so,eo */
#define RZ_REGEX_NOTEMPTY REG_NOTEMPTY /* NOT defined by POSIX; maps to PCRE2_NOTEMPTY */
#define RZ_REGEX_UNGREEDY REG_UNGREEDY /* NOT defined by POSIX; maps to PCRE2_UNGREEDY */
#define RZ_REGEX_UCP      REG_UCP /* NOT defined by POSIX; maps to PCRE2_UCP */
#define RZ_REGEX_PEND     REG_PEND /* GNU feature: pass end pattern by re_endp */
#define RZ_REGEX_NOSPEC   REG_NOSPEC /* Maps to PCRE2_LITERAL */
#define RZ_REGEX_EXTENDED REG_EXTENDED /* Unused by PCRE2 */

/* regerror() flags */
#define RZ_REGEX_ASSERT   REG_ASSERT /* internal error ? */
#define RZ_REGEX_BADBR    REG_BADBR /* invalid repeat counts in {} */
#define RZ_REGEX_BADPAT   REG_BADPAT /* pattern error */
#define RZ_REGEX_BADRPT   REG_BADRPT /* ? * + invalid */
#define RZ_REGEX_EBRACE   REG_EBRACE /* unbalanced {} */
#define RZ_REGEX_EBRACK   REG_EBRACK /* unbalanced [] */
#define RZ_REGEX_ECOLLATE REG_ECOLLATE /* collation error - not relevant */
#define RZ_REGEX_ECTYPE   REG_ECTYPE /* bad class */
#define RZ_REGEX_EESCAPE  REG_EESCAPE /* bad escape sequence */
#define RZ_REGEX_EMPTY    REG_EMPTY /* empty expression */
#define RZ_REGEX_EPAREN   REG_EPAREN /* unbalanced () */
#define RZ_REGEX_ERANGE   REG_ERANGE /* bad range inside [] */
#define RZ_REGEX_ESIZE    REG_ESIZE /* expression too big */
#define RZ_REGEX_ESPACE   REG_ESPACE /* failed to get memory */
#define RZ_REGEX_ESUBREG  REG_ESUBREG /* bad back reference */
#define RZ_REGEX_INVARG   REG_INVARG /* bad argument */
#define RZ_REGEX_NOMATCH  REG_NOMATCH /* match failed */

RZ_API int rz_regex_exec(const RzRegex *preg, const char *string, size_t nmatch, RzRegexMatch __pmatch[], int eflags);
RZ_API void rz_regex_free(RzRegex *);
RZ_API int rz_regex_comp(RzRegex *, const char *, int);
RZ_API size_t rz_regex_error(int, const RzRegex *, char *, size_t);

// Non native helper functions for our convenience.
RZ_API RzRegex *rz_regex_new(const char *pattern, RzRegexFlags cflags);
RZ_API void rz_regex_fini(RzRegex *);
RZ_API int rz_regex_match(const char *pattern, const char *text, RzRegexFlags cflags, RzRegexFlags eflags);
RZ_API const char *rz_regex_match_extract(RZ_NONNULL const char *text, RZ_NONNULL RzRegexMatch *match);

#endif /* !_REGEX_H_ */
