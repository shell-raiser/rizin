// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_REGEX_H
#define RZ_REGEX_H

#include <rz_vector.h>
#include <rz_types.h>
#include <rz_list.h>
#include <sys/types.h>

// TODO Check for static windows build and define this
/* #define PCRE2_STATIC */
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

// Some basic PCRE2 macros. There are way more defined
// and should be added here if needed.
#define RZ_REGEX_ERROR_NOMATCH PCRE2_ERROR_NOMATCH
#define RZ_REGEX_ERROR_PARTIAL PCRE2_ERROR_PARTIAL

#define RZ_REGEX_CASELESS  PCRE2_CASELESS
#define RZ_REGEX_EXTENDED  PCRE2_EXTENDED
#define RZ_REGEX_NOSUB     PCRE2_NOSUB
#define RZ_REGEX_MULTILINE PCRE2_MULTILINE
#define RZ_REGEX_NEWLINE   PCRE2_NEWLINE

#define RZ_REGEX_UNSET PCRE2_UNSET

typedef int RzRegexStatus; ///< An status number returned by the regex API.
typedef PCRE2_SIZE RzRegexSize; ///< Size of a text or regex. This is the size measured in code width. For UTF-8: bytes.
typedef ut32 RzRegexFlags; ///< Regex flag bits.
typedef PCRE2_SPTR RzRegexPattern; ///< A regex pattern string.
typedef pcre2_code RzRegex; ///< A regex expression.
typedef pcre2_match_data RzRegexMatchData; ///< A regex match data from PCRE2

typedef struct {
	RzRegexSize mname_idx; ///< Match name index into the pattern name table.
	RzRegexSize start; ///< Start offset into the text where the match starts.
	RzRegexSize len; ///< Length of match in bytes.
} RzRegexMatch;

typedef pcre2_general_context RzRegexGeneralContext; ///< General context.
typedef pcre2_compile_context RzRegexCompContext; ///< The context for compiling.
typedef pcre2_match_context RzRegexMatchContext; ///< The context for matching.
typedef struct {
	RzRegexGeneralContext *general;
	RzRegexCompContext *compile;
	RzRegexMatchContext *match;
} RzRegexContexts;

RZ_OWN RzRegexMatchData *rz_regex_match_data_new(const RzRegex *regex, RzRegexGeneralContext *context);
void rz_regex_match_data_free(RZ_OWN RzRegexMatchData *match_data);

RZ_API RZ_OWN RzRegex *rz_regex_new(const char *pattern, RzRegexFlags cflags);
RZ_API void rz_regex_free(RzRegex *regex);
RZ_API void rz_regex_error_msg(RzRegexStatus errcode, RZ_OUT char *errbuf, RzRegexSize errbuf_size);
RZ_API const ut8 *rz_regex_get_match_name(const RzRegex *regex, ut32 name_idx);
RZ_API RzRegexStatus rz_regex_match(const RzRegex *regex, RZ_NONNULL const char *text,
	RzRegexSize text_offset,
	RzRegexFlags options,
	RZ_NULLABLE RZ_OUT RzRegexMatchData *mdata);
RZ_API RZ_OWN RzPVector /*<RzRegexMatch>*/ *rz_regex_match_all_not_grouped(
	const RzRegex *regex,
	RZ_NONNULL const char *text,
	RzRegexSize text_offset,
	RzRegexFlags options);
RZ_API RZ_OWN RzVector /*<RzRegexMatch>*/ *rz_regex_match_first(
	const RzRegex *regex,
	RZ_NONNULL const char *text,
	RzRegexSize text_offset,
	RzRegexFlags options);
RZ_API RZ_OWN RzPVector /*<RzVector<RzRegexMatch>>*/ *rz_regex_match_all(
	const RzRegex *regex,
	RZ_NONNULL const char *text,
	RzRegexSize text_offset,
	RzRegexFlags options);

#endif /* !_REGEX_H_ */
