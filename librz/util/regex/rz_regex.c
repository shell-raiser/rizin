// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_regex.h>
#include <rz_types.h>
#include <rz_util/rz_assert.h>
#include <rz_util.h>

/**
 * \file Defines the wrapper functions to PCRE2.
 * For detailed documentation, refer to the man pages of PCRE2.
 */

/**
 * \brief Compiles a regex pattern to a RzRegex and returns it.
 *
 * \param pattern The PCRE2 regex pattern string.
 * \param cflags The compilation flags.
 *
 * \return The compiled regex or NULL in case of failure.
 */
RZ_API RZ_OWN RzRegex *rz_regex_new(const char *pattern, RzRegexFlags cflags) {
	RzRegex *regex = RZ_NEW0(RzRegex);
	int status = regcomp(regex, pattern, cflags);
	if (status != 0) {
		char err[512] = { 0 };
		regerror(status, regex, err, 512);
		RZ_LOG_ERROR("%s\n", err);
		return NULL;
	}
	return regex;
}

/**
 * \brief Compiles a regex pattern and saves it to the given \p regex.
 *
 * \param regex The RzRegex struct to save the compiled pattern to.
 * \param pattern The PCRE2 regex pattern string.
 * \param cflags The compilation flags.
 *
 * \return 0 in case of success or an error code which can be passed to rz_regex_err().
 */
RZ_API int rz_regex_comp(RZ_BORROW RzRegex *regex, const char *pattern, RzRegexFlags cflags) {
	return regcomp(regex, pattern, cflags);
}

/**
 * \brief Frees a given RzRegex.
 *
 * \param regex The RzRegex to free.
 */
RZ_API void rz_regex_free(RZ_OWN RzRegex *regex) {
	regfree(regex);
}

/**
 * \brief Frees a given RzRegex.
 *
 * \param regex The RzRegex to free.
 */
RZ_API void rz_regex_fini(RZ_OWN RzRegex *regex) {
	regfree(regex);
}

/**
 * \brief Generates the error message to \p errcode.
 *
 * \param errcode The error code as returned by rz_regex_comp() or rz_regex_exec().
 * \param regex The regex which was passed to rz_regex_comp() or rz_regex_exec().
 * \param errbuf The error message buffer. Can be NULL.
 * If non-NULL the first \p errbuf_size - 1 bytes of the error message are written to it.
 * \param errbuf_size The error message buffer size in bytes.
 *
 * \return The number of bytes the required to contain the null-terminated error message string.
 */
RZ_API size_t rz_regex_error(int errcode, const RzRegex *regex, RZ_OUT RZ_NULLABLE char *errbuf, size_t errbuf_size) {
	return regerror(errcode, regex, errbuf, errbuf_size);
}

/**
 * \brief Searches the given \p regex pattern in the \p text for max. \p nmatch matches.
 * The resulting matches are stored in \p matches.
 *
 * \param regex The compiled regex pattern RzRegex.
 * \param text The text to search for matches.
 * \param nmatch Max. number of matches to store in \p matches.
 * \param matches Output array to write the found pattern matches to.
 * \param eflags The regex execute flags to use for the pattern.
 *
 * \return Zero for a successful match or REG_NOMATCH for failure.
 */
RZ_API int rz_regex_exec(const RzRegex *regex, const char *text, size_t nmatch, RZ_OUT RzRegexMatch *matches, int eflags) {
	return regexec(regex, text, nmatch, matches, eflags);
}

/**
 * \brief Determines the number of \p pattern matches in the \p text.
 * It matches a maximum of RZ_REGEX_MAX_MATCH_COUNT.
 *
 * \param pattern The pattern to match.
 * \param text The text to search for matches.
 * \param cflags The regex compile flags to use for the pattern.
 * \param eflags The regex execute flags to use for the pattern.
 *
 * \return The number of matches found in \p text, matching the \p pattern.
 * Or RZ_REGEX_MATCH_FAIL in case of failure during compilation.
 * Or RZ_REGEX_MATCH_OVERFLOW if more than RZ_REGEX_MAX_MATCH_COUNT or more matches were found.
 */
RZ_API int rz_regex_match(const char *pattern, const char *text, RzRegexFlags cflags, RzRegexFlags eflags) {
	RzRegex *regex = rz_regex_new(pattern, cflags);
	if (!regex) {
		return RZ_REGEX_MATCH_FAIL;
	}
	RzRegexMatch matches[RZ_REGEX_MAX_MATCH_COUNT] = { 0 };
	if (regexec(regex, text, RZ_REGEX_MAX_MATCH_COUNT, matches, eflags) == RZ_REGEX_NOMATCH) {
		return 0;
	}
	int nmatches = 0;
	// Match at index 0 is the entire regex match.
	for (size_t i = 0; i < RZ_REGEX_MAX_MATCH_COUNT; i++) {
		if (matches[i].rm_so == -1) {
			return nmatches;
		}
		nmatches++;
	}
	return RZ_REGEX_MATCH_OVERFLOW;
}

/**
 * \brief Returns a pointer into \p text where the given \p match is located.
 *
 * \param text The string to extract the match from.
 * \param match A match in the \p text.
 *
 * \return The pointer into \p text according to \p match. Or NULL in case of failure.
 */
RZ_API const char *rz_regex_match_extract(RZ_NONNULL const char *text, RZ_NONNULL RzRegexMatch *match) {
	rz_return_val_if_fail(text && match, NULL);
	if (match->rm_so < 0) {
		return NULL;
	}
	if (match->rm_eo > strlen(text)) {
		RZ_LOG_WARN("Match (%" PFMT32d "/%" PFMT32d ") exceeds limits of passed text %s\n", match->rm_so, match->rm_eo, text);
		return NULL;
	}
	return &text[match->rm_so];
}
