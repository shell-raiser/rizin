// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_vector.h>
#include <rz_regex.h>
#include <rz_types.h>
#include <rz_util/rz_assert.h>
#include <rz_util.h>

/**
 * \file Defines the wrapper functions to PCRE2.
 */

/**
 * \brief Compile a regex pattern to a RzRegex and return it.
 * In case of an error, an error message is printed and NULL is returned.
 *
 * \param pattern The regex pattern string.
 * \param cflags The compilation flags or zero for default.
 * \param context The context for compilation. Can be NULL for default context.
 *
 * \return The compiled regex or NULL in case of failure.
 */
RZ_API RZ_OWN RzRegex *rz_regex_new(const char *pattern, RzRegexFlags cflags, RZ_NULLABLE RzRegexCompContext *context) {
	RzRegexStatus err_num;
	RzRegexSize err_off;
	RzRegex *regex = pcre2_compile(
		(PCRE2_SPTR)pattern,
		PCRE2_ZERO_TERMINATED,
		cflags,
		&err_num,
		&err_off,
		context);
	if (!regex) {
		PCRE2_UCHAR buffer[256];
		pcre2_get_error_message(err_num, buffer, sizeof(buffer));
		RZ_LOG_ERROR("Regex compilation failed at offset %" PFMTSZu ": %s\n", err_off,
			buffer);
		return NULL;
	}
	return regex;
}

/**
 * \brief Frees a given RzRegex.
 *
 * \param regex The RzRegex to free.
 */
RZ_API void rz_regex_free(RZ_OWN RzRegex *regex) {
	pcre2_code_free(regex);
}

RZ_OWN RzRegexMatchData *rz_regex_match_data_new(const RzRegex *regex, RzRegexGeneralContext *context) {
	return pcre2_match_data_create_from_pattern(regex, context);
}

void rz_regex_match_data_free(RZ_OWN RzRegexMatchData *match_data) {
	pcre2_match_data_free(match_data);
}

static RzRegexStatus rz_regex_match(const RzRegex *regex, RZ_NONNULL const char *text,
	RzRegexSize text_offset,
	RzRegexFlags options,
	RZ_NONNULL RZ_BORROW RzRegexMatchData *match_data,
	RZ_NULLABLE RzRegexMatchContext *mcontext) {
	return pcre2_match(regex, (PCRE2_SPTR)text, PCRE2_ZERO_TERMINATED, text_offset, options | PCRE2_MATCH_INVALID_UTF, match_data, mcontext);
}

/**
 * \brief Generates the error message to \p errcode.
 *
 * \param errcode The error code.
 * \param errbuf The error message buffer.
 * \param errbuf_size The error message buffer size in bytes.
 */
RZ_API void rz_regex_error_msg(RzRegexStatus errcode, RZ_OUT char *errbuf, RzRegexSize errbuf_size) {
	pcre2_get_error_message(errcode, (PCRE2_UCHAR *)errbuf, errbuf_size);
}

RZ_API const ut8 *rz_regex_get_match_name(const RzRegex *regex, ut32 name_idx) {
	rz_return_val_if_fail(regex, NULL);

	ut32 namecount;
	ut32 name_entry_size;
	PCRE2_SPTR nametable_ptr;

	pcre2_pattern_info(
		regex,
		PCRE2_INFO_NAMECOUNT,
		&namecount);

	pcre2_pattern_info(
		regex,
		PCRE2_INFO_NAMETABLE,
		&nametable_ptr);

	pcre2_pattern_info(
		regex,
		PCRE2_INFO_NAMEENTRYSIZE,
		&name_entry_size);

	for (size_t i = 0; i < namecount; i++) {
		int n = (nametable_ptr[0] << 8) | nametable_ptr[1];
		if (n == name_idx) {
			return nametable_ptr + 2;
		}
		nametable_ptr += name_entry_size;
	}
	return NULL;
}

RZ_API RZ_OWN RzVector /*<RzRegexMatch>*/ *rz_regex_match_first(
	const RzRegex *regex,
	RZ_NONNULL const char *text,
	RzRegexSize text_offset,
	RzRegexFlags options,
	RZ_NULLABLE RzRegexContexts *ctxs) {
	RzRegexMatchContext *mctx = NULL;
	RzRegexGeneralContext *gctx = NULL;
	if (ctxs) {
		mctx = ctxs->match;
		gctx = ctxs->general;
	}

	RzVector *matches = rz_vector_new(sizeof(RzRegexMatch), NULL, NULL);
	RzRegexMatchData *mdata = pcre2_match_data_create_from_pattern(regex, gctx);
	RzRegexStatus rc = rz_regex_match(regex, text, text_offset, options, mdata, mctx);

	if (rc == PCRE2_ERROR_NOMATCH) {
		// Nothing matched return empty vector.
		rz_regex_match_data_free(mdata);
		return matches;
	}

	if (rc < 0) {
		// Some error happend. Inform the user.
		PCRE2_UCHAR buffer[256];
		pcre2_get_error_message(rc, buffer, sizeof(buffer));
		RZ_LOG_WARN("Regex matching failed: %s\n", buffer);
		goto error;
	}

	// Add groups to vector
	PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(mdata);

	ut32 name_entry_size;
	PCRE2_SPTR nametable_ptr;

	pcre2_pattern_info(
		regex,
		PCRE2_INFO_NAMETABLE,
		&nametable_ptr);

	pcre2_pattern_info(
		regex,
		PCRE2_INFO_NAMEENTRYSIZE,
		&name_entry_size);

	for (size_t i = 0; i < rc; i++) {
		if (ovector[2 * i] > ovector[2 * i + 1]) {
			// This happens for \K lookaround. We fail if used.
			// See pcre2demo.c for details.
			RZ_LOG_ERROR("Usage of \\K to set start of the pattern later than the end, is not implemented.\n");
			goto error;
		}

		// Offset and length of match
		RzRegexMatch *match = RZ_NEW0(RzRegexMatch);
		match->start = ovector[2 * i];
		match->len = ovector[2 * i + 1] - match->start;

		// Match index with a name.
		// Index is saved in the first two bytes of a table entry.
		ut32 n = (nametable_ptr[0] << 8) | nametable_ptr[1];
		if (n != i) {
			// No name
			match->mname_idx = RZ_REGEX_UNSET;
			rz_vector_push(matches, match);
			continue;
		}

		match->mname_idx = n;
		nametable_ptr += name_entry_size;
		rz_vector_push(matches, match);
	}

	rz_regex_match_data_free(mdata);
	return matches;

error:
	rz_regex_match_data_free(mdata);
	rz_vector_free(matches);
	return NULL;
}

/**
 * \brief Finds all matches in a text and returns them as vector.
 */
RZ_API RZ_OWN RzPVector /*<RzVector<RzRegexMatch>>*/ *rz_regex_match_all(
	const RzRegex *regex,
	RZ_NONNULL const char *text,
	RzRegexSize text_offset,
	RzRegexFlags options,
	RZ_NULLABLE RzRegexContexts *ctxs) {
	rz_return_val_if_fail(regex && text, NULL);

	RzPVector *all_matches = rz_pvector_new((RzPVectorFree)rz_vector_free);
	RzVector *matches = rz_regex_match_first(regex, text, text_offset, options, ctxs);
	while (matches && rz_vector_len(matches) > 0) {
		rz_pvector_push(all_matches, matches);
		RzRegexMatch *m = rz_vector_head(matches);
		// Search again after the last match.
		text_offset = m->start + m->len;
		matches = rz_regex_match_first(regex, text, text_offset, options, ctxs);
	}

	// Free last vector without matches.
	rz_vector_free(matches);
	return all_matches;
}
