// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 LemonBoy <thatlemon@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_search.h"
#include <rz_vector.h>
#include <rz_regex.h>

/**
 * \return -1 on failure.
 */
RZ_API int rz_search_regexp_update(RzSearch *s, ut64 from, const ut8 *buf, int len) {
	RzSearchKeyword *kw;
	RzListIter *iter;
	RzPVector *matches = NULL;
	RzRegex *compiled = NULL;
	const int old_nhits = s->nhits;
	int ret = 0;

	rz_list_foreach (s->kws, iter, kw) {
		int reflags = RZ_REGEX_EXTENDED;

		if (kw->icase) {
			reflags |= RZ_REGEX_CASELESS;
		}

		compiled = rz_regex_new((char *)kw->bin_keyword, reflags);
		if (!compiled) {
			eprintf("Cannot compile '%s' regexp\n", kw->bin_keyword);
			return -1;
		}

		matches = rz_regex_match_all_not_grouped(compiled, (char *)buf, from, reflags);
		void *it;
		rz_pvector_foreach (matches, it) {
			RzRegexMatch *m = it;
			int t = rz_search_hit_new(s, kw, m->start);
			if (t == 0) {
				ret = -1;
				goto beach;
			}
			// Max hits reached
			if (t > 1) {
				goto beach;
			}
		}
		rz_pvector_free(matches);
	}

beach:
	rz_regex_free(compiled);
	rz_pvector_free(matches);
	if (!ret) {
		ret = s->nhits - old_nhits;
	}
	return ret;
}
