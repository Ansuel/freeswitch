/*
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2014, Anthony Minessale II <anthm@freeswitch.org>
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * The Initial Developer of the Original Code is
 * Michael Jerris <mike@jerris.com>
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Michael Jerris <mike@jerris.com>
 * Christian Marangi <ansuelsmth@gmail.com> # PCRE2 conversion
 *
 * switch_regex.h -- pcre2 wrapper and extensions Header
 *
 */
/*! \file switch_regex.h
    \brief Regex Header
*/
#ifndef SWITCH_REGEX_H
#define SWITCH_REGEX_H

SWITCH_BEGIN_EXTERN_C

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

typedef struct pcre2_memctl {
  void *    (*malloc)(size_t, void *);
  void      (*free)(void *, void *);
  void      *memory_data;
} pcre2_memctl;

#define CODE_BLOCKSIZE_TYPE size_t

typedef struct pcre2_real_code {
  pcre2_memctl memctl;            /* Memory control fields */
  const uint8_t *tables;          /* The character tables */
  void    *executable_jit;        /* Pointer to JIT code */
  uint8_t  start_bitmap[32];      /* Bitmap for starting code unit < 256 */
  CODE_BLOCKSIZE_TYPE blocksize;  /* Total (bytes) that was malloc-ed */
  uint32_t magic_number;          /* Paranoid and endianness check */
  uint32_t compile_options;       /* Options passed to pcre2_compile() */
  uint32_t overall_options;       /* Options after processing the pattern */
  uint32_t flags;                 /* Various state flags */
  uint32_t limit_match;           /* Limit set in the pattern */
  uint32_t limit_recursion;       /* Limit set in the pattern */
  uint32_t first_codeunit;        /* Starting code unit */
  uint32_t last_codeunit;         /* This codeunit must be seen */
  uint16_t bsr_convention;        /* What \R matches */
  uint16_t newline_convention;    /* What is a newline? */
  uint16_t max_lookbehind;        /* Longest lookbehind (characters) */
  uint16_t minlength;             /* Minimum length of match */
  uint16_t top_bracket;           /* Highest numbered group */
  uint16_t top_backref;           /* Highest numbered back reference */
  uint16_t name_entry_size;       /* Size (code units) of table entries */
  uint16_t name_count;            /* Number of name entries in the table */
} pcre2_real_code;

typedef struct pcre2_real_match_data {
  pcre2_memctl     memctl;
  const pcre2_real_code *code;    /* The pattern used for the match */
  PCRE2_SPTR       subject;       /* The subject that was matched */
  PCRE2_SPTR       mark;          /* Pointer to last mark */
  PCRE2_SIZE       leftchar;      /* Offset to leftmost code unit */
  PCRE2_SIZE       rightchar;     /* Offset to rightmost code unit */
  PCRE2_SIZE       startchar;     /* Offset to starting code unit */
  uint16_t         matchedby;     /* Type of match (normal, JIT, DFA) */
  uint16_t         oveccount;     /* Number of pairs */
  int              rc;            /* The return code from the match */
  PCRE2_SIZE       *ovector;    /* The first field */
} pcre2_real_match_data;

/**
 * @defgroup switch_regex Regular Expressions
 * @ingroup FREESWITCH
 * @{
 */
	typedef struct pcre2_real_code switch_regex_t;
	typedef struct pcre2_real_match_data switch_regex_match_data_t;

SWITCH_DECLARE(switch_regex_t *) switch_regex_compile(const char *pattern, int options, const char **errorptr, int *erroroffset,
													  const unsigned char *tables);

SWITCH_DECLARE(int) switch_regex_copy_substring(const char *subject, int *ovector, int stringcount, int stringnumber, char *buffer, int size);

SWITCH_DECLARE(void) switch_regex_free(void *data);

SWITCH_DECLARE(int) switch_regex_perform(const char *field, const char *expression, switch_regex_t **new_re, int *ovector, uint32_t olen);
SWITCH_DECLARE(void) switch_perform_substitution(switch_regex_t *re, int match_count, const char *data, const char *field_data,
												 char *substituted, switch_size_t len, int *ovector);

/*!
 \brief Function to evaluate an expression against a string
 \param target The string to find a match in
 \param expression The regular expression to run against the string
 \return Boolean if a match was found or not
*/
SWITCH_DECLARE(switch_status_t) switch_regex_match(const char *target, const char *expression);

/*!
 \brief Function to evaluate an expression against a string
 \param target The string to find a match in
 \param expression The regular expression to run against the string
 \param partial_match If non-zero returns SUCCESS if the target is a partial match, on successful return, this is set to non-zero if the match was partial and zero if it was a full match
 \return Boolean if a match was found or not
*/
SWITCH_DECLARE(switch_status_t) switch_regex_match_partial(const char *target, const char *expression, int *partial_match);

SWITCH_DECLARE(void) switch_capture_regex(switch_regex_t *re, int match_count, const char *field_data,
										  int *ovector, const char *var, switch_cap_callback_t callback, void *user_data);

SWITCH_DECLARE_NONSTD(void) switch_regex_set_var_callback(const char *var, const char *val, void *user_data);
SWITCH_DECLARE_NONSTD(void) switch_regex_set_event_header_callback(const char *var, const char *val, void *user_data);

#define switch_regex_safe_free(re)	if (re) {\
				switch_regex_free(re);\
				re = NULL;\
			}


/** @} */

SWITCH_END_EXTERN_C
#endif
/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4 noet:
 */
