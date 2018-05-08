/*
 * This is free and unencumbered software released into the public domain.
 */

#ifndef RT_JSTRING_H
#define RT_JSTRING_H

/* NOTE: internal use only */

/*****************************************************************//**
 * @file jstring.h
 * @brief String converters from JSON to utf8 and vice versa
 *
 * JSON SPEC:
 *
 * A string is a sequence of Unicode code points wrapped with
 * quotation marks (U+0022). All characters may be placed within the
 * quotation marks except for the characters that must be escaped:
 * quotation mark (U+0022), reverse solidus (U+005C), and the control
 * characters U+0000 to U+001F. There are two-character escape
 * sequence representations of some characters.
 *
 * - \" represents the quotation mark character (U+0022).
 * - \\ represents the reverse solidus character (U+005C).
 * - \/ represents the solidus character (U+002F).
 * - \b represents the backspace character (U+0008).
 * - "\\f" represents the form feed character (U+000C).
 * - "\\n" represents the line feed character (U+000A).
 * - "\\r" represents the carriage return character (U+000D).
 * - "\\t" represents the character tabulation character (U+0009).
 *
 * So, for example, a string containing only a single reverse solidus
 * character may be represented as "\\".  Any code point may be
 * represented as a hexadecimal number. The meaning of such a number
 * is determined by ISO/IEC 10646. If the code point is in the Basic
 * Multilingual Plane (U+0000 through U+FFFF), then it may be
 * represented as a six-character sequence: a reverse solidus,
 * followed by the lowercase letter u, followed by four hexadecimal
 * digits that encode the code point. Hexadecimal digits can be digits
 * (U+0030 through U+0039) or the hexadecimal letters A through F in
 * uppercase (U+0041 through U+0046) or lowercase (U+0061 through
 * U+0066). So, for example, a string containing only a single reverse
 * solidus character may be represented as "\\u005C".
 *
 * The following four cases all produce the same result:
 * - "\\u002F"
 * - "\\u002f"
 * - "\/"
 * - "/"
 *
 * To escape a code point that is not in the Basic Multilingual Plane,
 * the character is represented as a twelvecharacter sequence,
 * encoding the UTF-16 surrogate pair. So for example, a string
 * containing only the G clef character (U+1D11E) may be represented
 * as "\\uD834\\uDD1E".
 * @see http://www.json.org
 *********************************************************************/

/**
 * @brief Converts a JSON string into UTF-8.
 *
 * 1) \\uXXXX, XXXX is treated as UTF-16 and converted into UTF-8.

 * 2) \\uXXXX, when XXXX is between 0xd800 and 0xdbff, XXXX is treated
 *    as a leading surrogate and expects the next \\uYYYY is the
 *    trailing surrogate where YYYY is between 0xdc00 and 0xdffff.
 *    The surrogate pair is converted into UTF-32 and converted again
 *    into UTF-8.
 *
 * 3) \\X, the known control characters are converted to the
 *    corresponding value.
 *
 * 4) \\X, where is between 0x00 and 0x1F, and not specified in the
 *    spec above, converted into X.
 *
 * 5) Rest are simply copied without conversion.
 *
 * @param str the destination buffer
 * @param jstr the JSON string
 * @param n the size of the destination buffer
 * @return a pointer to the character for continuing process
 */
extern const char *jstrtostr(char **str, const char *jstr, unsigned int n);


/**
 * @brief Converts a string into JSON.
 *
 * The string is assumed to be UTF-8.
 *
 * 1) Control characters, 0x00-0x1F, are escaped.
 *
 * 2) Double quote(") and backslash(\) are escaped.
 *
 * 3) Ascii characters (<=0x7F) are simply copied.
 *
 * 4) Rest are converted into UTF-16 with \\uXXXX.
 *
 * @param jstr the destination buffer in JSON
 * @param str the string which is assumed to be UTF-8
 * @param n the size of the destination buffer
 * @return a pointer to the character for continuing process
 */
extern unsigned int strtojstr(char **jstr, const char *str, unsigned int n);

#endif
