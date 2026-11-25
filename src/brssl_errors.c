/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <pgmspace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "bearssl/bearssl.h"

static const char _NAME_BR_ERR_BAD_PARAM[] PROGMEM = "BR_ERR_BAD_PARAM";
static const char _NAME_BR_ERR_BAD_STATE[] PROGMEM = "BR_ERR_BAD_STATE";
static const char _NAME_BR_ERR_UNSUPPORTED_VERSION[] PROGMEM = "BR_ERR_UNSUPPORTED_VERSION";
static const char _NAME_BR_ERR_BAD_VERSION[] PROGMEM = "BR_ERR_BAD_VERSION";
static const char _NAME_BR_ERR_BAD_LENGTH[] PROGMEM = "BR_ERR_BAD_LENGTH";
static const char _NAME_BR_ERR_TOO_LARGE[] PROGMEM = "BR_ERR_TOO_LARGE";
static const char _NAME_BR_ERR_BAD_MAC[] PROGMEM = "BR_ERR_BAD_MAC";
static const char _NAME_BR_ERR_NO_RANDOM[] PROGMEM = "BR_ERR_NO_RANDOM";
static const char _NAME_BR_ERR_UNKNOWN_TYPE[] PROGMEM = "BR_ERR_UNKNOWN_TYPE";
static const char _NAME_BR_ERR_UNEXPECTED[] PROGMEM = "BR_ERR_UNEXPECTED";
static const char _NAME_BR_ERR_BAD_CCS[] PROGMEM = "BR_ERR_BAD_CCS";
static const char _NAME_BR_ERR_BAD_ALERT[] PROGMEM = "BR_ERR_BAD_ALERT";
static const char _NAME_BR_ERR_BAD_HANDSHAKE[] PROGMEM = "BR_ERR_BAD_HANDSHAKE";
static const char _NAME_BR_ERR_OVERSIZED_ID[] PROGMEM = "BR_ERR_OVERSIZED_ID";
static const char _NAME_BR_ERR_BAD_CIPHER_SUITE[] PROGMEM = "BR_ERR_BAD_CIPHER_SUITE";
static const char _NAME_BR_ERR_BAD_COMPRESSION[] PROGMEM = "BR_ERR_BAD_COMPRESSION";
static const char _NAME_BR_ERR_BAD_FRAGLEN[] PROGMEM = "BR_ERR_BAD_FRAGLEN";
static const char _NAME_BR_ERR_BAD_SECRENEG[] PROGMEM = "BR_ERR_BAD_SECRENEG";
static const char _NAME_BR_ERR_EXTRA_EXTENSION[] PROGMEM = "BR_ERR_EXTRA_EXTENSION";
static const char _NAME_BR_ERR_BAD_SNI[] PROGMEM = "BR_ERR_BAD_SNI";
static const char _NAME_BR_ERR_BAD_HELLO_DONE[] PROGMEM = "BR_ERR_BAD_HELLO_DONE";
static const char _NAME_BR_ERR_LIMIT_EXCEEDED[] PROGMEM = "BR_ERR_LIMIT_EXCEEDED";
static const char _NAME_BR_ERR_BAD_FINISHED[] PROGMEM = "BR_ERR_BAD_FINISHED";
static const char _NAME_BR_ERR_RESUME_MISMATCH[] PROGMEM = "BR_ERR_RESUME_MISMATCH";
static const char _NAME_BR_ERR_INVALID_ALGORITHM[] PROGMEM = "BR_ERR_INVALID_ALGORITHM";
static const char _NAME_BR_ERR_BAD_SIGNATURE[] PROGMEM = "BR_ERR_BAD_SIGNATURE";
static const char _NAME_BR_ERR_WRONG_KEY_USAGE[] PROGMEM = "BR_ERR_WRONG_KEY_USAGE";
static const char _NAME_BR_ERR_NO_CLIENT_AUTH[] PROGMEM = "BR_ERR_NO_CLIENT_AUTH";
static const char _NAME_BR_ERR_IO[] PROGMEM = "BR_ERR_IO";
static const char _NAME_BR_ERR_X509_INVALID_VALUE[] PROGMEM = "BR_ERR_X509_INVALID_VALUE";
static const char _NAME_BR_ERR_X509_TRUNCATED[] PROGMEM = "BR_ERR_X509_TRUNCATED";
static const char _NAME_BR_ERR_X509_EMPTY_CHAIN[] PROGMEM = "BR_ERR_X509_EMPTY_CHAIN";
static const char _NAME_BR_ERR_X509_INNER_TRUNC[] PROGMEM = "BR_ERR_X509_INNER_TRUNC";
static const char _NAME_BR_ERR_X509_BAD_TAG_CLASS[] PROGMEM = "BR_ERR_X509_BAD_TAG_CLASS";
static const char _NAME_BR_ERR_X509_BAD_TAG_VALUE[] PROGMEM = "BR_ERR_X509_BAD_TAG_VALUE";
static const char _NAME_BR_ERR_X509_INDEFINITE_LENGTH[] PROGMEM = "BR_ERR_X509_INDEFINITE_LENGTH";
static const char _NAME_BR_ERR_X509_EXTRA_ELEMENT[] PROGMEM = "BR_ERR_X509_EXTRA_ELEMENT";
static const char _NAME_BR_ERR_X509_UNEXPECTED[] PROGMEM = "BR_ERR_X509_UNEXPECTED";
static const char _NAME_BR_ERR_X509_NOT_CONSTRUCTED[] PROGMEM = "BR_ERR_X509_NOT_CONSTRUCTED";
static const char _NAME_BR_ERR_X509_NOT_PRIMITIVE[] PROGMEM = "BR_ERR_X509_NOT_PRIMITIVE";
static const char _NAME_BR_ERR_X509_PARTIAL_BYTE[] PROGMEM = "BR_ERR_X509_PARTIAL_BYTE";
static const char _NAME_BR_ERR_X509_BAD_BOOLEAN[] PROGMEM = "BR_ERR_X509_BAD_BOOLEAN";
static const char _NAME_BR_ERR_X509_OVERFLOW[] PROGMEM = "BR_ERR_X509_OVERFLOW";
static const char _NAME_BR_ERR_X509_BAD_DN[] PROGMEM = "BR_ERR_X509_BAD_DN";
static const char _NAME_BR_ERR_X509_BAD_TIME[] PROGMEM = "BR_ERR_X509_BAD_TIME";
static const char _NAME_BR_ERR_X509_UNSUPPORTED[] PROGMEM = "BR_ERR_X509_UNSUPPORTED";
static const char _NAME_BR_ERR_X509_LIMIT_EXCEEDED[] PROGMEM = "BR_ERR_X509_LIMIT_EXCEEDED";
static const char _NAME_BR_ERR_X509_WRONG_KEY_TYPE[] PROGMEM = "BR_ERR_X509_WRONG_KEY_TYPE";
static const char _NAME_BR_ERR_X509_BAD_SIGNATURE[] PROGMEM = "BR_ERR_X509_BAD_SIGNATURE";
static const char _NAME_BR_ERR_X509_TIME_UNKNOWN[] PROGMEM = "BR_ERR_X509_TIME_UNKNOWN";
static const char _NAME_BR_ERR_X509_EXPIRED[] PROGMEM = "BR_ERR_X509_EXPIRED";
static const char _NAME_BR_ERR_X509_DN_MISMATCH[] PROGMEM = "BR_ERR_X509_DN_MISMATCH";
static const char _NAME_BR_ERR_X509_BAD_SERVER_NAME[] PROGMEM = "BR_ERR_X509_BAD_SERVER_NAME";
static const char _NAME_BR_ERR_X509_CRITICAL_EXTENSION[] PROGMEM = "BR_ERR_X509_CRITICAL_EXTENSION";
static const char _NAME_BR_ERR_X509_NOT_CA[] PROGMEM = "BR_ERR_X509_NOT_CA";
static const char _NAME_BR_ERR_X509_FORBIDDEN_KEY_USAGE[] PROGMEM = "BR_ERR_X509_FORBIDDEN_KEY_USAGE";
static const char _NAME_BR_ERR_X509_WEAK_PUBLIC_KEY[] PROGMEM = "BR_ERR_X509_WEAK_PUBLIC_KEY";
static const char _NAME_BR_ERR_X509_NOT_TRUSTED[] PROGMEM = "BR_ERR_X509_NOT_TRUSTED";

static const struct {
    int err;
    const char *name;
} errors[] PROGMEM = {
    {
        BR_ERR_BAD_PARAM,
        _NAME_BR_ERR_BAD_PARAM
    }, {
        BR_ERR_BAD_STATE,
        _NAME_BR_ERR_BAD_STATE
    }, {
        BR_ERR_UNSUPPORTED_VERSION,
        _NAME_BR_ERR_UNSUPPORTED_VERSION
    }, {
        BR_ERR_BAD_VERSION,
        _NAME_BR_ERR_BAD_VERSION
    }, {
        BR_ERR_BAD_LENGTH,
        _NAME_BR_ERR_BAD_LENGTH
    }, {
        BR_ERR_TOO_LARGE,
        _NAME_BR_ERR_TOO_LARGE
    }, {
        BR_ERR_BAD_MAC,
        _NAME_BR_ERR_BAD_MAC
    }, {
        BR_ERR_NO_RANDOM,
        _NAME_BR_ERR_NO_RANDOM
    }, {
        BR_ERR_UNKNOWN_TYPE,
        _NAME_BR_ERR_UNKNOWN_TYPE
    }, {
        BR_ERR_UNEXPECTED,
        _NAME_BR_ERR_UNEXPECTED
    }, {
        BR_ERR_BAD_CCS,
        _NAME_BR_ERR_BAD_CCS
    }, {
        BR_ERR_BAD_ALERT,
        _NAME_BR_ERR_BAD_ALERT
    }, {
        BR_ERR_BAD_HANDSHAKE,
        _NAME_BR_ERR_BAD_HANDSHAKE
    }, {
        BR_ERR_OVERSIZED_ID,
        _NAME_BR_ERR_OVERSIZED_ID
    }, {
        BR_ERR_BAD_CIPHER_SUITE,
        _NAME_BR_ERR_BAD_CIPHER_SUITE
    }, {
        BR_ERR_BAD_COMPRESSION,
        _NAME_BR_ERR_BAD_COMPRESSION
    }, {
        BR_ERR_BAD_FRAGLEN,
        _NAME_BR_ERR_BAD_FRAGLEN
    }, {
        BR_ERR_BAD_SECRENEG,
        _NAME_BR_ERR_BAD_SECRENEG
    }, {
        BR_ERR_EXTRA_EXTENSION,
        _NAME_BR_ERR_EXTRA_EXTENSION
    }, {
        BR_ERR_BAD_SNI,
        _NAME_BR_ERR_BAD_SNI
    }, {
        BR_ERR_BAD_HELLO_DONE,
        _NAME_BR_ERR_BAD_HELLO_DONE
    }, {
        BR_ERR_LIMIT_EXCEEDED,
        _NAME_BR_ERR_LIMIT_EXCEEDED
    }, {
        BR_ERR_BAD_FINISHED,
        _NAME_BR_ERR_BAD_FINISHED
    }, {
        BR_ERR_RESUME_MISMATCH,
        _NAME_BR_ERR_RESUME_MISMATCH
    }, {
        BR_ERR_INVALID_ALGORITHM,
        _NAME_BR_ERR_INVALID_ALGORITHM
    }, {
        BR_ERR_BAD_SIGNATURE,
        _NAME_BR_ERR_BAD_SIGNATURE
    }, {
        BR_ERR_WRONG_KEY_USAGE,
        _NAME_BR_ERR_WRONG_KEY_USAGE
    }, {
        BR_ERR_NO_CLIENT_AUTH,
        _NAME_BR_ERR_NO_CLIENT_AUTH
    }, {
        BR_ERR_IO,
        _NAME_BR_ERR_IO
    }, {
        BR_ERR_X509_INVALID_VALUE,
        _NAME_BR_ERR_X509_INVALID_VALUE
    },
    {
        BR_ERR_X509_TRUNCATED,
        _NAME_BR_ERR_X509_TRUNCATED
    },
    {
        BR_ERR_X509_EMPTY_CHAIN,
        _NAME_BR_ERR_X509_EMPTY_CHAIN
    },
    {
        BR_ERR_X509_INNER_TRUNC,
        _NAME_BR_ERR_X509_INNER_TRUNC
    },
    {
        BR_ERR_X509_BAD_TAG_CLASS,
        _NAME_BR_ERR_X509_BAD_TAG_CLASS
    },
    {
        BR_ERR_X509_BAD_TAG_VALUE,
        _NAME_BR_ERR_X509_BAD_TAG_VALUE
    },
    {
        BR_ERR_X509_INDEFINITE_LENGTH,
        _NAME_BR_ERR_X509_INDEFINITE_LENGTH
    },
    {
        BR_ERR_X509_EXTRA_ELEMENT,
        _NAME_BR_ERR_X509_EXTRA_ELEMENT
    },
    {
        BR_ERR_X509_UNEXPECTED,
        _NAME_BR_ERR_X509_UNEXPECTED
    },
    {
        BR_ERR_X509_NOT_CONSTRUCTED,
        _NAME_BR_ERR_X509_NOT_CONSTRUCTED
    },
    {
        BR_ERR_X509_NOT_PRIMITIVE,
        _NAME_BR_ERR_X509_NOT_PRIMITIVE
    },
    {
        BR_ERR_X509_PARTIAL_BYTE,
        _NAME_BR_ERR_X509_PARTIAL_BYTE
    },
    {
        BR_ERR_X509_BAD_BOOLEAN,
        _NAME_BR_ERR_X509_BAD_BOOLEAN
    },
    {
        BR_ERR_X509_OVERFLOW,
        _NAME_BR_ERR_X509_OVERFLOW
    },
    {
        BR_ERR_X509_BAD_DN,
        _NAME_BR_ERR_X509_BAD_DN
    },
    {
        BR_ERR_X509_BAD_TIME,
        _NAME_BR_ERR_X509_BAD_TIME
    },
    {
        BR_ERR_X509_UNSUPPORTED,
        _NAME_BR_ERR_X509_UNSUPPORTED
    },
    {
        BR_ERR_X509_LIMIT_EXCEEDED,
        _NAME_BR_ERR_X509_LIMIT_EXCEEDED
    },
    {
        BR_ERR_X509_WRONG_KEY_TYPE,
        _NAME_BR_ERR_X509_WRONG_KEY_TYPE
    },
    {
        BR_ERR_X509_BAD_SIGNATURE,
        _NAME_BR_ERR_X509_BAD_SIGNATURE
    },
    {
        BR_ERR_X509_TIME_UNKNOWN,
        _NAME_BR_ERR_X509_TIME_UNKNOWN
    },
    {
        BR_ERR_X509_EXPIRED,
        _NAME_BR_ERR_X509_EXPIRED
    },
    {
        BR_ERR_X509_DN_MISMATCH,
        _NAME_BR_ERR_X509_DN_MISMATCH
    },
    {
        BR_ERR_X509_BAD_SERVER_NAME,
        _NAME_BR_ERR_X509_BAD_SERVER_NAME
    },
    {
        BR_ERR_X509_CRITICAL_EXTENSION,
        _NAME_BR_ERR_X509_CRITICAL_EXTENSION
    },
    {
        BR_ERR_X509_NOT_CA,
        _NAME_BR_ERR_X509_NOT_CA
    },
    {
        BR_ERR_X509_FORBIDDEN_KEY_USAGE,
        _NAME_BR_ERR_X509_FORBIDDEN_KEY_USAGE
    },
    {
        BR_ERR_X509_WEAK_PUBLIC_KEY,
        _NAME_BR_ERR_X509_WEAK_PUBLIC_KEY
    },
    {
        BR_ERR_X509_NOT_TRUSTED,
        _NAME_BR_ERR_X509_NOT_TRUSTED
    },
    { 0, 0 }
};

/* Returns PROGMEM pointers. */
PGM_P
async_tcp_find_error_name(int err)
{
    size_t u;
    PGM_P name;

    for (u = 0; (name = (PGM_P)pgm_read_ptr(&errors[u].name)) != NULL; u++) {
        if ((int)pgm_read_dword(&errors[u].err) == err) {
            return name;
        }
    }
    return NULL;
}
