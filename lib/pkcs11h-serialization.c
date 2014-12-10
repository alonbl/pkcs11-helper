/*
 * Copyright (c) 2005-2011 Alon Bar-Lev <alon.barlev@gmail.com>
 * All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, or the BSD license.
 *
 * GNU General Public License (GPL) Version 2
 * ===========================================
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (see the file COPYING.GPL included with this
 * distribution); if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * BSD License
 * ============
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     o Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     o Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     o Neither the name of the Alon Bar-Lev nor the names of its
 *       contributors may be used to endorse or promote products derived from
 *       this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "common.h"

#include "_pkcs11h-core.h"
#include "_pkcs11h-mem.h"
#include "_pkcs11h-util.h"
#include "_pkcs11h-token.h"
#include "_pkcs11h-certificate.h"

#define __PKCS11H_SERIALIZE_INVALID_CHARS	"\\/\"'%&#@!?$* <>{}[]()`|:;,.+-"

#if defined(ENABLE_PKCS11H_TOKEN) || defined(ENABLE_PKCS11H_CERTIFICATE)

CK_RV
pkcs11h_token_serializeTokenId (
	OUT char * const sz,
	IN OUT size_t *max,
	IN const pkcs11h_token_id_t token_id
) {
	const char *sources[5];
	CK_RV rv = CKR_FUNCTION_FAILED;
	size_t n;
	int e;

	/*_PKCS11H_ASSERT (sz!=NULL); Not required*/
	_PKCS11H_ASSERT (max!=NULL);
	_PKCS11H_ASSERT (token_id!=NULL);

	{ /* Must be after assert */
		sources[0] = token_id->manufacturerID;
		sources[1] = token_id->model;
		sources[2] = token_id->serialNumber;
		sources[3] = token_id->label;
		sources[4] = NULL;
	}

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_serializeTokenId entry sz=%p, *max="P_Z", token_id=%p",
		sz,
		sz != NULL ? *max : 0,
		(void *)token_id
	);

	n = 0;
	for (e=0;sources[e] != NULL;e++) {
		size_t t;
		if (
			(rv = _pkcs11h_util_escapeString (
				NULL,
				sources[e],
				&t,
				__PKCS11H_SERIALIZE_INVALID_CHARS
			)) != CKR_OK
		) {
			goto cleanup;
		}
		n+=t;
	}

	if (sz != NULL) {
		if (*max < n) {
			rv = CKR_ATTRIBUTE_VALUE_INVALID;
			goto cleanup;
		}

		n = 0;
		for (e=0;sources[e] != NULL;e++) {
			size_t t = *max-n;
			if (
				(rv = _pkcs11h_util_escapeString (
					sz+n,
					sources[e],
					&t,
					__PKCS11H_SERIALIZE_INVALID_CHARS
				)) != CKR_OK
			) {
				goto cleanup;
			}
			n+=t;
			sz[n-1] = '/';
		}
		sz[n-1] = '\x0';
	}

	*max = n;
	rv = CKR_OK;

cleanup:

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_serializeTokenId return rv=%lu-'%s', *max="P_Z", sz='%s'",
		rv,
		pkcs11h_getMessage (rv),
		*max,
		sz
	);

	return rv;
}

static int hexnybble(char c)
{
	if (c >= '0' || c <= '9')
		return c - '0';
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	else if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	else return -1;
}

static CK_RV parse_token_uri_attr (
	const char *uri,
	size_t urilen,
	char *tokstr,
	size_t toklen,
	size_t *parsed_len
) {
	int n1, n2;
	size_t orig_toklen = toklen;

	while (urilen && toklen > 1) {
		if (*uri == '%') {
			if (urilen < 3)
				return CKR_ATTRIBUTE_VALUE_INVALID;

			n1 = hexnybble(uri[1]);
			n2 = hexnybble(uri[2]);
			if (n1 == -1 || n2 == -1)
				return CKR_ATTRIBUTE_VALUE_INVALID;

			*tokstr = (n1 << 4) | n2;
			uri += 2;
			urilen -= 2;
		} else {
			*tokstr = *uri;
		}
		tokstr++;
		uri++;
		toklen--;
		urilen--;
		tokstr[1] = 0;
	}
	if (urilen)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	if (parsed_len)
		*parsed_len = orig_toklen - toklen;

	return CKR_OK;
}

static CK_RV parse_id_attr (
	const char *uri,
	size_t urilen,
	CK_BYTE_PTR *p_id,
	size_t *p_id_len
) {
	CK_RV rv;

	rv = _pkcs11h_mem_malloc ((void *)p_id, urilen + 1);
	if (rv != CKR_OK)
		return rv;

	return parse_token_uri_attr (uri, urilen, (void *)*p_id, urilen + 1, p_id_len);
}

static CK_RV parse_pkcs11_uri (
	OUT pkcs11h_token_id_t token_id,
	OUT pkcs11h_certificate_id_t certificate_id,
	IN const char * const sz
) {
	const char *semicolon, *equals, *p;

	_PKCS11H_ASSERT (token_id!=NULL);
	_PKCS11H_ASSERT (sz!=NULL);

	if (strncmp (sz, "pkcs11:", 7))
		return CKR_ATTRIBUTE_VALUE_INVALID;

	semicolon = sz + 6;
	while (semicolon[0] && semicolon[1]) {
		int keylen;

		p = semicolon + 1;
		semicolon = strchr (p, ';');
		if (!semicolon)
			semicolon = p + strlen(p);

		equals = strchr (p, '=');
		if (equals > semicolon)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		keylen = equals - p;

		if (keylen == 5 && !strncmp(p, "model", 5) &&
		    parse_token_uri_attr(equals + 1, semicolon - equals - 1,
					 (char *)&token_id->model,
					 sizeof(token_id->model),
					 NULL) == CKR_OK)
			continue;
		else if (keylen == 5 && !strncmp(p, "token", 5) &&
			 parse_token_uri_attr(equals + 1, semicolon - equals - 1,
					      (char *)&token_id->label,
					      sizeof(token_id->label),
					      NULL) == CKR_OK)
			continue;
		else if (keylen == 12 && !strncmp(p, "manufacturer", 12) &&
			 parse_token_uri_attr(equals + 1, semicolon - equals - 1,
					      (char *)&token_id->manufacturerID,
					      sizeof(token_id->manufacturerID),
					      NULL) == CKR_OK)
			continue;
		else if (keylen == 6 && !strncmp(p, "serial", 6) &&
			 parse_token_uri_attr(equals + 1, semicolon - equals - 1,
					      (char *)&token_id->serialNumber,
					      sizeof(token_id->serialNumber),
					      NULL) == CKR_OK)
			continue;
		else if (certificate_id && keylen == 2 && !strncmp(p, "id", 2) &&
			 parse_id_attr(equals + 1, semicolon - equals - 1,
				       &certificate_id->attrCKA_ID,
				       &certificate_id->attrCKA_ID_size) == CKR_OK)
			continue;
		/* We don't parse object= because the match code doesn't support
		   matching by label. */

		/* Failed to parse PKCS#11 URI element. */
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}
	/* The matching code doesn't support support partial matches; it needs
	 * *all* of manufacturer, model, serial and label attributes to be
	 * defined. So reject partial URIs early instead of letting it do the
	 * wrong thing. We can maybe improve this later. */
	if (!token_id->model[0] || !token_id->label[0] ||
	    !token_id->manufacturerID[0] || !token_id->serialNumber[0]) {
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	/* For a certificate ID we need CKA_ID */
	if (certificate_id && !certificate_id->attrCKA_ID_size) {
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	return CKR_OK;
}

static CK_RV
pkcs11h_token_legacy_deserializeTokenId (
	OUT pkcs11h_token_id_t *p_token_id,
	IN const char * const sz
) {
#define __PKCS11H_TARGETS_NUMBER 4
	struct {
		char *p;
		size_t s;
	} targets[__PKCS11H_TARGETS_NUMBER];

	pkcs11h_token_id_t token_id = NULL;
	char *p1 = NULL;
	char *_sz = NULL;
	int e;
	CK_RV rv = CKR_FUNCTION_FAILED;

	if (
		(rv = _pkcs11h_mem_strdup (
			(void *)&_sz,
			sz
		)) != CKR_OK
	) {
		goto cleanup;
	}

	p1 = _sz;

	if ((rv = _pkcs11h_token_newTokenId (&token_id)) != CKR_OK) {
		goto cleanup;
	}

	targets[0].p = token_id->manufacturerID;
	targets[0].s = sizeof (token_id->manufacturerID);
	targets[1].p = token_id->model;
	targets[1].s = sizeof (token_id->model);
	targets[2].p = token_id->serialNumber;
	targets[2].s = sizeof (token_id->serialNumber);
	targets[3].p = token_id->label;
	targets[3].s = sizeof (token_id->label);

	for (e=0;e < __PKCS11H_TARGETS_NUMBER;e++) {
		size_t l;
		char *p2 = NULL;

		/*
		 * Don't search for last
		 * separator
		 */
		if (e != __PKCS11H_TARGETS_NUMBER-1) {
			p2 = strchr (p1, '/');
			if (p2 == NULL) {
				rv = CKR_ATTRIBUTE_VALUE_INVALID;
				goto cleanup;
			}
			else {
				*p2 = '\x0';
			}
		}

		if (
			(rv = _pkcs11h_util_unescapeString (
				NULL,
				p1,
				&l
			)) != CKR_OK
		) {
			goto cleanup;
		}

		if (l > targets[e].s) {
			rv = CKR_ATTRIBUTE_VALUE_INVALID;
			goto cleanup;
		}

		l = targets[e].s;

		if (
			(rv = _pkcs11h_util_unescapeString (
				targets[e].p,
				p1,
				&l
			)) != CKR_OK
		) {
			goto cleanup;
		}

		p1 = p2+1;
	}

	strncpy (
		token_id->display,
		token_id->label,
		sizeof (token_id->display)
	);

	*p_token_id = token_id;
	token_id = NULL;

	rv = CKR_OK;

cleanup:

	if (_sz != NULL) {
		_pkcs11h_mem_free ((void *)&_sz);
	}

	if (token_id != NULL) {
		pkcs11h_token_freeTokenId (token_id);
	}

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_deserializeTokenId return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
#undef __PKCS11H_TARGETS_NUMBER
}

CK_RV
pkcs11h_token_deserializeTokenId (
	OUT pkcs11h_token_id_t *p_token_id,
	IN const char * const sz
) {
#define __PKCS11H_TARGETS_NUMBER 4
	struct {
		char *p;
		size_t s;
	} targets[__PKCS11H_TARGETS_NUMBER];

	pkcs11h_token_id_t token_id = NULL;
	CK_RV rv = CKR_FUNCTION_FAILED;

	_PKCS11H_ASSERT (p_token_id!=NULL);
	_PKCS11H_ASSERT (sz!=NULL);

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_deserializeTokenId entry p_token_id=%p, sz='%s'",
		(void *)p_token_id,
		sz
	);

	*p_token_id = NULL;

	if (strncmp (sz, "pkcs11:", 7))
		return pkcs11h_token_legacy_deserializeTokenId(p_token_id, sz);

	if ((rv = _pkcs11h_token_newTokenId (&token_id)) != CKR_OK) {
		goto cleanup;
	}

	if ((rv = parse_pkcs11_uri(token_id, NULL, sz)) != CKR_OK) {
		goto cleanup;
	}

	strncpy (
		token_id->display,
		token_id->label,
		sizeof (token_id->display)
	);

	*p_token_id = token_id;
	token_id = NULL;

	rv = CKR_OK;

cleanup:
	if (token_id != NULL) {
		pkcs11h_token_freeTokenId (token_id);
	}

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_deserializeTokenId return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
#undef __PKCS11H_TARGETS_NUMBER
}

#endif				/* ENABLE_PKCS11H_TOKEN || ENABLE_PKCS11H_CERTIFICATE */

#if defined(ENABLE_PKCS11H_CERTIFICATE)

CK_RV
pkcs11h_certificate_serializeCertificateId (
	OUT char * const sz,
	IN OUT size_t *max,
	IN const pkcs11h_certificate_id_t certificate_id
) {
	CK_RV rv = CKR_FUNCTION_FAILED;
	size_t saved_max = 0;
	size_t n = 0;
	size_t _max = 0;

	/*_PKCS11H_ASSERT (sz!=NULL); Not required */
	_PKCS11H_ASSERT (max!=NULL);
	_PKCS11H_ASSERT (certificate_id!=NULL);

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_serializeCertificateId entry sz=%p, *max="P_Z", certificate_id=%p",
		sz,
		sz != NULL ? *max : 0,
		(void *)certificate_id
	);

	if (sz != NULL) {
		saved_max = n = *max;
	}
	*max = 0;

	if (
		(rv = pkcs11h_token_serializeTokenId (
			sz,
			&n,
			certificate_id->token_id
		)) != CKR_OK
	) {
		goto cleanup;
	}

	_max = n + certificate_id->attrCKA_ID_size*2 + 1;

	if (sz != NULL) {
		if (saved_max < _max) {
			rv = CKR_ATTRIBUTE_VALUE_INVALID;
			goto cleanup;
		}

		sz[n-1] = '/';
		rv = _pkcs11h_util_binaryToHex (
			sz+n,
			saved_max-n,
			certificate_id->attrCKA_ID,
			certificate_id->attrCKA_ID_size
		);
	}

	*max = _max;
	rv = CKR_OK;

cleanup:

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_serializeCertificateId return rv=%lu-'%s', *max="P_Z", sz='%s'",
		rv,
		pkcs11h_getMessage (rv),
		*max,
		sz
	);

	return rv;
}

static CK_RV
pkcs11h_certificate_legacy_deserializeCertificateId (
	OUT pkcs11h_certificate_id_t * const p_certificate_id,
	IN const char * const sz
) {
	pkcs11h_certificate_id_t certificate_id = NULL;
	CK_RV rv = CKR_FUNCTION_FAILED;
	char *p = NULL;
	char *_sz = NULL;

	if (
		(rv = _pkcs11h_mem_strdup (
			(void *)&_sz,
			sz
		)) != CKR_OK
	) {
		goto cleanup;
	}

	p = _sz;

	if ((rv = _pkcs11h_certificate_newCertificateId (&certificate_id)) != CKR_OK) {
		goto cleanup;
	}

	if ((p = strrchr (_sz, '/')) == NULL) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto cleanup;
	}

	*p = '\x0';
	p++;

	if (
		(rv = pkcs11h_token_deserializeTokenId (
			&certificate_id->token_id,
			_sz
		)) != CKR_OK
	) {
		goto cleanup;
	}

	certificate_id->attrCKA_ID_size = strlen (p)/2;

	if (
		(rv = _pkcs11h_mem_malloc (
			(void *)&certificate_id->attrCKA_ID,
			certificate_id->attrCKA_ID_size)
		) != CKR_OK ||
		(rv = _pkcs11h_util_hexToBinary (
			certificate_id->attrCKA_ID,
			p,
			&certificate_id->attrCKA_ID_size
		)) != CKR_OK
	) {
		goto cleanup;
	}

	*p_certificate_id = certificate_id;
	certificate_id = NULL;
	rv = CKR_OK;

cleanup:

	if (certificate_id != NULL) {
		pkcs11h_certificate_freeCertificateId (certificate_id);
		certificate_id = NULL;
	}

	if (_sz != NULL) {
		_pkcs11h_mem_free ((void *)&_sz);
	}

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_legacy_deserializeCertificateId return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;

}

CK_RV
pkcs11h_certificate_deserializeCertificateId (
	OUT pkcs11h_certificate_id_t * const p_certificate_id,
	IN const char * const sz
) {
	pkcs11h_certificate_id_t certificate_id = NULL;
	CK_RV rv = CKR_FUNCTION_FAILED;

	_PKCS11H_ASSERT (p_certificate_id!=NULL);
	_PKCS11H_ASSERT (sz!=NULL);

	*p_certificate_id = NULL;

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_deserializeCertificateId entry p_certificate_id=%p, sz='%s'",
		(void *)p_certificate_id,
		sz
	);

	if (strncmp(sz, "pkcs11:", 7))
		return pkcs11h_certificate_legacy_deserializeCertificateId (p_certificate_id, sz);

	if ((rv = _pkcs11h_certificate_newCertificateId (&certificate_id)) != CKR_OK) {
		goto cleanup;
	}
	if ((rv = _pkcs11h_token_newTokenId (&certificate_id->token_id)) != CKR_OK) {
		goto cleanup;
	}

	if ((rv= parse_pkcs11_uri(certificate_id->token_id, certificate_id, sz)) != CKR_OK) {
		goto cleanup;
	}

	*p_certificate_id = certificate_id;
	certificate_id = NULL;
	rv = CKR_OK;

cleanup:
	if (certificate_id != NULL) {
		pkcs11h_certificate_freeCertificateId (certificate_id);
		certificate_id = NULL;
	}

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_deserializeCertificateId return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;

}

#endif				/* ENABLE_PKCS11H_CERTIFICATE */

