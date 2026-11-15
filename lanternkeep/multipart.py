"""Bounded, flat browser multipart forms; never recursively parse MIME bodies."""
import re
from email.parser import BytesParser
from email.policy import default as email_policy


class FileTooLarge(ValueError):
    pass


def parse_form(content_type, body, max_parts=100, max_file=200 * 1024):
    if '\r' in content_type or '\n' in content_type:
        raise ValueError('Malformed multipart header')
    parser = BytesParser(policy=email_policy)
    header = parser.parsebytes(('Content-Type: ' + content_type + '\r\n\r\n').encode('latin-1'), headersonly=True)
    boundary = header.get_boundary()
    if header.defects or header.get_content_type() != 'multipart/form-data' or not boundary:
        raise ValueError('Multipart boundary missing or invalid')
    try:
        boundary = boundary.encode('ascii')
    except UnicodeEncodeError as exc:
        raise ValueError('Invalid multipart boundary') from exc
    if not 1 <= len(boundary) <= 70 or boundary[-1:] == b' ' or not re.fullmatch(rb"[0-9A-Za-z'()+_,./:=? -]+", boundary):
        raise ValueError('Invalid multipart boundary')
    marker = b'--' + boundary
    # Conservative linear preflight, before allocating any part Messages.
    if body.count(marker) > max_parts + 1:
        raise ValueError('Multipart forms are limited to %s parts' % max_parts)
    delimiter = re.compile(rb'(?:\A|(?<=\n))' + re.escape(marker) + rb'(--)?[ \t]*(?:\r?\n|\Z)')
    boundaries = list(delimiter.finditer(body))
    if not boundaries or boundaries[0].group(1) or not boundaries[-1].group(1):
        raise ValueError('Multipart boundary missing or invalid')
    if any(item.group(1) for item in boundaries[:-1]):
        raise ValueError('Unexpected multipart closing boundary')
    if len(boundaries) - 1 > max_parts:
        raise ValueError('Multipart forms are limited to %s parts' % max_parts)
    result = {}
    for opening, closing in zip(boundaries, boundaries[1:]):
        raw = body[opening.end():closing.start()]
        if raw.endswith(b'\r\n'):
            raw = raw[:-2]
        elif raw.endswith(b'\n'):
            raw = raw[:-1]
        # headersonly is essential: even a malicious nested MIME body creates
        # just one Message here, and is then rejected without recursion.
        part = parser.parsebytes(raw, headersonly=True)
        if part.defects or part.get_content_maintype() == 'multipart' or part.get_content_disposition() != 'form-data':
            raise ValueError('Nested or malformed multipart data is not accepted')
        name = part.get_param('name', header='content-disposition')
        if not isinstance(name, str) or not name or len(name) > 80:
            raise ValueError('Invalid multipart field name')
        payload = part.get_payload(decode=True) or b''
        if part.defects:
            raise ValueError('Malformed multipart encoding')
        if len(payload) > max_file:
            raise FileTooLarge('Each uploaded or pasted file is limited to 200 KB')
        result.setdefault(name, []).append(payload.decode('utf-8', 'strict'))
    return result
