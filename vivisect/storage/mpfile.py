import base64
import logging

import msgpack

import vivisect
from vivisect.const import VWE_ADDMMAP, VWE_MAX

logger = logging.getLogger(__name__)

loadargs = {'use_list': False, 'raw': False, 'max_buffer_size': 2**32 -1}
if msgpack.version < (1, 0, 0):
    loadargs['encoding'] = 'utf-8'
else:
    loadargs['strict_map_key'] = False

# Binary payloads (memory map bytes, writeMemory's old bytes, FileBytes, any
# user supplied meta value, ...) must be stored as msgpack "bin" objects so
# that they come back as bytes.  With use_bin_type=False they are encoded as
# strings and any non-utf8 payload fails to decode on the way back in.
packargs = {'use_bin_type': True}

VSIG = b'MSGVIV'.ljust(8, b'\x00')


def _encode_event(event):
    '''
    Convert an in-memory event into its on-disk form.

    A VWE_ADDMMAP payload is (va, perms, fname, bytes[, align]).  Only the
    memory bytes are encoded, and every other field (notably align) must be
    preserved: dropping align changes the size the map gets on reload, which
    makes the map unreadable past its real size.
    '''
    if event[0] != VWE_ADDMMAP:
        return event

    einfo = list(event[1])
    if len(einfo) > 3:
        einfo[3] = base64.b64encode(einfo[3])
    return (event[0], tuple(einfo))


def _decode_event(event):
    if event[0] != VWE_ADDMMAP:
        return event

    einfo = list(event[1])
    if len(einfo) > 3:
        mape = einfo[3]
        if isinstance(mape, str):
            mape = mape.encode('ascii')
        einfo[3] = base64.b64decode(mape)

    # A 4-tuple payload is the DEPRECATED (pre-align) event format.  Hand it
    # through untouched; the workspace event handler understands both.
    return (event[0], tuple(einfo))


def _pack_event(f, event):
    msgpack.pack(_encode_event(event), f, **packargs)


def _pack_header(f):
    # The signature is packed as a raw string (not a bin object) so that
    # older mpfile readers, which expect a str, can still read new files.
    msgpack.pack(VSIG, f, use_bin_type=False)


def vivEventsAppendFile(filename, events):
    with open(filename, 'ab') as f:
        # Incremental saves append to an existing workspace.  If this is the
        # first save of the workspace the file starts out empty, so the
        # signature has to be written first or the file is not recognized as
        # a workspace on reload.
        if f.tell() == 0:
            _pack_header(f)

        for event in events:
            _pack_event(f, event)


def saveWorkspaceChanges(vw, filename):
    events = vw.exportWorkspaceChanges()
    vivEventsAppendFile(filename, events)


def vivEventsToFile(filename, events):
    with open(filename, 'wb') as f:
        _pack_header(f)
        for event in events:
            _pack_event(f, event)


def saveWorkspace(vw, filename):
    events = vw.exportWorkspace()
    vivEventsToFile(filename, events)


def _check_signature(siggy):
    if isinstance(siggy, bytes):
        return siggy == VSIG
    if isinstance(siggy, str):
        return siggy.encode('utf-8') == VSIG
    return False


def _looks_like_event(obj):
    # Header-less files (written by an older incremental-save bug) simply
    # start with the first event.
    return isinstance(obj, (tuple, list)) and len(obj) == 2 and \
        isinstance(obj[0], int) and 0 < obj[0] < VWE_MAX


def vivEventsFromFile(filename):
    events = []

    with open(filename, 'rb') as f:
        unpacker = msgpack.Unpacker(f, **loadargs)

        try:
            first = next(unpacker)
        except StopIteration:
            raise vivisect.InvalidWorkspace(filename, "invalid workspace file")
        except Exception as e:
            raise vivisect.InvalidWorkspace(filename, "invalid workspace file") from e

        if _check_signature(first):
            headerless = False
        elif _looks_like_event(first):
            # DEPRECATED: older incremental saves could omit the signature.
            # Treat the entire file as a stream of events.
            logger.warning('%s is missing its signature, attempting to load it anyway', filename)
            headerless = True
            events.append(_decode_event(first))
        else:
            logger.warning('Invalid file signature of %s', str(first))
            raise vivisect.InvalidWorkspace(filename, "invalid workspace file")

        try:
            for event in unpacker:
                events.append(_decode_event(event))
        except Exception as e:
            raise vivisect.InvalidWorkspace(filename, "invalid workspace file") from e

    if headerless:
        logger.debug('Loaded %d events from header-less workspace %s', len(events), filename)

    return events


def loadWorkspace(vw, filename):
    events = vivEventsFromFile(filename)
    vw.importWorkspace(events)
