import base64
import os
import hashlib
import msgpack
import tempfile
import unittest

import vivisect
import vivisect.storage.basicfile as vsbf
import vivisect.storage.mpfile as vsmp
import vivisect.parsers as v_parsers
from vivisect.const import *


def add_events(vw):
    # Call some APIs to populate the event list.
    # Coherency is not the objective. Just get some events in there.
    filehash = hashlib.md5(b'testfile').hexdigest()
    vw.addFile('testfile', 0x1000, filehash)
    vw.setMeta('Architecture', 'i386')
    vw.setMeta('Format', 'pe')
    vw.addMemoryMap(0x1000, 7, 'testfile', b'\x00' * 0x9000)
    vw.addLocation(0x2000, 4, 4, tinfo='fakeptr')
    vw.addLocation(0x3000, 16, 6, tinfo='oogieboogie')
    vw.addLocation(0x4000, 3, 5)
    vw.addLocation(0x5000, 3, 5)
    vw.addLocation(0x6000, 3, 5)
    vw.delLocation(0x4000)
    vw.addXref(0x4000, 0x3000, 1)
    vw.addXref(0x5000, 0x3000, 1)
    vw.delXref((0x5000, 0x3000, 1, 0))
    vw.setMeta('foo', 'bar')
    vw.setFileMeta('testfile', 'neato', 'burrito')
    vw.addVaSet('EmptySet', (('va', VASET_ADDRESS),))
    vw.delVaSet('FuncWrappers')
    vw.setComment(0x2000, 'test comment')
    vw.addExport(0x7000, EXP_FUNCTION, 'kernel32.YoThisExportFake', 'testfile')


class StorageTests(unittest.TestCase):

    def setUp(self):
        '''
        So on windows, you can't double open a temporary file (results in a fun "Permission Denied"
        exception). So instead, we setup a temporary file here and delete it in tearDown so that
        we don't maintain an open file descriptor to the temporary file
        '''
        self.tmpf = tempfile.NamedTemporaryFile(delete=False)

    def tearDown(self):
        self.tmpf.close()
        os.unlink(self.tmpf.name)

    def test_msgpack_idempotent(self):
        # test that what we put in, we can get out
        vw = vivisect.VivWorkspace()
        vw.setMeta('StorageName', self.tmpf.name)
        vw.setMeta('StorageModule', 'vivisect.storage.mpfile')
        add_events(vw)
        vw.saveWorkspace()
        self.tmpf.flush()

        ovw = vivisect.VivWorkspace()
        ovw.setMeta('StorageModule', 'vivisect.storage.mpfile')
        # So this is a bit naughty, but just the act of creating a workspace
        # induces some events in to the workspace. Nothing crazy, just some va sets
        # so delete those so we can have a clean comparison
        ovw._event_list = []
        ovw.loadWorkspace(self.tmpf.name)

        old = list(vw.exportWorkspace())
        new = list(ovw.exportWorkspace())
        self.assertEqual(len(old), 40)
        self.assertEqual(len(new), 41)  # the last event is a setMeta made by loadWorkspace
        self.assertEqual(new[-1], (VWE_SETMETA, ('StorageName', self.tmpf.name)))
        for idx in range(len(old)):
            self.assertEqual(old[idx], new[idx])

    def test_msgpack_to_basicfile(self):
        # make sure we're on par with what the OG storage mechanism can do
        mpfile = tempfile.NamedTemporaryFile(delete=False)
        basicfile = tempfile.NamedTemporaryFile(delete=False)

        try:
            ogvw = vivisect.VivWorkspace()
            add_events(ogvw)
            ogvw.setMeta('StorageName', mpfile.name)
            ogvw.setMeta('StorageModule', 'vivisect.storage.mpfile')
            ogvw.saveWorkspace()
            # Get rid of those last two meta sets so that the two new workspaces should be
            # the same save for the last meta set
            ogvw._event_list.pop()
            ogvw._event_list.pop()
            ogvw.setMeta('StorageName', basicfile.name)
            ogvw.setMeta('StorageModule', 'vivisect.storage.basicfile')
            ogvw.saveWorkspace()
            ogevt = list(ogvw.exportWorkspace())

            mvw = vivisect.VivWorkspace()
            mvw.setMeta('StorageModule', 'vivisect.storage.mpfile')
            mvw._event_list = []
            mvw.loadWorkspace(mpfile.name)
            mevt = list(mvw.exportWorkspace())
            self.assertEqual(len(mevt), 41)

            bvw = vivisect.VivWorkspace()
            bvw.setMeta('StorageModule', 'vivisect.storage.basicfile')
            bvw._event_list = []
            bvw.loadWorkspace(basicfile.name)
            bevt = list(bvw.exportWorkspace())
            self.assertEqual(len(bevt), 41)

            # the last three events are specific to the different storage modules
            for idx in range(len(mevt) - 3):
                self.assertEqual(mevt[idx], bevt[idx])
                self.assertEqual(ogevt[idx], bevt[idx])
        finally:
            mpfile.close()
            basicfile.close()
            os.unlink(mpfile.name)
            os.unlink(basicfile.name)

    def test_bad_event(self):
        vw = vivisect.VivWorkspace()
        with self.assertLogs() as logcap:
            vw.importWorkspace([(VWE_MAX + 1, (0xabad1dea, 4, 3, 'nope')),
                                (VWE_ADDFILE, ('VivisectFile', 0x1000, '3bfdad02b9a6522c84e356cf8f69135b'))])
        files = vw.getFiles()
        self.assertIn("IndexError: list index out of range", ''.join(logcap.output))
        self.assertEqual(1, len(files))
        self.assertEqual('VivisectFile', files[0])

    def test_basicfile_header(self):
        basicfile = tempfile.NamedTemporaryFile(delete=False)
        vw = vivisect.VivWorkspace()
        add_events(vw)
        vw.setMeta('StorageName', basicfile.name)
        vw.saveWorkspace(False)

        # test the header was added correctly
        with open(basicfile.name, 'rb') as f:
            header = f.read(8)
            self.assertEqual(header, vsbf.vivsig_cpickle)

        # now add events and make sure we don't add the header unnecessarily
        vw = vivisect.VivWorkspace()
        vw.loadWorkspace(basicfile.name)
        vw.addLocation(0x6100, 3, 5)
        vw.addLocation(0x6105, 3, 5)
        vw.addLocation(0x610a, 3, 5)
        vw.saveWorkspace(False)

        # now load it.  if a VIV\0\0\0\0\0 was added incorrectly, this will blow up
        vw = vivisect.VivWorkspace()
        vw.loadWorkspace(basicfile.name)
        self.assertEqual(vw.getLocation(0x6100), (0x6100, 3, 5, None))
        self.assertEqual(vw.getLocation(0x6105), (0x6105, 3, 5, None))
        self.assertEqual(vw.getLocation(0x610a), (0x610a, 3, 5, None))

    def _getWorkspace(self, filename, module='vivisect.storage.mpfile'):
        vw = vivisect.VivWorkspace()
        vw.setMeta('Architecture', 'i386')
        vw.setMeta('Format', 'pe')
        vw.setMeta('StorageName', filename)
        vw.setMeta('StorageModule', module)
        return vw

    def _reload(self, filename, module='vivisect.storage.mpfile'):
        vw = vivisect.VivWorkspace()
        vw.setMeta('StorageModule', module)
        vw.loadWorkspace(filename)
        return vw

    def test_mpfile_first_save_has_header(self):
        mpfile = tempfile.NamedTemporaryFile(delete=False)
        try:
            vw = self._getWorkspace(mpfile.name)
            add_events(vw)
            # An incremental save against a brand new file must still write
            # the signature, otherwise the file is guessed to be a blob.
            vw.saveWorkspace(False)

            with open(mpfile.name, 'rb') as f:
                self.assertEqual(next(msgpack.Unpacker(f, raw=False)), 'MSGVIV\x00\x00')

            self.assertEqual(v_parsers.guessFormatFilename(mpfile.name), 'mpviv')

            # and the events must survive the round trip
            ovw = self._reload(mpfile.name)
            self.assertEqual(ovw.getLocation(0x3000), (0x3000, 16, 6, 'oogieboogie'))
            self.assertEqual(ovw.getMeta('foo'), 'bar')
        finally:
            mpfile.close()
            os.unlink(mpfile.name)

    def test_mpfile_full_and_incremental_equivalent(self):
        fulld = tempfile.mkdtemp()
        incd = tempfile.mkdtemp()
        fullname = os.path.join(fulld, 'full.mviv')
        incname = os.path.join(incd, 'inc.mviv')
        try:
            # the same events arrived at two ways: a single full save, and an
            # initial incremental save followed by appended changes
            fvw = self._getWorkspace(fullname)
            add_events(fvw)
            fvw.saveWorkspace(True)

            ivw = self._getWorkspace(incname)
            ivw.saveWorkspace(False)
            add_events(ivw)
            ivw.saveWorkspace(False)

            fnew = self._reload(fullname)
            inew = self._reload(incname)
            # StorageName/StorageModule necessarily differ between the two
            # files; everything else must be identical.
            ignore = ('StorageName', 'StorageModule')
            fevts = [e for e in fnew.exportWorkspace() if not (e[0] == VWE_SETMETA and e[1][0] in ignore)]
            inevts = [e for e in inew.exportWorkspace() if not (e[0] == VWE_SETMETA and e[1][0] in ignore)]
            self.assertEqual(fevts, inevts)
        finally:
            for name in (fullname, incname):
                if os.path.exists(name):
                    os.unlink(name)
            os.rmdir(fulld)
            os.rmdir(incd)

    def test_mpfile_align_roundtrip(self):
        mpfile = tempfile.NamedTemporaryFile(delete=False)
        try:
            vw = self._getWorkspace(mpfile.name)
            # the map is 0x1234 real bytes but aligned out to 0x2000
            vw.addMemoryMap(0x1000, 7, 'testfile', b'\x11' * 0x1234, align=0x2000)
            vw.saveWorkspace(True)

            # append a map which also requires alignment
            vw.addMemoryMap(0x4000, 7, 'testfile', b'\x22' * 0x1234, align=0x2000)
            vw.saveWorkspace(False)

            ovw = self._reload(mpfile.name)
            self.assertEqual(ovw.getMemoryMaps(), [(0x1000, 0x2000, 7, 'testfile'),
                                                   (0x4000, 0x2000, 7, 'testfile')])
            # this address only exists because align was preserved
            self.assertEqual(ovw.readMemory(0x5ffc, 4), b'\x00\x00\x00\x00')
            self.assertEqual(ovw.readMemory(0x1230, 4), b'\x11\x11\x11\x11')
        finally:
            mpfile.close()
            os.unlink(mpfile.name)

    def test_mpfile_binary_payloads(self):
        mpfile = tempfile.NamedTemporaryFile(delete=False)
        try:
            vw = self._getWorkspace(mpfile.name)
            payload = bytes(range(256))
            vw.addMemoryMap(0x1000, 7, 'testfile', b'\x00' * 0x1000)
            vw.writeMemory(0x1004, payload)
            vw.setMeta('BinaryMeta', payload)
            vw.setMeta('FileBytes', v_parsers.compressBytes(payload * 4))
            vw.saveWorkspace(True)

            ovw = self._reload(mpfile.name)
            self.assertEqual(ovw.readMemory(0x1004, len(payload)), payload)
            self.assertEqual(ovw.getMeta('BinaryMeta'), payload)
            self.assertEqual(ovw.getMeta('FileBytes'), v_parsers.compressBytes(payload * 4))
        finally:
            mpfile.close()
            os.unlink(mpfile.name)

    def test_mpfile_legacy_quad(self):
        # a file written by an older vivisect: no align in the ADDMMAP event
        # payload, and binary strings packed without the bin type
        mpfile = tempfile.NamedTemporaryFile(delete=False)
        try:
            events = [
                (VWE_SETMETA, ('Architecture', 'i386')),
                (VWE_SETMETA, ('Format', 'pe')),
                (VWE_ADDFILE, ('testfile', 0x1000, hashlib.md5(b'testfile').hexdigest())),
                (VWE_ADDMMAP, (0x1000, 7, 'testfile', base64.b64encode(b'\xee' * 0x1234))),
                (VWE_SETMETA, ('StorageName', mpfile.name)),
            ]
            with open(mpfile.name, 'wb') as f:
                msgpack.pack(vsmp.VSIG, f, use_bin_type=False)
                for event in events:
                    msgpack.pack(event, f, use_bin_type=False)

            ovw = self._reload(mpfile.name)
            self.assertEqual(ovw.getMemoryMaps(), [(0x1000, 0x1234, 7, 'testfile')])
            self.assertEqual(ovw.readMemory(0x1230, 4), b'\xee\xee\xee\xee')
        finally:
            mpfile.close()
            os.unlink(mpfile.name)

    def test_mpfile_headerless_incremental(self):
        # files written by the old incremental-save bug lack a signature;
        # they are still workspaces so they must still load
        mpfile = tempfile.NamedTemporaryFile(delete=False)
        try:
            vw = self._getWorkspace(mpfile.name)
            add_events(vw)
            events = vw.exportWorkspace()
            with open(mpfile.name, 'wb') as f:
                for event in events:
                    if event[0] == VWE_ADDMMAP:
                        event = (event[0], (event[1][0], event[1][1], event[1][2],
                                            base64.b64encode(event[1][3]), event[1][4]))
                    msgpack.pack(event, f, use_bin_type=True)

            ovw = self._reload(mpfile.name)
            self.assertEqual(ovw.getMeta('foo'), 'bar')
            self.assertEqual(ovw.getLocation(0x3000), (0x3000, 16, 6, 'oogieboogie'))
        finally:
            mpfile.close()
            os.unlink(mpfile.name)
