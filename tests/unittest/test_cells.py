# Copyright 2019 James Brown
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Tests for TOR cell types, including Link Protocol 5 support."""

import struct
import pytest

from torpy.cells import (
    TorCommands,
    CellCreated,
    CellPaddingNegotiate,
    CellVPadding,
    CellAuthenticate,
    CellAuthorize,
    CellUnknown,
    CellVersions,
    CellPadding,
    CellCreate,
    CellRelay,
    CellDestroy,
    CellNetInfo,
)


class TestCellCreated:
    """Tests for CellCreated (NUM=2)."""

    def test_cell_number(self):
        """CellCreated should have NUM=2."""
        assert CellCreated.NUM == 2

    def test_serialization(self):
        """Test CellCreated serialization."""
        handshake_data = b'\x00' * 148  # DH_DATA (128) + KH (20)
        cell = CellCreated(handshake_data=handshake_data, circuit_id=0x1234)
        payload = cell._serialize_payload()
        assert payload == handshake_data

    def test_deserialization(self):
        """Test CellCreated deserialization."""
        handshake_data = b'\x01' * 148
        kwargs = CellCreated._deserialize_payload(handshake_data, proto_version=4)
        assert kwargs['handshake_data'] == handshake_data

    def test_is_fixed_length(self):
        """CellCreated should be fixed-length."""
        assert not CellCreated.is_var_len()


class TestCellPaddingNegotiate:
    """Tests for CellPaddingNegotiate (NUM=12) - Link Protocol 5."""

    def test_cell_number(self):
        """CellPaddingNegotiate should have NUM=12."""
        assert CellPaddingNegotiate.NUM == 12

    def test_padding_commands(self):
        """Test padding command constants."""
        assert CellPaddingNegotiate.PADDING_STOP == 0
        assert CellPaddingNegotiate.PADDING_START == 1

    def test_serialization_stop(self):
        """Test serialization with STOP command."""
        cell = CellPaddingNegotiate(
            version=0,
            command=CellPaddingNegotiate.PADDING_STOP,
            ito_low_ms=0,
            ito_high_ms=0
        )
        payload = cell._serialize_payload()
        expected = struct.pack('!BBHH', 0, 0, 0, 0)
        assert payload == expected

    def test_serialization_start(self):
        """Test serialization with START command and timeouts."""
        cell = CellPaddingNegotiate(
            version=0,
            command=CellPaddingNegotiate.PADDING_START,
            ito_low_ms=1500,
            ito_high_ms=9500
        )
        payload = cell._serialize_payload()
        expected = struct.pack('!BBHH', 0, 1, 1500, 9500)
        assert payload == expected

    def test_deserialization(self):
        """Test CellPaddingNegotiate deserialization."""
        payload = struct.pack('!BBHH', 0, 1, 1000, 5000) + b'\x00' * 100
        kwargs = CellPaddingNegotiate._deserialize_payload(payload, proto_version=5)
        assert kwargs['version'] == 0
        assert kwargs['command'] == 1
        assert kwargs['ito_low_ms'] == 1000
        assert kwargs['ito_high_ms'] == 5000

    def test_is_fixed_length(self):
        """CellPaddingNegotiate should be fixed-length."""
        assert not CellPaddingNegotiate.is_var_len()


class TestCellVPadding:
    """Tests for CellVPadding (NUM=128) - Variable-length padding."""

    def test_cell_number(self):
        """CellVPadding should have NUM=128."""
        assert CellVPadding.NUM == 128

    def test_serialization(self):
        """Test CellVPadding serialization."""
        padding_data = b'\xff' * 256
        cell = CellVPadding(padding_data=padding_data)
        payload = cell._serialize_payload()
        assert payload == padding_data

    def test_deserialization(self):
        """Test CellVPadding deserialization."""
        padding_data = b'\xaa' * 100
        kwargs = CellVPadding._deserialize_payload(padding_data, proto_version=5)
        assert kwargs['padding_data'] == padding_data

    def test_is_variable_length(self):
        """CellVPadding should be variable-length (NUM >= 128)."""
        assert CellVPadding.is_var_len()


class TestCellAuthenticate:
    """Tests for CellAuthenticate (NUM=131)."""

    def test_cell_number(self):
        """CellAuthenticate should have NUM=131."""
        assert CellAuthenticate.NUM == 131

    def test_serialization(self):
        """Test CellAuthenticate serialization."""
        auth_data = b'\x12\x34\x56\x78'
        cell = CellAuthenticate(auth_type=1, auth_data=auth_data)
        payload = cell._serialize_payload()
        expected = struct.pack('!HH', 1, 4) + auth_data
        assert payload == expected

    def test_deserialization(self):
        """Test CellAuthenticate deserialization."""
        auth_data = b'\xab\xcd\xef'
        payload = struct.pack('!HH', 2, 3) + auth_data + b'\x00' * 50
        kwargs = CellAuthenticate._deserialize_payload(payload, proto_version=5)
        assert kwargs['auth_type'] == 2
        assert kwargs['auth_data'] == auth_data

    def test_is_variable_length(self):
        """CellAuthenticate should be variable-length (NUM >= 128)."""
        assert CellAuthenticate.is_var_len()


class TestCellAuthorize:
    """Tests for CellAuthorize (NUM=132)."""

    def test_cell_number(self):
        """CellAuthorize should have NUM=132."""
        assert CellAuthorize.NUM == 132

    def test_is_variable_length(self):
        """CellAuthorize should be variable-length (NUM >= 128)."""
        assert CellAuthorize.is_var_len()


class TestTorCommands:
    """Tests for TorCommands cell type registry."""

    def test_get_known_cell_types(self):
        """Test retrieving known cell types."""
        assert TorCommands.get_by_num(0) == CellPadding
        assert TorCommands.get_by_num(1) == CellCreate
        assert TorCommands.get_by_num(2) == CellCreated
        assert TorCommands.get_by_num(3) == CellRelay
        assert TorCommands.get_by_num(4) == CellDestroy
        assert TorCommands.get_by_num(7) == CellVersions
        assert TorCommands.get_by_num(8) == CellNetInfo

    def test_get_protocol_v5_cell_types(self):
        """Test retrieving Link Protocol 5 cell types."""
        assert TorCommands.get_by_num(12) == CellPaddingNegotiate
        assert TorCommands.get_by_num(128) == CellVPadding
        assert TorCommands.get_by_num(131) == CellAuthenticate
        assert TorCommands.get_by_num(132) == CellAuthorize

    def test_unknown_cell_type_handler(self):
        """Test that unknown cell types return a dynamic handler class."""
        # Cell type 84 is not defined in the protocol
        unknown_class = TorCommands.get_by_num(84)
        assert unknown_class.NUM == 84
        assert issubclass(unknown_class, CellUnknown)

    def test_unknown_cell_type_different_numbers(self):
        """Test that different unknown cell types get different classes."""
        class1 = TorCommands.get_by_num(84)
        class2 = TorCommands.get_by_num(85)
        assert class1.NUM == 84
        assert class2.NUM == 85
        # They should be different classes
        assert class1 is not class2


class TestCellUnknown:
    """Tests for CellUnknown generic handler."""

    def test_serialization(self):
        """Test CellUnknown serialization."""
        payload = b'\x12\x34\x56\x78'
        cell = CellUnknown(cell_num=99, payload=payload)
        serialized = cell._serialize_payload()
        assert serialized == payload

    def test_deserialization(self):
        """Test CellUnknown deserialization."""
        payload = b'\xaa\xbb\xcc'
        kwargs = CellUnknown._deserialize_payload(payload, proto_version=5)
        assert kwargs['payload'] == payload


class TestProtocolVersionSupport:
    """Tests for protocol version support in cell_socket."""

    def test_supported_versions_include_v5(self):
        """Test that SUPPORTED_VERSION includes version 5."""
        from torpy.cell_socket import TorProtocol
        assert 5 in TorProtocol.SUPPORTED_VERSION
        assert 3 in TorProtocol.SUPPORTED_VERSION
        assert 4 in TorProtocol.SUPPORTED_VERSION
