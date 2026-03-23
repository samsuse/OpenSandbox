#
# Copyright 2026 Alibaba Group Holding Ltd.
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

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RunInSessionRequest")


@_attrs_define
class RunInSessionRequest:
    """Request to run code in an existing bash session

    Attributes:
        code (str): Shell code to execute in the session Example: echo "Hello".
        cwd (str | Unset): Working directory override for this run (optional) Example: /workspace.
        timeout_ms (int | Unset): Maximum execution time in milliseconds (optional; server may not enforce if omitted)
            Example: 30000.
    """

    code: str
    cwd: str | Unset = UNSET
    timeout_ms: int | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        code = self.code

        cwd = self.cwd

        timeout_ms = self.timeout_ms

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "code": code,
            }
        )
        if cwd is not UNSET:
            field_dict["cwd"] = cwd
        if timeout_ms is not UNSET:
            field_dict["timeout_ms"] = timeout_ms

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        code = d.pop("code")

        cwd = d.pop("cwd", UNSET)

        timeout_ms = d.pop("timeout_ms", UNSET)

        run_in_session_request = cls(
            code=code,
            cwd=cwd,
            timeout_ms=timeout_ms,
        )

        run_in_session_request.additional_properties = d
        return run_in_session_request

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
