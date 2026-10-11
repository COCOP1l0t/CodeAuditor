from __future__ import annotations

import os
import stat
from pathlib import Path

import ntsecuritycon
import pywintypes
import win32api
import win32con
import win32file
import win32security

_READ_CONTROL = 0x00020000
_WRITE_DAC = 0x00040000
_FILE_READ_ATTRIBUTES = 0x0080
_SECURITY_INFORMATION = (
    win32security.OWNER_SECURITY_INFORMATION
    | win32security.DACL_SECURITY_INFORMATION
    | win32security.PROTECTED_DACL_SECURITY_INFORMATION
)


def _open_no_follow(path: Path, access: int = _FILE_READ_ATTRIBUTES):
    return win32file.CreateFile(
        str(path),
        access,
        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
        None,
        win32con.OPEN_EXISTING,
        win32file.FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )


def _file_information(path: Path):
    handle = _open_no_follow(path)
    try:
        attributes = win32file.GetFileAttributes(str(path))
        if attributes & win32con.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError(f"path must not be a reparse point: {path}")
        info = win32file.GetFileInformationByHandle(handle)
        final_path = win32file.GetFinalPathNameByHandle(handle, 0)
        return info, final_path
    finally:
        handle.Close()


def inspect_regular_file(path: Path, *, single_link: bool = True) -> os.stat_result:
    info, _final_path = _file_information(path)
    stat_result = path.lstat()
    if not stat.S_ISREG(stat_result.st_mode):
        raise ValueError(f"path is not a regular disk file: {path}")
    # BY_HANDLE_FILE_INFORMATION.NumberOfLinks is tuple index 7 in pywin32.
    if single_link and int(info[7]) != 1:
        raise ValueError(f"file must not be hard-linked: {path}")
    return stat_result


def _private_dacl():
    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(), win32security.TOKEN_QUERY
    )
    user_sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    system_sid = win32security.CreateWellKnownSid(
        win32security.WinLocalSystemSid, None
    )
    acl = win32security.ACL()
    acl.AddAccessAllowedAce(
        win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, user_sid
    )
    acl.AddAccessAllowedAce(
        win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, system_sid
    )
    return user_sid, system_sid, acl


def harden_private_file(path: str | os.PathLike[str]) -> None:
    path = Path(path)
    inspect_regular_file(path)
    user_sid, _system_sid, dacl = _private_dacl()
    win32security.SetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        _SECURITY_INFORMATION,
        user_sid,
        None,
        dacl,
        None,
    )


def private_file_is_secure(path: str | os.PathLike[str]) -> bool:
    path = Path(path)
    try:
        inspect_regular_file(path)
        user_sid, system_sid, _acl = _private_dacl()
        descriptor = win32security.GetNamedSecurityInfo(
            str(path),
            win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION
            | win32security.DACL_SECURITY_INFORMATION,
        )
        owner = descriptor.GetSecurityDescriptorOwner()
        dacl = descriptor.GetSecurityDescriptorDacl()
        if owner != user_sid or dacl is None:
            return False
        allowed = {str(user_sid), str(system_sid)}
        for index in range(dacl.GetAceCount()):
            ace = dacl.GetAce(index)
            ace_type = ace[0][0]
            mask = ace[1]
            sid = ace[2]
            if ace_type == win32security.ACCESS_ALLOWED_ACE_TYPE:
                if str(sid) not in allowed and mask & (
                    ntsecuritycon.FILE_GENERIC_READ
                    | ntsecuritycon.FILE_GENERIC_WRITE
                    | ntsecuritycon.FILE_ALL_ACCESS
                ):
                    return False
        return True
    except (OSError, ValueError, pywintypes.error):
        return False
