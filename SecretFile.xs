#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <windows.h>
#include <sddl.h>
#include <shlobj.h>
#include <Lmcons.h>

void
set_errno(pTHX) {
    DWORD err = GetLastError();
    switch (err) {
    case ERROR_NO_MORE_FILES:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_BAD_NET_NAME:
    case ERROR_BAD_NETPATH:
    case ERROR_BAD_PATHNAME:
    case ERROR_FILE_NOT_FOUND:
    case ERROR_FILENAME_EXCED_RANGE:
    case ERROR_INVALID_DRIVE:
       errno = ENOENT;
        break;
    case ERROR_NOT_ENOUGH_MEMORY:
        errno = ENOMEM;
        break;
    case ERROR_LOCK_VIOLATION:
        errno = WSAEWOULDBLOCK;
        break;
    case ERROR_ALREADY_EXISTS:
        errno = EEXIST;
        break;
    case ERROR_ACCESS_DENIED:
        errno = EACCES;
        break;
    case ERROR_NOT_SAME_DEVICE:
      errno = EXDEV;
      break;
   default:
        errno = EINVAL;
        break;
    }
}

wchar_t empty_wstr[] = { 0, };

wchar_t *
SvPVwchar_nolen(pTHX_ SV *sv) {
    wchar_t *out;
    STRLEN in_len;
    int out_len;
    char *in = SvPVutf8(sv, in_len);
    if (!in_len) return empty_wstr;
    if (out_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, in, (int)in_len, NULL, 0)) {
        Newx(out, out_len + 2, wchar_t);
        SAVEFREEPV(out);
        if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, in, (int)in_len, out, out_len) == out_len) {
            out[out_len] = 0;
            return out;
        }
    }
    return NULL;
}

SV *
_create_secret_file(pTHX_ SV *name_sv, SV *data_sv, UV flags) {
    static const char ssd_template[] = "O:%sD:P(A;;FA;;;%s)";
    char user_name[UNLEN+1];
    DWORD user_name_size = sizeof(user_name);
    if (GetUserNameA(user_name, &user_name_size)) {
        char sid[2048];
        DWORD sid_size = sizeof(sid);
        char domain_name[2048];
        DWORD domain_name_size = sizeof(domain_name);
        SID_NAME_USE sid_type;
        if (LookupAccountNameA(NULL, user_name, sid, &sid_size,
                               domain_name, &domain_name_size,
                               &sid_type)) {
            char *sid_as_string;
            if (ConvertSidToStringSidA(sid, &sid_as_string)) {
                PSECURITY_DESCRIPTOR sd = NULL;
                DWORD sd_size;
                SV *ssd_as_sv = sv_2mortal(newSVpvf(ssd_template, sid_as_string, sid_as_string));
                LocalFree(sid_as_string);
                if (ConvertStringSecurityDescriptorToSecurityDescriptorA(SvPV_nolen(ssd_as_sv),
                                                                         SDDL_REVISION_1,
                                                                         &sd, &sd_size)) {
                    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), sd, 0 };
                    HANDLE fh = CreateFileW(SvPVwchar_nolen(aTHX_ name_sv),
                                            GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS,
                                            FILE_ATTRIBUTE_TEMPORARY, NULL);
                    if (fh != INVALID_HANDLE_VALUE) {
                        STRLEN len;
                        char *data = SvPVbyte(data_sv, len);
                        while (len > 0) {
                            DWORD written;
                            if (WriteFile(fh, data, len, &written, NULL)) {
                                data += written;
                                len -= written;
                            }
                            else {
                                break;
                            }
                        }
                        if (CloseHandle(fh)) {
                            if (len == 0)
                                return &PL_sv_yes;
                        }
                    }
                }

            }
        }
    }
    set_errno(aTHX);
    return &PL_sv_undef;
}

SV *
newSVwchar(pTHX_ wchar_t *wstr, STRLEN wlen, UINT code_page) {
    int len = WideCharToMultiByte(CP_UTF8,
                                  0,
                                  wstr, (wlen ? wlen : -1),
                                  NULL, 0,
                                  NULL, NULL);
    if (len) {
        SV *sv = sv_2mortal(newSV(len));
        SvPOK_on(sv);
        if (code_page == CP_UTF8) SvUTF8_on(sv);
        SvCUR_set(sv, len - 1);
        if (WideCharToMultiByte(code_page,
                                0,
                                wstr, (wlen ? wlen : -1),
                                SvPVX(sv), len + 1,
                                NULL, NULL) == len) {
            return SvREFCNT_inc(sv);
        }
        Perl_warn(aTHX_ "WideCharToMultiByte failed 2");
    }
    Perl_warn(aTHX_ "WideCharToMultiByte failed");
    return &PL_sv_undef;
}

SV *
_local_appdata_path(pTHX) {
    wchar_t buffer[MAX_PATH + 1];
    if(SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA,
                                  NULL, SHGFP_TYPE_CURRENT, buffer))) {
        STRLEN wlen = wcslen(buffer);
        SV *sv = newSVwchar(aTHX_ buffer, 0, CP_UTF8);
        STRLEN len;
        char *pv = SvPV(sv, len);
        Perl_warn(aTHX_ "LOCAL_APPDATA: |%s| [%d -> %d]", pv, wlen, len);
        return sv;
    }
    Perl_warn(aTHX_ "local_appdata_path failed");
    return &PL_sv_undef;
}

SV *
_short_path(pTHX_ SV *path) {
    wchar_t *wpath = SvPVwchar_nolen(aTHX_ path);
    int len = GetShortPathNameW(wpath, NULL, 0);
    if (len) {
        wchar_t *buffer;
        Newx(buffer, len + 1, wchar_t);
        SAVEFREEPV(buffer);
        int len2 = GetShortPathNameW(wpath, buffer, len);
        if (len2 + 1 == len ) {
            Perl_warn(aTHX_ "short path len: %d", len);
            return newSVwchar(aTHX_ buffer, len, CP_ACP);
        }
        else {
            Perl_warn(aTHX_ "GetShortPathNameW lies %d => %d", len, len2);
        }
    }
    else 
        Perl_warn(aTHX_ "GetShortPathNameW failed %d", GetLastError());

    set_errno(aTHX);
    return &PL_sv_undef;
}


MODULE = Win32::SecretFile		PACKAGE = Win32::SecretFile		

SV *
_create_secret_file(file, data, flags)
    SV *file
    SV *data
    UV flags
CODE:
    RETVAL = _create_secret_file(aTHX_ file, data, flags);
OUTPUT:
    RETVAL

SV *
_local_appdata_path()
CODE:
    RETVAL = _local_appdata_path(aTHX);
OUTPUT:
    RETVAL

SV *
_create_directory(path) 
    SV *path
INIT:
    wchar_t *wdir;
CODE:
    if ((wdir = SvPVwchar_nolen(aTHX_ path)) &&
        CreateDirectoryW(wdir, NULL))
        RETVAL = &PL_sv_yes;
    else {
        set_errno(aTHX);
        RETVAL = &PL_sv_undef;
    }
OUTPUT:
    RETVAL

SV *
_short_path(SV *path)
CODE:
    RETVAL = _short_path(aTHX_ path);
OUTPUT:
    RETVAL
