#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <windows.h>
#include <sddl.h>
#include <Lmcons.h>

const char ssd_template[] = "O:%sD:P(A;;FA;;;%s)";

SV *
create_password_file(pTHX_ SV *name, SV *data) {

    char user_name[UNLEN+1];
    DWORD user_name_size = sizeof(user_name);
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, 0 };

    SV *rc = &PL_sv_undef;
    if (GetUserName(user_name, &user_name_size)) {
        char sid[2048];
        DWORD sid_size = sizeof(sid);
        char domain_name[2048];
        DWORD domain_name_size = sizeof(domain_name);
        SID_NAME_USE sid_type;
        if (LookupAccountName(NULL, user_name, sid, &sid_size,
                              domain_name, &domain_name_size,
                              &sid_type)) {
            char *sid_as_string;
            if (ConvertSidToStringSid(sid, &sid_as_string)) {
                SV *ssd_as_sv = sv_2mortal(newSVpvf(ssd_template, sid_as_string, sid_as_string));
                SECURITY_DESCRIPTOR *sd = NULL;
                DWORD sd_size;
                printf( "SID (as string): '%s'\n", sid_as_string);
                if (ConvertStringSecurityDescriptorToSecurityDescriptor(SvPV_nolen(ssd_as_sv),
                                                                        SDDL_REVISION_1,
                                                                        &sd, &sd_size)) {
                    HANDLE fh;
                    sa.lpSecurityDescriptor = sd;
                    fh = CreateFile(SvPV_nolen(name),
                                    GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_TEMPORARY, NULL);
                    if (fh != INVALID_HANDLE_VALUE) {
                        STRLEN len;
                        DWORD written;
                        char *data_as_string = SvPV(data, len);
                        WriteFile(fh, data_as_string, len, &written, NULL);
                        if (CloseHandle(fh))
                            rc = &PL_sv_yes;
                    }
                }
                LocalFree(sid_as_string);
            }
        }
    }
    return rc;
}

MODULE = Win32::SecretFile		PACKAGE = Win32::SecretFile		

SV *
create_password_file(file, data)
    SV *file
    SV *data
CODE:
    RETVAL = create_password_file(aTHX_ file, data);
OUTPUT:
    RETVAL
