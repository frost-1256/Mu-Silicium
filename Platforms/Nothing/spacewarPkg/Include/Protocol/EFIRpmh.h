/** @file
  EFI RPMH protocol — reverse engineered from the spacewar binary stack
  (RpmhDxe.efi producer, PmicDxeLa.efi consumer), 2026-10-27.

  Evidence:
  - RpmhDxe installs this GUID via InstallMultipleProtocolInterfaces
    together with the interface struct in its .data (VA 0xE0D8).
  - PmicDxeLa locates it in four "pm_rpmh" wrappers; each failure path
    prints "Rpmh protocol is not initialized:%r".
  - Struct layout read from RpmhDxe .data: Revision 0x00010001 at +0x00,
    then 24 function pointers at +0x08..+0xC0.

  Only the methods PmicDxeLa was observed to call are typed here; the
  rest stay opaque slots so offsets never shift. Argument semantics are
  as observed at the PmicDxeLa call sites; see UEFI_TOUCH_POWER_PLAN.md
  (winboot/) for the full analysis. Do not "fix" these signatures from
  memory of other QC trees — they are pinned to this binary.
**/
#ifndef _EFI_RPMH_H_
#define _EFI_RPMH_H_

#define EFI_RPMH_PROTOCOL_GUID \
  { 0xE1D0B573, 0xF29F, 0x495D, { 0x93, 0x52, 0xCA, 0x0D, 0xD4, 0x2A, 0x0A, 0x74 } }

extern EFI_GUID gEfiRpmhProtocolGuid;

typedef struct _EFI_RPMH_PROTOCOL EFI_RPMH_PROTOCOL;

///
/// One request-set context, as built by PmicDxeLa's builder
/// (pm_rpmh.c @0x16300). Header is 12 bytes; entries are 12 bytes:
/// { Address, Data, Flag, pad[3] }. The builder computes
/// Address = DescBase + DescOffset from a resource descriptor and
/// appends to the "active" set and/or the "sleep" set depending on
/// descriptor flag bytes. Header: +0x00 flag word (observed 0/1/2),
/// +0x04 entry count, +0x08 unused/zero.
/// Entries start at +0x0C.
///
typedef struct {
  UINT32  Flag;
  UINT32  Count;
  UINT32  Reserved;
  struct {
    UINT32  Address;
    UINT32  Data;
    UINT8   Flag;
    UINT8   Pad[3];
  } Entries[1];
} RPMH_REQUEST_SET;

///
/// Method #5 (+0x30). Observed call (PmicDxeLa @0x16288 wrapper):
///   Handle = M5(DrvId, "pmic", &Handle)
/// DrvId is NOT a literal at the call site: PmicDxeLa resolves it from a
/// per-platform config table (lookup key 0x4C, index 0). The runtime
/// value on spacewar is still an open item — see plan doc.
/// The wrapper returns the handle (the OUT slot), discarding status.
///
typedef
EFI_STATUS
(EFIAPI *RPMH_CREATE_HANDLE)(
  IN  UINT32   DrvId,
  IN  CHAR8   *ClientName,
  OUT VOID   **Handle
  );

///
/// Method #14 (+0x78). Observed call (PmicDxeLa @0x16390, the
/// pm_rpmh issue path): for each non-empty set,
///   M14(Handle, Set, &ResultCode)
/// The wrapper returns ResultCode (an INT32 written by the method);
/// the EFI_STATUS return is ignored by the caller. ResultCode is
/// later handed to methods #22/#23 (churn/wait style calls).
///
typedef
EFI_STATUS
(EFIAPI *RPMH_ISSUE_SET)(
  IN  VOID              *Handle,
  IN  RPMH_REQUEST_SET  *Set,
  OUT INT32             *ResultCode
  );

///
/// Methods #22 (+0xB8) and #23 (+0xC0). Observed as tail calls
/// (PmicDxeLa @0x16428 / @0x16440): M(Handle, ResultCode) when the
/// code is non-zero. Churn/wait-for-completion style; exact split
/// between the two is not yet pinned.
///
typedef
EFI_STATUS
(EFIAPI *RPMH_CHURN)(
  IN  VOID    *Handle,
  IN  UINT32   ResultCode
  );

typedef VOID *RPMH_OPAQUE_METHOD;

struct _EFI_RPMH_PROTOCOL {
  UINT32              Revision;        // +0x00 = 0x00010001
  RPMH_OPAQUE_METHOD  M00;             // +0x08
  RPMH_OPAQUE_METHOD  M01;             // +0x10
  RPMH_OPAQUE_METHOD  M02;             // +0x18
  RPMH_OPAQUE_METHOD  M03;             // +0x20
  RPMH_OPAQUE_METHOD  M04;             // +0x28
  RPMH_CREATE_HANDLE  CreateHandle;    // +0x30  (#5)
  RPMH_OPAQUE_METHOD  M06;             // +0x38  (unobserved; an earlier
                                       //  +0x38 sighting turned out to
                                       //  be a different protocol's)
  RPMH_OPAQUE_METHOD  M07;             // +0x40
  RPMH_OPAQUE_METHOD  M08;             // +0x48
  RPMH_OPAQUE_METHOD  M09;             // +0x50
  RPMH_OPAQUE_METHOD  M10;             // +0x58
  RPMH_OPAQUE_METHOD  M11;             // +0x60
  RPMH_OPAQUE_METHOD  M12;             // +0x68
  RPMH_OPAQUE_METHOD  M13;             // +0x70
  RPMH_ISSUE_SET      IssueSet;        // +0x78  (#14)
  RPMH_OPAQUE_METHOD  M15;             // +0x80
  RPMH_OPAQUE_METHOD  M16;             // +0x88
  RPMH_OPAQUE_METHOD  M17;             // +0x90
  RPMH_OPAQUE_METHOD  M18;             // +0x98
  RPMH_OPAQUE_METHOD  M19;             // +0xA0
  RPMH_OPAQUE_METHOD  M20;             // +0xA8
  RPMH_OPAQUE_METHOD  M21;             // +0xB0
  RPMH_CHURN          Churn22;         // +0xB8  (#22)
  RPMH_CHURN          Churn23;         // +0xC0  (#23)
};

#endif
