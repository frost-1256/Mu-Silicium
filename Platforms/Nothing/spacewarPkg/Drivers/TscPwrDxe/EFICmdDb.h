/** @file
  EFI CmdDb protocol — reverse engineered from the spacewar binary
  stack (PmicDxeLa.efi consumer), 2026-10-27.

  PmicDxeLa locates this GUID in four wrappers (@0x171D4, @0x17250,
  @0x172CC, @0x17348) around its PRM resource init (pm_prm_init.c).
  The wrappers pass the resource descriptor's +0x18 field as the
  lookup argument. Runtime evidence (probe v0.2 crash on device,
  FAR = 0x00000033636F646C = the packed bytes of "ldoc3"): the
  field is a POINTER to the resource name string and the methods
  dereference it — passing the packed-name value instead faults.
  (A CHAR8 name buffer also reads as the packed UINT64 key, so a
  string pointer satisfies either interpretation.)

  Methods take the protocol as first argument (This-style), unlike
  the RPMh protocol. Only observed methods are typed.
**/
#ifndef _EFI_CMDDB_H_
#define _EFI_CMDDB_H_

#define EFI_CMDDB_PROTOCOL_GUID \
  { 0x1C34F691, 0xD33D, 0x4E14, { 0xB8, 0xF8, 0x32, 0xC6, 0xC0, 0x29, 0xE9, 0x5B } }

extern EFI_GUID gEfiCmdDbProtocolGuid;

typedef struct _EFI_CMDDB_PROTOCOL EFI_CMDDB_PROTOCOL;

///
/// Method +0x10. Observed (PRM init @0x14AE4): the returned UINT32
/// is stored as the resource's vote address (resource struct +0x40).
///   Address = M10(This, Key, &Address)  -- wrapper returns Address.
///
typedef
EFI_STATUS
(EFIAPI *CMDDB_GET_ADDRESS)(
  IN  EFI_CMDDB_PROTOCOL  *This,
  IN  CONST CHAR8         *Name,
  OUT UINT32              *Address
  );

///
/// Method +0x28. Observed (PRM init @0x14AD4): returns a UINT16
/// version; the caller class-checks (Version & 0xFF00).
///
typedef
EFI_STATUS
(EFIAPI *CMDDB_GET_VERSION)(
  IN  EFI_CMDDB_PROTOCOL  *This,
  IN  CONST CHAR8         *Name,
  OUT UINT16              *Version
  );

typedef VOID *CMDDB_OPAQUE_METHOD;

struct _EFI_CMDDB_PROTOCOL {
  CMDDB_OPAQUE_METHOD  M00;             // +0x00
  CMDDB_OPAQUE_METHOD  M01;             // +0x08
  CMDDB_GET_ADDRESS    GetAddress;      // +0x10
  CMDDB_OPAQUE_METHOD  M03;             // +0x18
  CMDDB_OPAQUE_METHOD  M04;             // +0x20
  CMDDB_GET_VERSION    GetVersion;      // +0x28
  CMDDB_OPAQUE_METHOD  M06;             // +0x30  (This, key, &u32 -- validator)
  CMDDB_OPAQUE_METHOD  M07;             // +0x38  (This, key, a1, a2, &ret -- validator)
};

#endif
