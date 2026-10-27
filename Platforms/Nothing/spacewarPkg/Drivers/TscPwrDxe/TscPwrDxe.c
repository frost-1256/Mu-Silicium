/** @file
  TscPwrDxe — FT3680 touch power for spacewar, UEFI side.

  The FT3680 is powered from RPMh regulators pm8350c_l3 (2.8 V) and
  pm8350c_l8 (1.8 V). Under Windows nothing raises those rails, so
  the chip never answers on SPI. End goal: vote both LDOs on during
  DXE via the EFI RPMH protocol (binary RpmhDxe), using CmdDb for
  the resource addresses — the same machinery the binary PmicDxeLa
  uses. Protocol facts: EFIRpmh.h / EFICmdDb.h (this directory) and
  winboot/UEFI_TOUCH_POWER_PLAN.md.

  THIS BUILD IS A PROBE (v0.2). It issues NO votes. It only:
    1. Locates the CmdDb protocol and queries, for the packed-name
       keys "ldoc3" / "ldoc8": GetVersion (+0x28) and GetAddress
       (+0x10).
    2. Locates the RPMh protocol and calls CreateHandle with the
       candidate DrvIds {0, 1, 2} (the value PmicDxeLa resolves on
       spacewar is runtime config data, not visible statically;
       CreateHandle performs no ID validation and has no side
       effects beyond allocating a handle struct).
    3. Writes all results to \TSCPROBE.TXT on the ESP (the volume
       that contains \EFI), so they can be read afterwards from the
       PC over the recovery gadget (esp partition).
  Every failure path returns EFI_SUCCESS: never block the boot.
**/

#include <Uefi.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include "EFIRpmh.h"
#include "EFICmdDb.h"
#include <Protocol/SimpleFileSystem.h>

#define TSC_CMDDB_KEY(Name)  \
  ((UINT64)(Name)[0]        | ((UINT64)(Name)[1] << 8)  | \
   ((UINT64)(Name)[2] << 16) | ((UINT64)(Name)[3] << 24) | \
   ((UINT64)(Name)[4] << 32))

STATIC
EFI_STATUS
WriteProbeFile (
  IN CHAR8  *Text,
  IN UINTN   Len
  )
{
  EFI_STATUS                     Status;
  UINTN                          Count;
  EFI_HANDLE                    *Handles;
  UINTN                          Index;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;
  EFI_FILE_PROTOCOL             *Root;
  EFI_FILE_PROTOCOL             *File;
  UINTN                          Written;

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiSimpleFileSystemProtocolGuid,
                  NULL,
                  &Count,
                  &Handles
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = EFI_NOT_FOUND;
  for (Index = 0; Index < Count; Index++) {
    Fs = NULL;
    if (EFI_ERROR (gBS->HandleProtocol (
                           Handles[Index],
                           &gEfiSimpleFileSystemProtocolGuid,
                           (VOID **)&Fs
                           ))) {
      continue;
    }
    Root = NULL;
    if (EFI_ERROR (Fs->OpenVolume (Fs, &Root))) {
      continue;
    }
    //
    // Identify the ESP by the presence of the \EFI directory.
    //
    File = NULL;
    Status = Root->Open (
                     Root,
                     &File,
                     L"\\EFI",
                     EFI_FILE_MODE_READ,
                     0
                     );
    if (!EFI_ERROR (Status)) {
      File->Close (File);
      File = NULL;
      Status = Root->Open (
                       Root,
                       &File,
                       L"\\TSCPROBE.TXT",
                       EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                       0
                       );
      if (!EFI_ERROR (Status)) {
        Written = Len;
        File->Write (File, &Written, Text);
        File->Close (File);
        Root->Close (Root);
        break;
      }
    }
    Root->Close (Root);
  }

  gBS->FreePool (Handles);
  return Status;
}

EFI_STATUS
EFIAPI
TscPwrDxeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_CMDDB_PROTOCOL  *CmdDb;
  EFI_RPMH_PROTOCOL   *Rpmh;
  CHAR8                Buf[1024];
  UINTN                Len;
  UINT32               Addr3, Addr8;
  UINT16               Ver3, Ver8;
  EFI_STATUS           St3, St8, StV3, StV8;
  UINT32               Idx;
  VOID                *Handle;
  EFI_STATUS           StH;

  Len = AsciiSPrint (Buf, sizeof (Buf), "TscPwr probe v0.2\n");

  CmdDb = NULL;
  if (!EFI_ERROR (gBS->LocateProtocol (
                         &gEfiCmdDbProtocolGuid,
                         NULL,
                         (VOID **)&CmdDb
                         ))) {
    Addr3 = 0; Ver3 = 0;
    StV3 = CmdDb->GetVersion (CmdDb, TSC_CMDDB_KEY ("ldoc3"), &Ver3);
    St3  = CmdDb->GetAddress (CmdDb, TSC_CMDDB_KEY ("ldoc3"), &Addr3);
    Addr8 = 0; Ver8 = 0;
    StV8 = CmdDb->GetVersion (CmdDb, TSC_CMDDB_KEY ("ldoc8"), &Ver8);
    St8  = CmdDb->GetAddress (CmdDb, TSC_CMDDB_KEY ("ldoc8"), &Addr8);
    Len += AsciiSPrint (
             Buf + Len, sizeof (Buf) - Len,
             "CmdDb ldoc3: ver st=%r ver=0x%x addr st=%r addr=0x%x\n"
             "CmdDb ldoc8: ver st=%r ver=0x%x addr st=%r addr=0x%x\n",
             StV3, Ver3, St3, Addr3, StV8, Ver8, St8, Addr8
             );
  } else {
    Len += AsciiSPrint (Buf + Len, sizeof (Buf) - Len, "CmdDb: NOT FOUND\n");
  }

  Rpmh = NULL;
  if (!EFI_ERROR (gBS->LocateProtocol (
                         &gEfiRpmhProtocolGuid,
                         NULL,
                         (VOID **)&Rpmh
                         ))) {
    Len += AsciiSPrint (
             Buf + Len, sizeof (Buf) - Len,
             "Rpmh: rev=0x%x\n", Rpmh->Revision
             );
    for (Idx = 0; Idx <= 2; Idx++) {
      Handle = NULL;
      StH = Rpmh->CreateHandle (Idx, "pmic", &Handle);
      Len += AsciiSPrint (
               Buf + Len, sizeof (Buf) - Len,
               "Rpmh CreateHandle drv=%u st=%r handle=%p\n",
               Idx, StH, Handle
               );
    }
  } else {
    Len += AsciiSPrint (Buf + Len, sizeof (Buf) - Len, "Rpmh: NOT FOUND\n");
  }

  WriteProbeFile (Buf, Len);
  return EFI_SUCCESS;
}
