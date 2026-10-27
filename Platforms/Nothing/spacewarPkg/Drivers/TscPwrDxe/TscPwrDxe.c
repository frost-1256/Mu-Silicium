/** @file
  TscPwrDxe — FT3680 touch power for spacewar, UEFI side.

  The FT3680 is powered from RPMh regulators pm8350c_l3 (2.8 V) and
  pm8350c_l8 (1.8 V). Under Windows nothing raises those rails, so
  the chip never answers on SPI. End goal: vote both LDOs on during
  DXE via the EFI RPMH protocol (binary RpmhDxe), using CmdDb for
  the resource addresses — the same machinery the binary PmicDxeLa
  uses. Protocol facts: EFIRpmh.h / EFICmdDb.h (this directory) and
  winboot/UEFI_TOUCH_POWER_PLAN.md.

  THIS BUILD IS A PROBE (v0.4, checkpointed). It issues NO votes. It only:
    1. Locates the CmdDb protocol and queries, for the resource
       names "ldoc3" / "ldoc8": GetVersion (+0x28) and GetAddress
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
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Guid/EventGroup.h>
#include "EFIRpmh.h"
#include "EFICmdDb.h"
#include <Protocol/SimpleFileSystem.h>

STATIC EFI_FILE_PROTOCOL *gProbeRoot;
STATIC EFI_FILE_PROTOCOL *gProbeFile;

STATIC
EFI_STATUS
ProbeOpen (
  VOID
  )
{
  EFI_STATUS                     Status;
  UINTN                          Count;
  EFI_HANDLE                    *Handles;
  UINTN                          Index;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;
  EFI_FILE_PROTOCOL             *File;

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
    gProbeRoot = NULL;
    if (EFI_ERROR (Fs->OpenVolume (Fs, &gProbeRoot))) {
      continue;
    }
    //
    // Identify the ESP by the presence of the \EFI directory.
    //
    File = NULL;
    Status = gProbeRoot->Open (
                           gProbeRoot,
                           &File,
                           L"\\EFI",
                           EFI_FILE_MODE_READ,
                           0
                           );
    if (!EFI_ERROR (Status)) {
      File->Close (File);
      Status = gProbeRoot->Open (
                             gProbeRoot,
                             &gProbeFile,
                             L"\\TSCPROBE.TXT",
                             EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                             0
                             );
      if (!EFI_ERROR (Status)) {
        break;
      }
    }
    gProbeRoot->Close (gProbeRoot);
    gProbeRoot = NULL;
  }

  gBS->FreePool (Handles);
  return Status;
}

//
// Append one checkpoint line and flush it to the ESP immediately, so
// the file always shows the last step that COMPLETED even if the
// next call faults (UEFI has no observable console on this device).
//
STATIC CHAR8  gProbeBuf[2048];
STATIC UINTN  gProbeLen;

STATIC
VOID
ProbeLog (
  IN CHAR8  *Text
  )
{
  UINTN  Len;
  UINTN  Written;

  Len = AsciiStrLen (Text);
  if (gProbeLen + Len < sizeof (gProbeBuf)) {
    CopyMem (gProbeBuf + gProbeLen, Text, Len);
    gProbeLen += Len;
  }
  if (gProbeFile == NULL) {
    return;
  }
  Written = Len;
  gProbeFile->Write (gProbeFile, &Written, Text);
  gProbeFile->Flush (gProbeFile);
}

STATIC
VOID
ProbeClose (
  VOID
  )
{
  if (gProbeFile != NULL) {
    gProbeFile->Close (gProbeFile);
    gProbeFile = NULL;
  }
  if (gProbeRoot != NULL) {
    gProbeRoot->Close (gProbeRoot);
    gProbeRoot = NULL;
  }
}


STATIC
VOID
Say (
  IN CHAR8  *Text
  )
{
  CHAR16  Uni[256];
  UINTN   I;

  for (I = 0; Text[I] != 0 && I < 250; I++) {
    Uni[I] = (CHAR16)Text[I];
  }
  Uni[I] = 0;
  if (gST != NULL && gST->ConOut != NULL) {
    gST->ConOut->OutputString (gST->ConOut, Uni);
    gST->ConOut->OutputString (gST->ConOut, L"\r\n");
  }
  DEBUG ((DEBUG_ERROR, "TSCPROBE: %a\n", Text));
  ProbeLog (Text);
  ProbeLog ("\n");
  if (gBS != NULL) {
    gBS->Stall (2000000);
  }
}

STATIC EFI_GUID mTscVendorGuid =
  { 0x1a799c27, 0x4f8f, 0x4bd1, { 0xae, 0x13, 0xcf, 0x36, 0xac, 0xf7, 0xdb, 0xf2 } };

STATIC VOID ProbeStoreVariable (VOID);

STATIC
VOID
ProbeRun (
  VOID
  )
{
  EFI_CMDDB_PROTOCOL  *CmdDb;
  EFI_RPMH_PROTOCOL   *Rpmh;
  CHAR8                Line[256];
  UINT32               Addr;
  UINT16               Ver;
  EFI_STATUS           St;
  UINT32               Idx;
  VOID                *Handle;
  UINT32               Addr3, Addr8;
  UINT16               Ver3, Ver8;
  EFI_STATUS           StA3, StA8;
  UINT32               DrvIdx;
  UINTN                VarSize;
  STATIC UINT32        DrvCandidates[4] = { 1, 2, 3, 4 };

  Addr3 = Addr8 = 0; Ver3 = Ver8 = 0; StA3 = StA8 = EFI_NOT_FOUND;

  Say ("TscPwr probe v0.7 - staged");
  ProbeOpen ();

  CmdDb = NULL;
  St = gBS->LocateProtocol (&gEfiCmdDbProtocolGuid, NULL, (VOID **)&CmdDb);
  AsciiSPrint (Line, sizeof (Line), "CmdDb locate st=%r", St);
  Say (Line);
  if (!EFI_ERROR (St)) {
    Say ("calling GetVersion ldoc3");
    St = CmdDb->GetVersion (CmdDb, "ldoc3", &Ver3);
    AsciiSPrint (Line, sizeof (Line), "ldoc3 ver st=%r ver=0x%x", St, Ver3);
    Say (Line);

    Say ("calling GetAddress ldoc3");
    StA3 = CmdDb->GetAddress (CmdDb, "ldoc3", &Addr3);
    AsciiSPrint (Line, sizeof (Line), "ldoc3 addr st=%r addr=0x%x", StA3, Addr3);
    Say (Line);

    Say ("calling GetVersion ldoc8");
    St = CmdDb->GetVersion (CmdDb, "ldoc8", &Ver8);
    AsciiSPrint (Line, sizeof (Line), "ldoc8 ver st=%r ver=0x%x", St, Ver8);
    Say (Line);

    Say ("calling GetAddress ldoc8");
    StA8 = CmdDb->GetAddress (CmdDb, "ldoc8", &Addr8);
    AsciiSPrint (Line, sizeof (Line), "ldoc8 addr st=%r addr=0x%x", StA8, Addr8);
    Say (Line);
  }

  Rpmh = NULL;
  St = gBS->LocateProtocol (&gEfiRpmhProtocolGuid, NULL, (VOID **)&Rpmh);
  AsciiSPrint (Line, sizeof (Line), "Rpmh locate st=%r", St);
  Say (Line);
  if (!EFI_ERROR (St)) {
    AsciiSPrint (Line, sizeof (Line), "Rpmh rev=0x%x", Rpmh->Revision);
    Say (Line);

    Say ("== SUMMARY ==");
    AsciiSPrint (Line, sizeof (Line), "ldoc3 ver=0x%x addr st=%r addr=0x%x", Ver3, StA3, Addr3);
    Say (Line);
    AsciiSPrint (Line, sizeof (Line), "ldoc8 ver=0x%x addr st=%r addr=0x%x", Ver8, StA8, Addr8);
    Say (Line);

    DrvIdx = 0;
    VarSize = sizeof (DrvIdx);
    gRT->GetVariable (L"TscDrvIdx", &mTscVendorGuid, NULL, &VarSize, &DrvIdx);
    if (DrvIdx >= 4) {
      DrvIdx = 0;
    }
    Idx = DrvIdx + 1;
    gRT->SetVariable (
           L"TscDrvIdx", &mTscVendorGuid,
           EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS |
           EFI_VARIABLE_NON_VOLATILE,
           sizeof (Idx), &Idx
           );
    AsciiSPrint (Line, sizeof (Line), "trying CreateHandle drv=%u", DrvCandidates[DrvIdx]);
    Say (Line);
    Handle = NULL;
    St = Rpmh->CreateHandle (DrvCandidates[DrvIdx], "pmic", &Handle);
    AsciiSPrint (Line, sizeof (Line), "CreateHandle drv=%u st=%r handle=%p", DrvCandidates[DrvIdx], St, Handle);
    Say (Line);
  }

  Say ("PROBE DONE");
  ProbeClose ();
  ProbeStoreVariable ();
}

STATIC
VOID
ProbeStoreVariable (
  VOID
  )
{
  if (gProbeLen == 0) {
    return;
  }
  gRT->SetVariable (
         L"TscProbe",
         &mTscVendorGuid,
         EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS |
         EFI_VARIABLE_NON_VOLATILE,
         gProbeLen,
         gProbeBuf
         );
}

EFI_STATUS
EFIAPI
TscPwrDxeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  ProbeRun ();
  return EFI_SUCCESS;
}
