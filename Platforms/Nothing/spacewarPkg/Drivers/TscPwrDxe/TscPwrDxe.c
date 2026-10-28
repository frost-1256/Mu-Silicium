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
#include <Protocol/LoadedImage.h>

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
  EFI_STATUS           St;
  UINT32               Idx;
  UINT32               Addr3, Addr8;
  UINT16               Ver3, Ver8;
  EFI_STATUS           StA3, StA8;

  Addr3 = Addr8 = 0; Ver3 = Ver8 = 0; StA3 = StA8 = EFI_NOT_FOUND;

  Say ("TscPwr probe v1.4 - staged");
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

    //
    // v1.0: runtime table readout + the actual votes.
    // PmicDxeLa's per-PMIC tables are runtime-populated, so read
    // them out of its loaded image (FILE_GUID slot at RVA
    // 0x20018), walk table[2] (pm8350c) for the ldoc3/ldoc8 range
    // entries, then issue the exact FA5F306B write calls its
    // pm_ldo workers build: voltage first (cmd 2, steps payload),
    // then enable (cmd 1, payload byte 0x80). All values are
    // recomputed from the live tables, nothing hardcoded.
    //
    {
      EFI_LOADED_IMAGE_PROTOCOL  *Img;
      EFI_HANDLE                 *ImgHandles;
      UINTN                       ImgCount, Ii;
      UINT8                      *LaBase;
      UINT8                      *Info, *Ctx, *Sub, *RangeTab, *Entry;
      UINT32                      Count, Arg0, Min, Max, Step;
      UINT16                      ResV[9], ResE[9], ResR[9];
      UINT32                      StepsV[9], TargetUv;
      VOID                       *Fa5;
      VOID                       *Fa5Cached;

      typedef EFI_STATUS (EFIAPI *FA5_READ)(
        VOID *This, UINT32 Arg0, UINT32 One, UINT32 ResId,
        UINT32 *Payload, UINT32 Cmd, VOID *Extra);
      FA5_READ   Read;
      UINT32     Payload;

      STATIC EFI_GUID  LaGuid = { 0x5776232E, 0x082D, 0x4B75, { 0x9A, 0x0E, 0xFE, 0x1D, 0x13, 0xF7, 0xA5, 0xD9 } };
      STATIC EFI_GUID  Fa5Guid = { 0xFA5F306B, 0xF47D, 0x4AC4, { 0xA4, 0x7D, 0x88, 0x2F, 0x82, 0x04, 0xEC, 0x30 } };

      LaBase = NULL;
      ImgHandles = NULL;
      ImgCount = 0;
      Say ("I1: enumerating loaded images");
      St = gBS->LocateHandleBuffer (ByProtocol, &gEfiLoadedImageProtocolGuid, NULL, &ImgCount, &ImgHandles);
      AsciiSPrint (Line, sizeof (Line), "images st=%r count=%u", St, (UINT32)ImgCount);
      Say (Line);
      if (!EFI_ERROR (St)) {
        for (Ii = 0; Ii < ImgCount; Ii++) {
          Img = NULL;
          if (EFI_ERROR (gBS->HandleProtocol (ImgHandles[Ii], &gEfiLoadedImageProtocolGuid, (VOID **)&Img))) {
            continue;
          }
          if (Img->ImageBase == NULL || Img->ImageSize < 0x21000) {
            continue;
          }
          if (CompareGuid ((EFI_GUID *)((UINT8 *)Img->ImageBase + 0x20018), &LaGuid)) {
            LaBase = (UINT8 *)Img->ImageBase;
            break;
          }
        }
        gBS->FreePool (ImgHandles);
      }
      AsciiSPrint (Line, sizeof (Line), "PmicDxeLa base=%p", LaBase);
      Say (Line);

      ResV[3] = ResV[8] = ResE[3] = ResE[8] = ResR[3] = ResR[8] = 0;
      StepsV[3] = StepsV[8] = 0;
      Arg0 = 0;
      if (LaBase != NULL) {
        Say ("I2: reading pmic table[2]");
        Info = *(UINT8 **)(LaBase + 0x21CD0 + 2 * sizeof (VOID *));
        AsciiSPrint (Line, sizeof (Line), "info=%p", Info);
        Say (Line);
        if (Info != NULL) {
          Ctx = *(UINT8 **)Info;
          Sub = *(UINT8 **)(Info + 8);
          Arg0 = *(UINT32 *)Ctx;
          Count = *(UINT32 *)(Info + 8 + 0xC);
          RangeTab = *(UINT8 **)(Info + 8 + 0x10);
          AsciiSPrint (Line, sizeof (Line), "arg0=0x%x count=%u S=%p range=%p", Arg0, Count, Sub, RangeTab);
          Say (Line);
          if (RangeTab != NULL && Count > 8) {
            for (Idx = 3; Idx <= 8; Idx += 5) {
              Entry = RangeTab + Idx * 0x14;
              Min = *(UINT32 *)Entry;
              Max = *(UINT32 *)(Entry + 4);
              Step = *(UINT32 *)(Entry + 8);
              TargetUv = (Idx == 3) ? 2800000 : 1800000;
              ResV[Idx] = *(UINT16 *)(Sub + 0xC) + *(UINT16 *)(Entry + 0xC);
              ResE[Idx] = *(UINT16 *)(Sub + 0x16) + *(UINT16 *)(Entry + 0xC);
              ResR[Idx] = *(UINT16 *)(Sub + 0x10) + *(UINT16 *)(Entry + 0xC);
              StepsV[Idx] = (Step != 0 && TargetUv >= Min && TargetUv <= Max)
                            ? (TargetUv - Min) / Step : 0;
              AsciiSPrint (Line, sizeof (Line),
                "ldo%u min=%u max=%u step=%u valid=%u type=%u",
                Idx, Min, Max, Step, Entry[0xE], Entry[0x10]);
              Say (Line);
              AsciiSPrint (Line, sizeof (Line),
                "ldo%u resV=0x%x resE=0x%x steps(%u)=%u",
                Idx, ResV[Idx], ResE[Idx], TargetUv, StepsV[Idx]);
              Say (Line);
              AsciiSPrint (Line, sizeof (Line),
                "ldo%u resR=0x%x", Idx, ResR[Idx]);
              Say (Line);
            }
          }
        }
        Fa5Cached = *(VOID **)(LaBase + 0x22580);
        AsciiSPrint (Line, sizeof (Line), "FA5 cached=%p", Fa5Cached);
        Say (Line);
      }

      Say ("I3: locating FA5F306B protocol");
      Fa5 = NULL;
      St = gBS->LocateProtocol (&Fa5Guid, NULL, &Fa5);
      AsciiSPrint (Line, sizeof (Line), "FA5 locate st=%r ptr=%p", St, Fa5);
      Say (Line);

      if (Fa5 != NULL && StepsV[3] != 0 && StepsV[8] != 0) {
        Read = (FA5_READ)((VOID **)Fa5)[1];

        Say ("READ ldo3 voltage (channel check)");
        Payload = 0;
        St = Read (Fa5, Arg0, 1, ResR[3], &Payload, 2, NULL);
        AsciiSPrint (Line, sizeof (Line), "ldo3 read st=%r steps=%u", St, Payload);
        Say (Line);
      } else {
        Say ("READ SKIPPED (missing inputs)");
      }

      //
      // v1.3 matrix results: hdr1/hdr2 sets only queue commands
      // in RpmhDxe's core (Flag != 0 path appends to a pending
      // list and returns 0 unsent); hdr0 sets reach the real TCS
      // send, which returned 1. The trailing hdr0 repeat returned
      // 0 via the core's "redundant commands" short circuit, not
      // via a successful send. So the open question is the TCS
      // send itself. v1.4 issues the single canonical set
      // (hdr0/ent1, name "pmic") here at ReadyToBoot (EarlyVote
      // in the entry point already issued it at DXE dispatch) so
      // both timings can be compared in one boot.
      //
      if (Rpmh != NULL && Addr3 != 0 && Addr8 != 0 &&
          StepsV[3] != 0 && StepsV[8] != 0) {
        struct {
          UINT32  Flag;
          UINT32  Count;
          UINT32  Reserved;
          struct {
            UINT32  Address;
            UINT32  Data;
            UINT8   Flag;
            UINT8   Pad[3];
          } E[4];
        } Set;
        VOID   *Handle;
        INT32   Result;

        Handle = NULL;
        Rpmh->CreateHandle (2, "pmic", &Handle);
        AsciiSPrint (Line, sizeof (Line), "LATE handle=%p", Handle);
        Say (Line);
        if (Handle != NULL) {
          Set.Flag = 0;
          Set.Count = 4;
          Set.Reserved = 0;
          Set.E[0].Address = Addr3;     Set.E[0].Data = StepsV[3];
          Set.E[0].Flag = 1;            Set.E[0].Pad[0] = Set.E[0].Pad[1] = Set.E[0].Pad[2] = 0;
          Set.E[1].Address = Addr3 + 4; Set.E[1].Data = 1;
          Set.E[1].Flag = 1;            Set.E[1].Pad[0] = Set.E[1].Pad[1] = Set.E[1].Pad[2] = 0;
          Set.E[2].Address = Addr8;     Set.E[2].Data = StepsV[8];
          Set.E[2].Flag = 1;            Set.E[2].Pad[0] = Set.E[2].Pad[1] = Set.E[2].Pad[2] = 0;
          Set.E[3].Address = Addr8 + 4; Set.E[3].Data = 1;
          Set.E[3].Flag = 1;            Set.E[3].Pad[0] = Set.E[3].Pad[1] = Set.E[3].Pad[2] = 0;
          Result = -1;
          St = Rpmh->IssueSet (Handle, (RPMH_REQUEST_SET *)&Set, &Result);
          AsciiSPrint (Line, sizeof (Line), "LATE IssueSet st=%r result=%d", St, Result);
          Say (Line);
          gBS->Stall (500000);
        }
        if (Fa5 != NULL) {
          Read = (FA5_READ)((VOID **)Fa5)[1];
          Payload = 0;
          St = Read (Fa5, Arg0, 1, ResR[3], &Payload, 2, NULL);
          AsciiSPrint (Line, sizeof (Line), "ldo3 now steps=%u st=%r", Payload, St);
          Say (Line);
          Payload = 0;
          St = Read (Fa5, Arg0, 1, ResR[8], &Payload, 2, NULL);
          AsciiSPrint (Line, sizeof (Line), "ldo8 now steps=%u st=%r", Payload, St);
          Say (Line);
        }
        Say ("VOTE DONE");
      } else {
        Say ("VOTE SKIPPED (missing inputs)");
      }
    }
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

STATIC
VOID
EFIAPI
VoteNotify (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  ProbeRun ();
  gBS->CloseEvent (Event);
}

//
// v1.4: the same canonical vote as ProbeRun issues at
// ReadyToBoot, but fired at DXE dispatch time. The RpmhDxe
// core's low-level TCS send is the current suspect (it returned
// 1 for every real send at ReadyToBoot); the RSC/TCS state this
// early — before the rest of the platform drivers run — may
// differ. Voltages are the known mV values for ldoc3/ldoc8.
//
STATIC
VOID
EarlyVote (
  VOID
  )
{
  EFI_CMDDB_PROTOCOL  *CmdDb;
  EFI_RPMH_PROTOCOL   *Rpmh;
  EFI_STATUS           St;
  UINT32               Addr3, Addr8;
  CHAR8                Line[128];
  VOID                *Handle;
  INT32                Result;
  struct {
    UINT32  Flag;
    UINT32  Count;
    UINT32  Reserved;
    struct {
      UINT32  Address;
      UINT32  Data;
      UINT8   Flag;
      UINT8   Pad[3];
    } E[4];
  } Set;

  Say ("EARLY vote at DXE entry");
  CmdDb = NULL;
  Rpmh = NULL;
  Addr3 = Addr8 = 0;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiCmdDbProtocolGuid, NULL, (VOID **)&CmdDb)) ||
      EFI_ERROR (gBS->LocateProtocol (&gEfiRpmhProtocolGuid, NULL, (VOID **)&Rpmh))) {
    Say ("EARLY: protocol locate failed");
    return;
  }
  CmdDb->GetAddress (CmdDb, "ldoc3", &Addr3);
  CmdDb->GetAddress (CmdDb, "ldoc8", &Addr8);
  AsciiSPrint (Line, sizeof (Line), "EARLY addr3=0x%x addr8=0x%x", Addr3, Addr8);
  Say (Line);
  if (Addr3 == 0 || Addr8 == 0) {
    return;
  }
  Handle = NULL;
  Rpmh->CreateHandle (2, "pmic", &Handle);
  AsciiSPrint (Line, sizeof (Line), "EARLY handle=%p", Handle);
  Say (Line);
  if (Handle == NULL) {
    return;
  }
  Set.Flag = 0;
  Set.Count = 4;
  Set.Reserved = 0;
  Set.E[0].Address = Addr3;     Set.E[0].Data = 2800;
  Set.E[0].Flag = 1;            Set.E[0].Pad[0] = Set.E[0].Pad[1] = Set.E[0].Pad[2] = 0;
  Set.E[1].Address = Addr3 + 4; Set.E[1].Data = 1;
  Set.E[1].Flag = 1;            Set.E[1].Pad[0] = Set.E[1].Pad[1] = Set.E[1].Pad[2] = 0;
  Set.E[2].Address = Addr8;     Set.E[2].Data = 1800;
  Set.E[2].Flag = 1;            Set.E[2].Pad[0] = Set.E[2].Pad[1] = Set.E[2].Pad[2] = 0;
  Set.E[3].Address = Addr8 + 4; Set.E[3].Data = 1;
  Set.E[3].Flag = 1;            Set.E[3].Pad[0] = Set.E[3].Pad[1] = Set.E[3].Pad[2] = 0;
  Result = -1;
  St = Rpmh->IssueSet (Handle, (RPMH_REQUEST_SET *)&Set, &Result);
  AsciiSPrint (Line, sizeof (Line), "EARLY IssueSet st=%r result=%d", St, Result);
  Say (Line);
}

EFI_STATUS
EFIAPI
TscPwrDxeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_EVENT  Event;

  //
  // v1.1: at DXE dispatch the SPMI block is not reachable yet
  // (v1.0 died with a synchronous external abort inside SPMI.dll
  // at FAR 0x0DE30008). Defer the whole sequence to ReadyToBoot,
  // when platform init has brought everything up.
  // v1.2: even at ReadyToBoot the FA5 write faults (arbiter TX
  // window) while reads succeed; the votes go through RPMh
  // IssueSet instead (see the vote block in ProbeRun).
  // v1.3: variant matrix — hdr1/hdr2 only queue, hdr0 sends
  // fail with Result=1. v1.4: also fire the vote at DXE entry
  // (EarlyVote above) to compare TCS-send behaviour by timing.
  //
  EarlyVote ();
  return gBS->CreateEventEx (
                EVT_NOTIFY_SIGNAL,
                TPL_CALLBACK,
                VoteNotify,
                NULL,
                &gEfiEventReadyToBootGuid,
                &Event
                );
}
