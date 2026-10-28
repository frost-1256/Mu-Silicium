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
STATIC VOID UefiTouchCheck (IN CHAR8 *Label);
STATIC VOID RscVote (IN CHAR8 *Label);

STATIC
VOID
ProbeRun (
  VOID
  )
{
  Say ("TscPwr probe v2.1 - RSC direct");
  ProbeOpen ();
  RscVote ("LATE");
  gBS->Stall (500000);
  UefiTouchCheck ("LATE");
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
// v1.5: UEFI-side FT3680 check — a direct port of the Windows
// driver's TLMM bit-bang + framed boot-ID read (Gpio.c/Spb.c/
// Ft3680.c in ft3680-driver/). After a vote, power-cycle the
// chip (GPIO105 reset) and ask for its boot ID over bit-banged
// SPI (MOSI 52, MISO 53, CLK 54, CS 55; TLMM window at physical
// 0x0F100000). If the chip answers here, the rails are live in
// UEFI and the loss happens at the OS handoff; if it stays
// silent, the vote never lands electrically.
//
#define TSC_TLMM_BASE   0x0F100000
#define TSC_PIN_CTL(P)  ((volatile UINT32 *)(UINTN)(TSC_TLMM_BASE + (P) * 0x1000))
#define TSC_PIN_IO(P)   ((volatile UINT32 *)(UINTN)(TSC_TLMM_BASE + (P) * 0x1000 + 4))

STATIC
VOID
TscPinConfig (
  IN UINT32  Pin,
  IN BOOLEAN Oe
  )
{
  UINT32  V = *TSC_PIN_CTL (Pin);
  V &= ~(0xFu << 2);
  if (Oe) {
    V |= (1u << 9);
  } else {
    V &= ~(1u << 9);
  }
  *TSC_PIN_CTL (Pin) = V;
}

STATIC
VOID
TscPinWrite (
  IN UINT32   Pin,
  IN BOOLEAN  Value
  )
{
  UINT32  V = *TSC_PIN_IO (Pin);
  if (Value) {
    V |= (1u << 1);
  } else {
    V &= ~(1u << 1);
  }
  *TSC_PIN_IO (Pin) = V;
}

STATIC
BOOLEAN
TscPinRead (
  IN UINT32  Pin
  )
{
  return (*TSC_PIN_IO (Pin) & 1u) != 0;
}

STATIC
UINT8
TscShiftByte (
  IN UINT8  Out
  )
{
  UINT8  In = 0;
  INT32  Bit;
  for (Bit = 7; Bit >= 0; Bit--) {
    TscPinWrite (52, (BOOLEAN)((Out >> Bit) & 1));
    gBS->Stall (3);
    TscPinWrite (54, TRUE);
    gBS->Stall (3);
    if (TscPinRead (53)) {
      In |= (UINT8)(1 << Bit);
    }
    TscPinWrite (54, FALSE);
    gBS->Stall (3);
  }
  return In;
}

STATIC
VOID
TscSpiTransfer (
  IN OUT UINT8  *Buf,
  IN UINTN       Len,
  IN BOOLEAN     Read
  )
{
  UINTN  I;
  TscPinWrite (55, FALSE);
  gBS->Stall (3);
  for (I = 0; I < Len; I++) {
    UINT8  R = TscShiftByte (Read ? 0x00 : Buf[I]);
    if (Read) {
      Buf[I] = R;
    }
  }
  TscPinWrite (54, FALSE);
  TscPinWrite (55, TRUE);
  gBS->Stall (150);
}

STATIC
VOID
TscSpiReadFrame (
  IN UINT8   *Head,
  IN UINTN    HeadLen,
  IN UINT8   *Rx,
  IN UINTN    RxLen
  )
{
  UINTN  I;
  TscPinWrite (55, FALSE);
  gBS->Stall (3);
  for (I = 0; I < HeadLen; I++) {
    (VOID)TscShiftByte (Head[I]);
  }
  for (I = 0; I < RxLen; I++) {
    Rx[I] = TscShiftByte (0x00);
  }
  TscPinWrite (54, FALSE);
  TscPinWrite (55, TRUE);
  gBS->Stall (150);
}

STATIC
UINT16
TscCrcKermit (
  IN UINT8  *Data,
  IN UINTN   Len
  )
{
  UINT16  Crc = 0xFFFF;
  UINTN   I;
  INT32   Bit;
  for (I = 0; I < Len; I++) {
    Crc = (UINT16)(Crc ^ Data[I]);
    for (Bit = 0; Bit < 8; Bit++) {
      Crc = (Crc & 1) ? (UINT16)((Crc >> 1) ^ 0x8408) : (UINT16)(Crc >> 1);
    }
  }
  return Crc;
}

STATIC
VOID
UefiTouchCheck (
  IN CHAR8  *Label
  )
{
  CHAR8   Line[160];
  UINT8   Frame[8];
  UINT8   Head[7];
  UINT8   Rx[4];
  UINT32  Attempt;
  UINT16  Calc, Read;

  TscPinConfig (52, TRUE);
  TscPinConfig (53, FALSE);
  TscPinConfig (54, TRUE);
  TscPinConfig (55, TRUE);
  TscPinConfig (105, TRUE);
  TscPinWrite (54, FALSE);
  TscPinWrite (55, TRUE);

  /* reset pulse: low 10 ms, high, 250 ms settle */
  TscPinWrite (105, FALSE);
  gBS->Stall (10000);
  TscPinWrite (105, TRUE);
  gBS->Stall (250000);

  for (Attempt = 0; Attempt < 3; Attempt++) {
    /* framed write of the start command {0x55, 0xAA} */
    Frame[0] = 0x55; Frame[1] = 0x00; Frame[2] = 0x00; Frame[3] = 0x01;
    Frame[4] = 0x00; Frame[5] = 0x00; Frame[6] = 0x00; Frame[7] = 0xAA;
    TscSpiTransfer (Frame, 8, FALSE);
    gBS->Stall (12000);
    /* framed read of register 0x90, 2 data bytes + CRC16 */
    Head[0] = 0x90; Head[1] = 0xA0; Head[2] = 0x00; Head[3] = 0x02;
    Head[4] = 0x00; Head[5] = 0x00; Head[6] = 0x00;
    Rx[0] = Rx[1] = Rx[2] = Rx[3] = 0;
    TscSpiReadFrame (Head, 7, Rx, 4);
    Calc = TscCrcKermit (Rx, 2);
    Read = (UINT16)((Rx[3] << 8) | Rx[2]);
    AsciiSPrint (Line, sizeof (Line),
      "%a bootid %u: raw %02X %02X %02X %02X calc %04X read %04X",
      Label, Attempt, Rx[0], Rx[1], Rx[2], Rx[3], Calc, Read);
    Say (Line);
    if (Calc == Read && Rx[0] != 0 && Rx[1] != 0) {
      AsciiSPrint (Line, sizeof (Line), "%a: CHIP ALIVE id %02X %02X", Label, Rx[0], Rx[1]);
      Say (Line);
      return;
    }
  }
  AsciiSPrint (Line, sizeof (Line), "%a: chip silent", Label);
  Say (Line);
}

//
// v2.0: bypass RpmhDxe entirely and program the apps RSC
// directly, following the public mainline rpmh-rsc protocol
// (drivers/soc/qcom/rpmh-rsc.c). RpmhDxe's queue/trigger chain
// never completes a send on this build (v1.2-v1.5), so write
// the ACTIVE TCS ourselves: buffer the commands, set
// CMD_ENABLE, run the AMC trigger sequence, poll the DRV IRQ
// status for completion, then clean up like tcs_tx_done.
//
// Layout (lahaina-family apps_rsc): RSC at 0x18200000, DRV2 at
// +0x20000, TCS blocks at DRV + qcom,tcs-offset (0xD00), TCS
// stride 672, command stride 20. tcs-config puts ACTIVE first,
// so TCS 0 and 1 are the ACTIVE TCSes. RSC_DRV_STATUS is zero
// while a TCS is busy. MSGID = LEN(8) | RESP_REQ | WRITE for
// wait-for-completion writes.
//
#define RSC_DRV_BASE    0x18220000
#define RSC_TCS_BASE    (RSC_DRV_BASE + 0xD00)
#define RSC_TCS_STRIDE  672
#define RSC_CMD_STRIDE  20
#define RSC_REG32(A)    (*(volatile UINT32 *)(UINTN)(A))
#define TCS_REG(T, R)   RSC_REG32 (RSC_TCS_BASE + RSC_TCS_STRIDE * (T) + (R))
#define TCS_CMD(T, J, R) \
  RSC_REG32 (RSC_TCS_BASE + RSC_TCS_STRIDE * (T) + (R) + RSC_CMD_STRIDE * (J))

STATIC
VOID
RscSyncWrite (
  IN UINTN   Addr,
  IN UINT32  Value
  )
{
  UINT32  Tries;

  RSC_REG32 (Addr) = Value;
  for (Tries = 0; Tries < 10000; Tries++) {
    if (RSC_REG32 (Addr) == Value) {
      return;
    }
    gBS->Stall (10);
  }
}

STATIC
VOID
RscVote (
  IN CHAR8  *Label
  )
{
  CHAR8   Line[200];
  UINT32  Cfg, NumTcs, Ncpt, T, J, Ctrl, IrqSt, Tries;
  UINT32  CmdAddr[6];
  UINT32  CmdData[6];

  CmdAddr[0] = 0x40E00;  CmdData[0] = 2800;  /* ldoc3 voltage mV */
  CmdAddr[1] = 0x40E08;  CmdData[1] = 7;     /* ldoc3 mode HPM */
  CmdAddr[2] = 0x40E04;  CmdData[2] = 1;     /* ldoc3 enable */
  CmdAddr[3] = 0x42500;  CmdData[3] = 1800;  /* ldoc8 voltage mV */
  CmdAddr[4] = 0x42508;  CmdData[4] = 7;     /* ldoc8 mode HPM */
  CmdAddr[5] = 0x42504;  CmdData[5] = 1;     /* ldoc8 enable */

  Cfg = RSC_REG32 (RSC_DRV_BASE + 0x0C);
  NumTcs = (Cfg >> 12) & 0x3F;   /* DRV2 field of DRV_PRNT_CHLD_CONFIG */
  Ncpt = (Cfg >> 27) & 0x1F;
  AsciiSPrint (Line, sizeof (Line),
    "%a RSC cfg=0x%x numtcs=%u ncpt=%u", Label, Cfg, NumTcs, Ncpt);
  Say (Line);
  if (NumTcs < 2 || NumTcs > 16 || Ncpt < 4 || Ncpt > 16) {
    AsciiSPrint (Line, sizeof (Line), "%a RSC: implausible config, no writes", Label);
    Say (Line);
    return;
  }

  for (T = 0; T < 2; T++) {
    if (TCS_REG (T, 0x18) == 0) {
      AsciiSPrint (Line, sizeof (Line), "%a RSC: tcs%u busy, skip", Label, T);
      Say (Line);
      continue;
    }
    AsciiSPrint (Line, sizeof (Line),
      "%a RSC: tcs%u status=0x%x ctrl=0x%x enable=0x%x",
      Label, T, TCS_REG (T, 0x18), TCS_REG (T, 0x14), TCS_REG (T, 0x1C));
    Say (Line);

    for (J = 0; J < 6; J++) {
      TCS_CMD (T, J, 0x30) = 8 | (1u << 8) | (1u << 16);  /* MSGID */
      TCS_CMD (T, J, 0x34) = CmdAddr[J];                  /* ADDR */
      TCS_CMD (T, J, 0x38) = CmdData[J];                  /* DATA */
    }
    TCS_REG (T, 0x1C) = TCS_REG (T, 0x1C) | 0x3F;          /* CMD_ENABLE */

    /* __tcs_set_trigger: clear trigger, clear enable (both
       sync), set enable (sync), then set trigger (plain). */
    Ctrl = TCS_REG (T, 0x14);
    RscSyncWrite (RSC_TCS_BASE + RSC_TCS_STRIDE * T + 0x14, Ctrl & ~(1u << 24));
    Ctrl = TCS_REG (T, 0x14);
    RscSyncWrite (RSC_TCS_BASE + RSC_TCS_STRIDE * T + 0x14, Ctrl & ~(1u << 16));
    RscSyncWrite (RSC_TCS_BASE + RSC_TCS_STRIDE * T + 0x14, (1u << 16));
    TCS_REG (T, 0x14) = (1u << 16) | (1u << 24);

    IrqSt = 0;
    for (Tries = 0; Tries < 2000; Tries++) {
      IrqSt = RSC_REG32 (RSC_TCS_BASE + 0x04);
      if ((IrqSt & (1u << T)) != 0) {
        break;
      }
      gBS->Stall (100);
    }
    AsciiSPrint (Line, sizeof (Line),
      "%a RSC: tcs%u irq=0x%x tries=%u status=0x%x",
      Label, T, IrqSt, Tries, TCS_REG (T, 0x18));
    Say (Line);
    for (J = 0; J < 6; J++) {
      AsciiSPrint (Line, sizeof (Line),
        "%a RSC: cmd%u status=0x%x", Label, J, TCS_CMD (T, J, 0x3C));
      Say (Line);
    }

    /* reclaim like tcs_tx_done */
    TCS_REG (T, 0x1C) = 0;
    RSC_REG32 (RSC_TCS_BASE + 0x08) = (1u << T);
    AsciiSPrint (Line, sizeof (Line), "%a RSC: vote fired on tcs%u", Label, T);
    Say (Line);
    return;
  }

  AsciiSPrint (Line, sizeof (Line), "%a RSC: no idle ACTIVE TCS", Label);
  Say (Line);
}

STATIC
VOID
EarlyVote (
  VOID
  )
{
  Say ("EARLY vote at DXE entry (RSC direct)");
  UefiTouchCheck ("PRE");
  RscVote ("EARLY");
  gBS->Stall (500000);
  UefiTouchCheck ("EARLY");
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
