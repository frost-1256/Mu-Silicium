/** @file
  RailProbeDxe — READ-ONLY probe: when do the FT3680 touch rails
  come up during boot on spacewar (E5 follow-up)?

  Background: the E5 variant UEFI (Run #60) removed TscPwrDxe,
  the driver that votes pm8350c LDO3_C (2.8 V) and LDO8_C (1.8 V)
  up during DXE — yet touch worked from the start of Windows.
  Some other element of the boot chain raises the rails. This
  probe finds out WHEN they are up, without changing anything:

    Sample "ENTRY"       — driver entry; APRIORI places this
                           driver right after TimerDxe, i.e.
                           before every Qualcomm platform binary
                           except EnvDxe.
    Sample "ENDOFDXE"    — EndOfDxe event.
    Sample "READYTOBOOT" — ReadyToBoot event (last UEFI point
                           before the OS loader runs).

  Each sample does two read-only things:
    1. Dump the apps RSC (DRV2) TCS command slots. If an
       apps-side DXE driver voted a rail through the RSC, the
       command addresses (ldoc3 = 0x40E00, ldoc8 = 0x42500)
       remain visible in the slots.
    2. Ask the FT3680 itself: TLMM bit-bang boot-ID check
       (verbatim port of the proven TscPwrDxe v1.5/v2.1 check).
       If the chip answers 56 62, its rails are electrically up.

  This driver issues NO votes and NO PMIC/RSC writes. The only
  register writes are TLMM GPIO configuration for the touch
  check (identical to the historic probe builds) and the log
  file on the ESP. Every failure path returns success: never
  block the boot.

  Results go to \RAILPROBE.TXT on the ESP (flushed per line,
  backlog dumped when the file first becomes available). UEFI
  NV variables do not persist on this build (established
  earlier), so the ESP file is the only result channel.
**/

#include <Uefi.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiLib.h>
#include <Guid/EventGroup.h>
#include <Protocol/SimpleFileSystem.h>

//
// ---------- log buffer + ESP file (pattern: TscPwrDxe v0.4) ----------
//

STATIC CHAR8               gProbeBuf[32768];
STATIC UINTN               gProbeLen;
STATIC UINTN               gFileLen;
STATIC EFI_FILE_PROTOCOL   *gProbeRoot;
STATIC EFI_FILE_PROTOCOL   *gProbeFile;

STATIC
VOID
ProbeFlush (
  VOID
  )
{
  UINTN  Written;

  if (gProbeFile == NULL || gFileLen >= gProbeLen) {
    return;
  }
  Written = gProbeLen - gFileLen;
  if (!EFI_ERROR (gProbeFile->Write (gProbeFile, &Written, gProbeBuf + gFileLen))) {
    gFileLen += Written;
    gProbeFile->Flush (gProbeFile);
  }
}

STATIC
VOID
ProbeLog (
  IN CHAR8  *Text
  )
{
  UINTN  Len;

  Len = AsciiStrLen (Text);
  if (gProbeLen + Len < sizeof (gProbeBuf)) {
    CopyMem (gProbeBuf + gProbeLen, Text, Len);
    gProbeLen += Len;
  }

  DEBUG ((DEBUG_ERROR, "RAILPROBE: %a", Text));
  ProbeFlush ();
}

STATIC
VOID
LogLine (
  IN CHAR8  *Format,
  ...
  )
{
  CHAR8    Line[256];
  VA_LIST  Args;

  VA_START (Args, Format);
  AsciiVSPrint (Line, sizeof (Line), Format, Args);
  VA_END (Args);
  ProbeLog (Line);
  ProbeLog ("\n");
}

STATIC
EFI_STATUS
ProbeOpen (
  VOID
  )
{
  EFI_STATUS                       Status;
  UINTN                            Count;
  EFI_HANDLE                       *Handles;
  UINTN                            Index;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *Fs;
  EFI_FILE_PROTOCOL                *File;

  if (gProbeFile != NULL) {
    return EFI_SUCCESS;
  }

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
                             L"\\RAILPROBE.TXT",
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
  if (!EFI_ERROR (Status)) {
    ProbeFlush ();  // dump the buffered backlog
  }

  return Status;
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

//
// ---------- apps RSC TCS slot dump (READ-ONLY) ----------
// Layout identical to TscPwrDxe v3.2: RSC DRV2 at 0x18220000,
// TCS blocks at DRV + 0xD00, TCS stride 672, command stride 20.
// Command registers per slot: +0x30 MSGID, +0x34 ADDR, +0x38
// DATA, +0x3C STATUS. Regulator vote addresses: ldoc3 0x40E00,
// ldoc8 0x42500 (+0 voltage, +4 enable, +8 mode).
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
TcsDump (
  IN CHAR8  *Label
  )
{
  UINT32  Cfg, NumTcs, Ncpt, T, J;
  UINT32  Addr, Data, Status;

  Cfg    = RSC_REG32 (RSC_DRV_BASE + 0x0C);
  NumTcs = (Cfg >> 12) & 0x3F;
  Ncpt   = (Cfg >> 27) & 0x1F;
  LogLine ("%a TCS dump: DRV cfg 0x%08x numtcs %u ncpt %u", Label, Cfg, NumTcs, Ncpt);
  if (NumTcs < 2 || NumTcs > 16 || Ncpt < 4 || Ncpt > 16) {
    LogLine ("%a TCS dump: implausible cfg, skipped", Label);
    return;
  }

  for (T = 0; T < NumTcs; T++) {
    LogLine (
      "%a TCS%u st 0x%08x ctrl 0x%08x en 0x%08x",
      Label, T,
      TCS_REG (T, 0x18), TCS_REG (T, 0x14), TCS_REG (T, 0x1C)
      );
    for (J = 0; J < Ncpt; J++) {
      Addr = TCS_CMD (T, J, 0x34);
      if (Addr == 0) {
        continue;
      }
      Data   = TCS_CMD (T, J, 0x38);
      Status = TCS_CMD (T, J, 0x3C);
      if (Addr >= 0x40E00 && Addr < 0x40E10) {
        LogLine ("%a  t%u c%u addr 0x%05x data 0x%08x st 0x%08x <== LDOC3", Label, T, J, Addr, Data, Status);
      } else if (Addr >= 0x42500 && Addr < 0x42510) {
        LogLine ("%a  t%u c%u addr 0x%05x data 0x%08x st 0x%08x <== LDOC8", Label, T, J, Addr, Data, Status);
      } else {
        LogLine ("%a  t%u c%u addr 0x%05x data 0x%08x st 0x%08x", Label, T, J, Addr, Data, Status);
      }
    }
  }
}

//
// ---------- FT3680 boot-ID check (verbatim port of the proven
// TscPwrDxe v1.5/v2.1 UefiTouchCheck and its helpers; TLMM
// bit-bang over GPIO 52-55, reset on GPIO 105, TLMM window at
// physical 0x0F100000) ----------
//

#define TSC_TLMM_BASE   0x0F100000
#define TSC_PIN_CTL(P)  ((volatile UINT32 *)(UINTN)(TSC_TLMM_BASE + (P) * 0x1000))
#define TSC_PIN_IO(P)   ((volatile UINT32 *)(UINTN)(TSC_TLMM_BASE + (P) * 0x1000 + 4))

STATIC
VOID
TscPinConfig (
  IN UINT32   Pin,
  IN BOOLEAN  Oe
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
  IN OUT UINT8    *Buf,
  IN     UINTN    Len,
  IN     BOOLEAN  Read
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
  IN UINT8  *Head,
  IN UINTN  HeadLen,
  IN UINT8  *Rx,
  IN UINTN  RxLen
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
  IN UINTN  Len
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
    LogLine (
      "%a bootid %u: raw %02X %02X %02X %02X calc %04X read %04X",
      Label, Attempt, Rx[0], Rx[1], Rx[2], Rx[3], Calc, Read
      );
    if (Calc == Read && Rx[0] != 0 && Rx[1] != 0) {
      LogLine ("%a: CHIP ALIVE id %02X %02X", Label, Rx[0], Rx[1]);
      return;
    }
  }
  LogLine ("%a: chip silent", Label);
}

//
// ---------- sampling ----------
//

STATIC
VOID
Sample (
  IN CHAR8  *Label
  )
{
  LogLine ("=== SAMPLE %a ===", Label);
  TcsDump (Label);
  UefiTouchCheck (Label);
}

STATIC
VOID
EFIAPI
EndOfDxeNotify (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  ProbeOpen ();
  Sample ("ENDOFDXE");
  gBS->CloseEvent (Event);
}

STATIC
VOID
EFIAPI
ReadyToBootNotify (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  ProbeOpen ();
  Sample ("READYTOBOOT");
  ProbeClose ();
  gBS->CloseEvent (Event);
}

EFI_STATUS
EFIAPI
RailProbeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_EVENT  Event;

  ProbeOpen ();
  LogLine ("RailProbe v1.0 (E5 base: no TscPwrDxe; read-only)");
  Sample ("ENTRY");

  if (EFI_ERROR (gBS->CreateEventEx (
                          EVT_NOTIFY_SIGNAL,
                          TPL_CALLBACK,
                          EndOfDxeNotify,
                          NULL,
                          &gEfiEndOfDxeEventGroupGuid,
                          &Event
                          ))) {
    LogLine ("RailProbe: EndOfDxe event registration FAILED");
  }
  if (EFI_ERROR (gBS->CreateEventEx (
                          EVT_NOTIFY_SIGNAL,
                          TPL_CALLBACK,
                          ReadyToBootNotify,
                          NULL,
                          &gEfiEventReadyToBootGuid,
                          &Event
                          ))) {
    LogLine ("RailProbe: ReadyToBoot event registration FAILED");
  }
  return EFI_SUCCESS;
}
