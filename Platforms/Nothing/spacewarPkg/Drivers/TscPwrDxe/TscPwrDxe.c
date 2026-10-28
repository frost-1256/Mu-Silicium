/** @file
  TscPwrDxe — FT3680 touch power for spacewar (production, v3.2).

  The FT3680 is powered from RPMh regulators pm8350c_l3 (2.8 V)
  and pm8350c_l8 (1.8 V). Under Windows nothing raises those
  rails, so this driver votes both LDOs on during DXE by
  programming the apps RSC directly (the RpmhDxe protocol path
  never completes a send on this platform; established by the
  v0.x-v1.x probes, see winboot/UEFI_TOUCH_POWER_PLAN.md).

  The vote body and timing are EXACTLY the proven v2.1 sequence
  (CI Run #42; Windows-side boot ID 56 62 confirmed): vote at
  driver entry — dispatch is Depex-gated on the Rpmh/CmdDb
  protocols, which keeps it late — and again at ReadyToBoot,
  per LDO voltage -> mode (HPM) -> enable, six commands in one
  ACTIVE TCS, CMD_ENABLE OR-ed in, completion polled on the
  DRV IRQ status, reclaim = CMD_ENABLE 0 + IRQ clear.

  v3.0/v3.1 changed the vote internals (CMD_WAIT_FOR_CMPL and
  IRQ_ENABLE writes, sanitize writes, CMD_STATUS polling,
  AMC-clearing reclaim) and BOTH hung the boot at the logo —
  so those "hardening" changes are deliberately NOT here.
  The only change vs v2.1 is the removal of the probe
  scaffolding (Say() 2 s stalls, ESP probe file, UEFI bit-bang
  touch check, NV variable): the boot is no longer slowed by
  diagnostics. Failures are DEBUG-only and never block boot.

  RSC layout (lahaina-family apps_rsc): RSC at 0x18200000,
  DRV2 at +0x20000, TCS blocks at DRV + 0xD00, TCS stride 672,
  command stride 20. Regulator offsets: ldoc3 CmdDb 0x40E00,
  ldoc8 0x42500; +0 voltage, +4 enable, +8 mode.
**/

#include <Uefi.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Guid/EventGroup.h>
#include "EFIRpmh.h"
#include "EFICmdDb.h"
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/LoadedImage.h>

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
  VOID
  )
{
  UINT32  Cfg, NumTcs, Ncpt, T, J, Ctrl, IrqSt, Tries;
  UINT32  CmdAddr[6];
  UINT32  CmdData[6];
  UINT32  CmdStatus[6];

  CmdAddr[0] = 0x40E00;  CmdData[0] = 2800;  /* ldoc3 voltage mV */
  CmdAddr[1] = 0x40E08;  CmdData[1] = 7;     /* ldoc3 mode HPM */
  CmdAddr[2] = 0x40E04;  CmdData[2] = 1;     /* ldoc3 enable */
  CmdAddr[3] = 0x42500;  CmdData[3] = 1800;  /* ldoc8 voltage mV */
  CmdAddr[4] = 0x42508;  CmdData[4] = 7;     /* ldoc8 mode HPM */
  CmdAddr[5] = 0x42504;  CmdData[5] = 1;     /* ldoc8 enable */

  Cfg = RSC_REG32 (RSC_DRV_BASE + 0x0C);
  NumTcs = (Cfg >> 12) & 0x3F;   /* DRV2 field of DRV_PRNT_CHLD_CONFIG */
  Ncpt = (Cfg >> 27) & 0x1F;
  if (NumTcs < 2 || NumTcs > 16 || Ncpt < 4 || Ncpt > 16) {
    DEBUG ((DEBUG_ERROR, "TscPwr: implausible RSC cfg 0x%x, no vote\n",
            (UINTN)Cfg));
    return;
  }

  for (T = 0; T < 2; T++) {
    if (TCS_REG (T, 0x18) == 0) {
      continue;   /* TCS busy (STATUS is zero while busy) */
    }

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
    for (J = 0; J < 6; J++) {
      CmdStatus[J] = TCS_CMD (T, J, 0x3C);
    }

    /* reclaim like tcs_tx_done */
    TCS_REG (T, 0x1C) = 0;
    RSC_REG32 (RSC_TCS_BASE + 0x08) = (1u << T);
    DEBUG ((DEBUG_ERROR,
      "TscPwr: vote fired on tcs%u irq=0x%x st=%x %x %x %x %x %x\n",
      (UINTN)T, (UINTN)IrqSt,
      (UINTN)CmdStatus[0], (UINTN)CmdStatus[1], (UINTN)CmdStatus[2],
      (UINTN)CmdStatus[3], (UINTN)CmdStatus[4], (UINTN)CmdStatus[5]));
    return;
  }

  DEBUG ((DEBUG_ERROR, "TscPwr: no idle ACTIVE TCS, no vote\n"));
}

STATIC
VOID
EFIAPI
VoteNotify (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  RscVote ();
  gBS->CloseEvent (Event);
}

EFI_STATUS
EFIAPI
TscPwrDxeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_EVENT  Event;

  RscVote ();
  return gBS->CreateEventEx (
                EVT_NOTIFY_SIGNAL,
                TPL_CALLBACK,
                VoteNotify,
                NULL,
                &gEfiEventReadyToBootGuid,
                &Event
                );
}
