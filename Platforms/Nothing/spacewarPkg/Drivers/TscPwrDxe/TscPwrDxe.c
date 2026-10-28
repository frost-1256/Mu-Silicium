/** @file
  TscPwrDxe — FT3680 touch power for spacewar (production, v3.0).

  The FT3680 touch controller is powered from RPMh regulators
  pm8350c_l3 (2.8 V, touch VDD) and pm8350c_l8 (1.8 V, IOVDD).
  Under Windows nothing raises those rails, so this driver votes
  both LDOs on (voltage, HPM mode, enable) by programming the
  apps RSC directly — the RpmhDxe protocol path enqueues the
  requests but its send chain never completes on this platform
  (established by the v0.x-v1.x probes; see
  winboot/UEFI_TOUCH_POWER_PLAN.md).

  The vote runs twice: once at DXE dispatch and once at
  ReadyToBoot. It is idempotent (same values re-asserted) and
  every failure path falls through silently: this driver must
  never block or slow the boot. No console output; results go
  to DEBUG only.

  RSC protocol follows mainline drivers/soc/qcom/rpmh-rsc.c:
  apps RSC at 0x18200000, DRV2 at +0x20000, TCS blocks at
  DRV + 0xD00, TCS stride 672, command stride 20. Lahaina-family
  tcs-config puts the ACTIVE TCSes first (TCS 0 and 1).
  Regulator register offsets follow the vendor rpmh-regulator.c:
  VRM address = CmdDb base + 4 * index {VOLTAGE 0, ENABLE 1,
  MODE 2, HEADROOM 3}; ldoc3 CmdDb address 0x40E00, ldoc8
  0x42500 (read from CmdDb at runtime by the v0.9 probe).
**/

#include <Uefi.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseLib.h>
#include <Guid/EventGroup.h>

#define RSC_DRV_BASE    0x18220000
#define RSC_TCS_BASE    (RSC_DRV_BASE + 0xD00)
#define RSC_TCS_STRIDE  672
#define RSC_CMD_STRIDE  20
#define RSC_REG32(A)    (*(volatile UINT32 *)(UINTN)(A))
#define TCS_REG(T, R)   RSC_REG32 (RSC_TCS_BASE + RSC_TCS_STRIDE * (T) + (R))
#define TCS_CMD(T, J, R) \
  RSC_REG32 (RSC_TCS_BASE + RSC_TCS_STRIDE * (T) + (R) + RSC_CMD_STRIDE * (J))

#define RSC_IRQ_ENABLE        0x00
#define RSC_IRQ_STATUS        0x04
#define RSC_IRQ_CLEAR         0x08
#define TCS_CMD_WAIT_FOR_CMPL 0x10
#define TCS_CONTROL           0x14
#define TCS_STATUS            0x18
#define TCS_CMD_ENABLE        0x1C
#define TCS_CMD_MSGID         0x30
#define TCS_CMD_ADDR          0x34
#define TCS_CMD_DATA          0x38
#define TCS_CMD_STATUS        0x3C

#define CMD_STATUS_DONE       0x10100   /* ISSUED | COMPL */
#define VOTE_CMD_COUNT        6
#define VOTE_CMD_MASK         0x3F

//
// Write a TCS register and poll until the value reads back
// (the AMC trigger protocol requires these "sync" writes).
// Returns FALSE if the value never lands — the caller must
// not claim the vote was sent in that case.
//
STATIC
BOOLEAN
RscSyncWrite (
  IN UINTN   Addr,
  IN UINT32  Value
  )
{
  UINT32  Tries;

  RSC_REG32 (Addr) = Value;
  for (Tries = 0; Tries < 10000; Tries++) {
    if (RSC_REG32 (Addr) == Value) {
      return TRUE;
    }
    gBS->Stall (10);
  }
  return FALSE;
}

//
// Clear the AMC trigger/enable bits, like the false branch of
// __tcs_set_trigger (used when reclaiming a TCS).
//
STATIC
VOID
RscClearTrigger (
  IN UINT32  T
  )
{
  UINT32  Ctrl;

  Ctrl = TCS_REG (T, TCS_CONTROL);
  (VOID)RscSyncWrite (RSC_TCS_BASE + RSC_TCS_STRIDE * T + TCS_CONTROL,
                      Ctrl & ~(1u << 24));
  Ctrl = TCS_REG (T, TCS_CONTROL);
  (VOID)RscSyncWrite (RSC_TCS_BASE + RSC_TCS_STRIDE * T + TCS_CONTROL,
                      Ctrl & ~(1u << 16));
}

//
// Vote ldoc3 (2800 mV) and ldoc8 (1800 mV) on: for each LDO,
// voltage, mode = HPM (7), enable — one ACTIVE TCS, six
// commands, wait-for-completion semantics.
//
STATIC
VOID
RscVote (
  VOID
  )
{
  UINT32  Cfg, NumTcs, Ncpt, T, J, Ctrl, IrqSt, Tries;
  UINT32  CmdAddr[VOTE_CMD_COUNT];
  UINT32  CmdData[VOTE_CMD_COUNT];
  UINT32  CmdStatus[VOTE_CMD_COUNT];
  BOOLEAN Done;

  CmdAddr[0] = 0x40E00;  CmdData[0] = 2800;  /* ldoc3 voltage mV */
  CmdAddr[1] = 0x40E08;  CmdData[1] = 7;     /* ldoc3 mode HPM */
  CmdAddr[2] = 0x40E04;  CmdData[2] = 1;     /* ldoc3 enable */
  CmdAddr[3] = 0x42500;  CmdData[3] = 1800;  /* ldoc8 voltage mV */
  CmdAddr[4] = 0x42508;  CmdData[4] = 7;     /* ldoc8 mode HPM */
  CmdAddr[5] = 0x42504;  CmdData[5] = 1;     /* ldoc8 enable */

  DEBUG ((DEBUG_ERROR, "TscPwr: RSC id 0x%x\n",
          (UINTN)RSC_REG32 (RSC_DRV_BASE)));

  Cfg    = RSC_REG32 (RSC_DRV_BASE + 0x0C);
  NumTcs = (Cfg >> 12) & 0x3F;   /* DRV2 field of DRV_PRNT_CHLD_CONFIG */
  Ncpt   = (Cfg >> 27) & 0x1F;
  if (NumTcs < 2 || NumTcs > 16 || Ncpt < VOTE_CMD_COUNT || Ncpt > 16) {
    DEBUG ((DEBUG_ERROR, "TscPwr: implausible RSC cfg 0x%x, no vote\n",
            (UINTN)Cfg));
    return;
  }

  for (T = 0; T < 2; T++) {
    if (TCS_REG (T, TCS_STATUS) == 0) {
      continue;   /* TCS busy (STATUS is zero while busy) */
    }

    /* Drop any stale completion bit and make sure this TCS can
       signal completion before we trigger (adversarial-review F1). */
    RSC_REG32 (RSC_TCS_BASE + RSC_IRQ_CLEAR) = (1u << T);
    RSC_REG32 (RSC_TCS_BASE + RSC_IRQ_ENABLE) |= (1u << T);

    /* Start from a clean slate: no stale commands can be
       re-issued and no stale wait bits survive (review F3). */
    if (!RscSyncWrite (RSC_TCS_BASE + RSC_TCS_STRIDE * T + TCS_CMD_ENABLE, 0) ||
        !RscSyncWrite (RSC_TCS_BASE + RSC_TCS_STRIDE * T + TCS_CMD_WAIT_FOR_CMPL,
                       0)) {
      DEBUG ((DEBUG_ERROR, "TscPwr: tcs%u sanitize failed, no vote\n",
              (UINTN)T));
      return;
    }

    for (J = 0; J < VOTE_CMD_COUNT; J++) {
      TCS_CMD (T, J, TCS_CMD_MSGID) = 8 | (1u << 8) | (1u << 16);
      TCS_CMD (T, J, TCS_CMD_ADDR)  = CmdAddr[J];
      TCS_CMD (T, J, TCS_CMD_DATA)  = CmdData[J];
    }
    MemoryFence ();
    TCS_REG (T, TCS_CMD_WAIT_FOR_CMPL) = VOTE_CMD_MASK;
    TCS_REG (T, TCS_CMD_ENABLE)        = VOTE_CMD_MASK;
    MemoryFence ();

    /* __tcs_set_trigger: clear trigger, clear enable (both
       sync), set enable (sync), then set trigger (plain). */
    Ctrl = TCS_REG (T, TCS_CONTROL);
    if (!RscSyncWrite (RSC_TCS_BASE + RSC_TCS_STRIDE * T + TCS_CONTROL,
                       Ctrl & ~(1u << 24))) {
      goto trigger_fail;
    }
    Ctrl = TCS_REG (T, TCS_CONTROL);
    if (!RscSyncWrite (RSC_TCS_BASE + RSC_TCS_STRIDE * T + TCS_CONTROL,
                       Ctrl & ~(1u << 16))) {
      goto trigger_fail;
    }
    if (!RscSyncWrite (RSC_TCS_BASE + RSC_TCS_STRIDE * T + TCS_CONTROL,
                       (1u << 16))) {
      goto trigger_fail;
    }
    TCS_REG (T, TCS_CONTROL) = (1u << 16) | (1u << 24);

    /* Completion: poll the per-command status until every
       command reports ISSUED|COMPL (review F1/F2). Snapshot
       first, reclaim immediately, log afterwards (review F5). */
    Done = FALSE;
    IrqSt = 0;
    for (J = 0; J < VOTE_CMD_COUNT; J++) {
      CmdStatus[J] = 0;
    }
    for (Tries = 0; Tries < 2000; Tries++) {
      Done = TRUE;
      for (J = 0; J < VOTE_CMD_COUNT; J++) {
        CmdStatus[J] = TCS_CMD (T, J, TCS_CMD_STATUS);
        if ((CmdStatus[J] & CMD_STATUS_DONE) != CMD_STATUS_DONE) {
          Done = FALSE;
        }
      }
      IrqSt = RSC_REG32 (RSC_TCS_BASE + RSC_IRQ_STATUS);
      if (Done) {
        break;
      }
      gBS->Stall (100);
    }

    /* Reclaim like tcs_tx_done, plus AMC bit cleanup (F7). */
    RscClearTrigger (T);
    TCS_REG (T, TCS_CMD_ENABLE) = 0;
    RSC_REG32 (RSC_TCS_BASE + RSC_IRQ_CLEAR) = (1u << T);

    DEBUG ((DEBUG_ERROR,
      "TscPwr: vote on tcs%u %a irq=0x%x st=%x %x %x %x %x %x\n",
      (UINTN)T, Done ? "complete" : "TIMEOUT", (UINTN)IrqSt,
      (UINTN)CmdStatus[0], (UINTN)CmdStatus[1], (UINTN)CmdStatus[2],
      (UINTN)CmdStatus[3], (UINTN)CmdStatus[4], (UINTN)CmdStatus[5]));
    return;

trigger_fail:
    DEBUG ((DEBUG_ERROR, "TscPwr: tcs%u control sync failed, no vote\n",
            (UINTN)T));
    TCS_REG (T, TCS_CMD_ENABLE) = 0;
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
