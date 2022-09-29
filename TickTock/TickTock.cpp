#include <algorithm>
#include <array>
#include <format>
#include <iostream>
#include <map>
#include <stdio.h>
#include <string>
#include <tchar.h>
#include <vector>
#include <Windows.h>
#include <winternl.h>

#include <DbgHelp.h>
#include <psapi.h>
#include <tlhelp32.h>

//
// From Ntdef.h.
//
// Treat anything not STATUS_SUCCESS as an error.
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) == 0)
#define STATUS_SUCCESS   ((NTSTATUS)0x00000000L)

//
// Scanner config options.
//
bool bShowDebugOutput = false;
std::string defaultSymbolPath = "C:\\SYMBOLS\\;";

//
// Run time linking for NtQueryInformationProcess.
//
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    IN  HANDLE ProcessHandle,
    IN  PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN  ULONG ProcessInformationLength,
    OUT PULONG ReturnLength    OPTIONAL
    );
pNtQueryInformationProcess myNtQueryInformationProcess;

//
// Required threadpool symbols.
//
using ptr = intptr_t;
ptr pTppTimerpCleanupGroupMemberVFuncs = NULL;
ptr pRtlpTpTimerFinalizationCallback = NULL;
ptr pRtlpTpTimerCallback = NULL;
ptr pTppTimerpTaskVFuncs = NULL;
ptr pRtlCreateTimer = NULL;

//
// Threadpool heap allocation constants.
//
// RtlCreateTimer: Heap = RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, 0i64, 0x60i64);
// NB In both cases we dont need to retrieve full alloc to find what we need.
int rtlCreateTimerHeapAllocMinSizeToRead = 15;
// TpAllocTimer: Heap = RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, (TppHeapTag + 0x100000) | 8u, 0x168i64);
int tpAllocTimerHeapAllocMinSizeToRead = 25;

//
// Templated wrappers around ReadProcessMemory.
//
template<typename T>
T readProcessMemory(HANDLE hProcess, LPVOID targetAddress)
{
    T returnValue;
    (void)ReadProcessMemory(hProcess, targetAddress, &returnValue, sizeof(T), NULL);
    return returnValue;
}

template<typename T>
void readProcessMemory(HANDLE hProcess, PVOID targetAddress, SIZE_T elementsToRead, std::vector<T> &buffer)
{
    (void)ReadProcessMemory(hProcess, targetAddress, buffer.data(), elementsToRead * sizeof(T), NULL);
    return;
}

//
// Takes a symbol name and finds its address.
//
NTSTATUS ResolveSymbolFromName(HANDLE hProcess, PCSTR symbolName, ptr &address)
{
    NTSTATUS status = STATUS_SUCCESS;

    // [0] Prepare buffer for SYMBOL_INFO
    ULONG64 buffer[(sizeof(SYMBOL_INFO) +
        MAX_SYM_NAME * sizeof(TCHAR) +
        sizeof(ULONG64) - 1) /
        sizeof(ULONG64)];
    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;

    // [1] Resolve symbol name
    if (!SymFromName(hProcess, symbolName, pSymbol))
    {
        std::cout << "[-] SymFromName returned an error: " << GetLastError() << "for symbol name: " << symbolName << "\n";
        status = STATUS_ASSERTION_FAILURE;
        goto Cleanup;
    }
    address = pSymbol->Address;

Cleanup:
    return status;
}

//
// Takes an address and resolves its corresponding symbol.
//
NTSTATUS ResolveSymbolFromAddress(HANDLE hProcess, ptr targetAddress, std::string &symbol)
{
    NTSTATUS status = STATUS_SUCCESS;

    // [0] Prepare buffer for SYMBOL_INFO
    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;

    // [1] Resolve address
    if (!SymFromAddr(hProcess, targetAddress, NULL, pSymbol))
    {
        printf("[-] Failed to resolve callback function - SymFromAddr returned error : %d\n", GetLastError());
        status = STATUS_ASSERTION_FAILURE;
        goto Cleanup;
    }
    symbol = pSymbol->Name;

Cleanup:
    return status;
}

//
// Performs scanner initilisation via resolving necessary thread pool pointers and required functions.
//
NTSTATUS InitialiseScanner()
{
    NTSTATUS status = STATUS_SUCCESS;

    // [1] Initialise symbols
    if (!SymInitialize(GetCurrentProcess(), defaultSymbolPath.c_str(), TRUE))
    {
        std::cout << "[!] SymInitialze returned an error: " << GetLastError() << "\n";
        status = STATUS_ASSERTION_FAILURE;
        goto Cleanup;
    }

    // [2] Resolve required thread pool symbols
    if (!NT_SUCCESS(ResolveSymbolFromName(GetCurrentProcess(), "ntdll!TppTimerpCleanupGroupMemberVFuncs", pTppTimerpCleanupGroupMemberVFuncs)))
    {
        std::cout << "[!] Failed to resolve required threadpool symbols\n";
        status = STATUS_ASSERTION_FAILURE;
        goto Cleanup;
    }

    if (!NT_SUCCESS(ResolveSymbolFromName(GetCurrentProcess(), "ntdll!RtlpTpTimerFinalizationCallback", pRtlpTpTimerFinalizationCallback)))
    {
        std::cout << "[!] Failed to resolve required threadpool symbols\n";
        status = STATUS_ASSERTION_FAILURE;
        goto Cleanup;
    }

    if (!NT_SUCCESS(ResolveSymbolFromName(GetCurrentProcess(), "ntdll!RtlpTpTimerCallback", pRtlpTpTimerCallback)))
    {
        std::cout << "[!] Failed to resolve required threadpool symbols\n";
        status = STATUS_ASSERTION_FAILURE;
        goto Cleanup;
    }

    if (!NT_SUCCESS(ResolveSymbolFromName(GetCurrentProcess(), "ntdll!TppTimerpTaskVFuncs", pTppTimerpTaskVFuncs)))
    {
        std::cout << "[!] Failed to resolve required threadpool symbols\n";
        status = STATUS_ASSERTION_FAILURE;
        goto Cleanup;
    }

    // [3] Lastly, resolve NtQueryInformationProcess
    myNtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll.dll"),
        "NtQueryInformationProcess");
    if (NULL == myNtQueryInformationProcess)
    {
        std::cout << "[!] Failed to resolve NtQueryInformationProcess\n";
        status = STATUS_ASSERTION_FAILURE;
        goto Cleanup;
    }

Cleanup:
    return status;
}

//
// Parses the remote process PEB to find all the target process heap allocations.
//
NTSTATUS FindProcessHeaps(HANDLE hProcess, std::vector<MEMORY_BASIC_INFORMATION> &processHeapVector)
{
    NTSTATUS status = STATUS_SUCCESS;
    PROCESS_BASIC_INFORMATION ProcessInformation = {};
    PEB peb = {};
    PVOID processHeapsArrayPtr = NULL;
    std::vector<PVOID> heapPtrs;
    PVOID pebHeapEntry = 0;
    uint32_t numberOfHeaps = 0;

    // [0] Sanity check handle
    if (hProcess == INVALID_HANDLE_VALUE)
    {
        status = STATUS_ASSERTION_FAILURE;
        goto Cleanup;
    }

    // [1] Locate remote PEB and read it into memory
    status = myNtQueryInformationProcess(hProcess, ProcessBasicInformation, &ProcessInformation, sizeof(ProcessInformation), NULL);
    if (status != 0)
    {
        status = STATUS_ASSERTION_FAILURE;
        goto Cleanup;
    }
    peb = readProcessMemory<PEB>(hProcess, ProcessInformation.PebBaseAddress);

    // [2] From the peb, retrieve the number of heaps and pointer to the process heaps
    // + 0x0e8 NumberOfHeaps    : 3
    // + 0x0ec MaximumNumberOfHeaps : 0x10
    // + 0x0f0 ProcessHeaps : 0x00007ffe`445b9d40  -> 0x00000196`26510000 Void
    // Ref: https://github.com/odzhan/injection/blob/master/ntlib/ntddk.h#L3164-L3166
    pebHeapEntry = peb.Reserved9[16];
    numberOfHeaps = (uint64_t)pebHeapEntry & 0xFFFFFFFF;
    processHeapsArrayPtr = (PVOID)peb.Reserved9[17];
    heapPtrs.resize(numberOfHeaps);
    // Read the process heaps array (which contains ptrs to heap locations).
    readProcessMemory<PVOID>(hProcess, processHeapsArrayPtr, numberOfHeaps, heapPtrs);

    // [3] Loop round and record the region size.
    for (const auto& heapPtr : heapPtrs)
    {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQueryEx(hProcess, (PVOID)heapPtr, &mbi, sizeof(mbi)))
        {
            status = STATUS_ASSERTION_FAILURE;
            goto Cleanup;
        }
        processHeapVector.push_back(mbi);
    }

Cleanup:
    return status;
}

//
// Converts an intptr to vector of bytes.
//
void IntToVectorOfBytes(ptr originalValue, std::vector<uint8_t> &byteVector)
{
    byteVector.push_back(originalValue & 0xFF);
    byteVector.push_back((originalValue >> 8) & 0xFF);
    byteVector.push_back((originalValue >> 16) & 0xFF);
    byteVector.push_back((originalValue >> 24) & 0xFF);
    byteVector.push_back((originalValue >> 32) & 0xFF);
    byteVector.push_back((originalValue >> 40) & 0xFF);
    byteVector.push_back((originalValue >> 48) & 0xFF);
    byteVector.push_back((originalValue >> 56) & 0xFF);
    return;
}

//
// Takes an address and retrieves the base name of the specified module.
//
NTSTATUS GetModuleBaseNameWrapper(HANDLE hProcess, PVOID targetAddress, std::string& moduleName)
{
    NTSTATUS status = STATUS_SUCCESS;
    char szModuleBaseName[MAX_PATH];

    if (GetModuleBaseNameA(hProcess, (HMODULE)targetAddress, szModuleBaseName, sizeof(szModuleBaseName)))
    {
         moduleName = szModuleBaseName;
    }
    else
    {
        printf("[-] GetModuleBaseName returned error : %d\n", GetLastError());
        status = STATUS_ASSERTION_FAILURE;
    }

    return status;
}

//
// Takes an address and resolves its corresponding symbol
// via performing manual resolution.
//
NTSTATUS GetBasicSymbolFromAddress(HANDLE hProcess, ptr targetAddress, std::string &symbol)
{
    NTSTATUS status = STATUS_SUCCESS;
    MEMORY_BASIC_INFORMATION mbi = {};
    std::string moduleName;

    // [0] Sanity check incoming targetAddress.
    if (NULL == targetAddress)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    // [1] Query pages at target addr.
    if (!VirtualQueryEx(hProcess, (PVOID)targetAddress, &mbi, sizeof(mbi)))
    {
        status = STATUS_ASSERTION_FAILURE;
        goto Cleanup;
    }

    // [2] Try and resolve module at addr.
    if (!NT_SUCCESS(GetModuleBaseNameWrapper(hProcess, mbi.AllocationBase, moduleName)))
    {
        status = STATUS_ASSERTION_FAILURE;
        goto Cleanup;
    }

    // [3] Calculate offset from allocation base and return as basemodule + offset (e.g. winlogon+0x63590).
    symbol = moduleName + "+0x" + std::format("{:x}", (targetAddress - (ptr)mbi.AllocationBase));

Cleanup:
    return status;
}

//
// Rough heuristic to sanity check whether a timer callback ptr looks valid.
//
// https://www.unknowncheats.me/forum/c-and-c-/304873-checking-valid-pointer.html
bool IsInvalidPtr(intptr_t ptr)
{
    static SYSTEM_INFO si = {};
    if (nullptr == si.lpMinimumApplicationAddress)
    {
        GetSystemInfo(&si);
    }

    return ((ptr < (intptr_t)si.lpMinimumApplicationAddress || ptr > (intptr_t)si.lpMaximumApplicationAddress));
}

//
// Scans a remote processes heap memory in order to find timer-queue timers.
//
// RtlCreateTimer creates two heap allocations:
//   1) One itself via directly calling RtlAllocateHeap
//   2) One indirectly via calling TpAllocTimer
// This function looks for a common pattern of pointers that are set on the
// *second* block of memory (via TpAllocTimer). This block of memory also contains a ptr to
// the first allocation, which contains the actual callback and parameter passed
// in the call to CreateTimerQueueTimer. By following this pointer we can
// identify and enumerate timer-queue timers.
void ScanHeapMemory(HANDLE hProcess, std::vector<MEMORY_BASIC_INFORMATION> &processHeapVector)
{
    bool printDelimiter = true;

    // [0] Convert target ptr to vector of bytes first so we can use STL search algorithm.
    std::vector<uint8_t> pTppTimerpCleanupGroupMemberVFuncsBytes;
    IntToVectorOfBytes(pTppTimerpCleanupGroupMemberVFuncs, pTppTimerpCleanupGroupMemberVFuncsBytes);

    // [1] Loop over each heap.
    for (auto heap : processHeapVector)
    {
        // [2] Read in heap memory.
        std::vector<uint8_t> heapMemory(heap.RegionSize);
        readProcessMemory<uint8_t>(hProcess, heap.AllocationBase, heap.RegionSize, heapMemory);

        // [2] Scan heap memory for a pointer to ntdll!TppTimerpCleanupGroupMemberVFuncs.
        auto heapMemoryIt = begin(heapMemory);
        while (true)
        {
            heapMemoryIt = search(heapMemoryIt, end(heapMemory), begin(pTppTimerpCleanupGroupMemberVFuncsBytes), end(pTppTimerpCleanupGroupMemberVFuncsBytes));

            // If we didn't find anything skip to next heap.
            if (heapMemoryIt == heapMemory.end())
            {
                break;
            }

            // Record virtual address for debugging purposes in case we have a match.
            PVOID virtualAddrOfTimer = (PCHAR)heap.AllocationBase + (heapMemoryIt - heapMemory.begin());

            // [3] If we have found our target pointer, we *know* the expected memory layout
            // from this point on. Hence, for simplicity, copy over data to new vector of
            // intptrs so we can quickly check other offsets for expected ptr values.

            // [3.1] First work out current index and convert to ptr.
            PINT_PTR vectorStart = (PINT_PTR)heapMemory.data() + ((heapMemoryIt - heapMemory.begin()) / sizeof(intptr_t));

            // [3.2] Advance iterator so we keep scanning remaining
            // heap memory if we fail to find a timer.
            std::advance(heapMemoryIt, 1);

            // [3.3] Create new vector of intptrs from current index.
            // Sanity check our end ptr doesn't overrun vector data.
            PINT_PTR vectorEnd = vectorStart + tpAllocTimerHeapAllocMinSizeToRead;
            PINT_PTR upperBound = (PINT_PTR)&(*(heapMemory.end() - sizeof(intptr_t)));
            if (vectorEnd > upperBound)
            {
                continue;
            }
            std::vector<ptr> tpAllocTimerHeapAllocData(vectorStart, vectorEnd);

            // If we have a timer, heap memory allocated by TpAllocTimer
            // will look like this:
            // 0:000 > dps 0000021c4e003610 L 170
            // 0000021c`4e003610  00000000`00000001 (Bool indicicating if it has yet to fire?)
            // 0000021c`4e003618  00007ffe`4456c1e8 ntdll!TppTimerpCleanupGroupMemberVFuncs  <-- Current index
            // 0000021c`4e003620  00000000`00000000
            // 0000021c`4e003628  00000000`00000000
            // 0000021c`4e003630  00007ffe`44458820 ntdll!RtlpTpTimerFinalizationCallback [4]
            // 0000021c`4e003638  0000021c`4e003638
            // 0000021c`4e003640  0000021c`4e003638
            // 0000021c`4e003648  00000000`00000000
            // 0000021c`4e003650  00000000`00000000
            // 0000021c`4e003658  00000000`00000000
            // 0000021c`4e003660  00007ffe`444c60a0 ntdll!RtlpTpTimerCallback [5]
            // 0000021c`4e003668  0000021c`4dfff290 Ptr to first allocation by RtlCreateTimer which contains the target callback and parameter. [6]
            // 0000021c`4e003670  00000000`00000000
            // 0000021c`4e003678  00000000`00000000
            // 0000021c`4e003680  00000000`00000000
            // 0000021c`4e003688  00000000`00000000
            // 0000021c`4e003690  00000000`00000000
            // 0000021c`4e003698  00000000`00000000
            // 0000021c`4e0036a0  0000021c`4e005120
            // 0000021c`4e0036a8  0000021c`4e005170
            // 0000021c`4e0036b0  0000021c`4e005170
            // 0000021c`4e0036b8  00000000`00000002
            // 0000021c`4e0036c0  00007ffe`44459ee0 ntdll!RtlCreateTimer + 0x190
            // 0000021c`4e0036c8  00000000`00000000
            // 0000021c`4e0036d0  00000000`00000001
            // 0000021c`4e0036d8  00007ffe`4456c138 ntdll!TppTimerpTaskVFuncs [7]
            // 0000021c`4e0036e0  00000001`00000000
            // 0000021c`4e0036e8  00000000`00000000
            // 0000021c`4e0036f0  00000000`00000000

            // [4] Look ahead for pointer to ntdll!RtlpTpTimerFinalizationCallback.
            auto tpAllocTimerHeapAllocDataIt = tpAllocTimerHeapAllocData.begin();
            std::advance(tpAllocTimerHeapAllocDataIt, 3);
            if (pRtlpTpTimerFinalizationCallback != *tpAllocTimerHeapAllocDataIt)
            {
                continue;
            }

            // [5] Look ahead for pointer to ntdll!RtlpTpTimerCallback.
            std::advance(tpAllocTimerHeapAllocDataIt, 6);
            if (pRtlpTpTimerCallback != *tpAllocTimerHeapAllocDataIt)
            {
                continue;
            }

            // [6] Record ptr to initial RtlCreateTimer heap allocation.
            // The ptr after ntdll!RtlpTpTimerCallback points to the initial
            // heap allocation performed by RtlCreateTimer. This contains the
            // target callback and parameter.
            std::advance(tpAllocTimerHeapAllocDataIt, 1);
            auto RtlCreateTimerHeapDataPtr = *tpAllocTimerHeapAllocDataIt;

            // [7] Look ahead for pointer to ntdll!TppTimerpTaskVFuncs.
            std::advance(tpAllocTimerHeapAllocDataIt, 14);
            if (pTppTimerpTaskVFuncs != *tpAllocTimerHeapAllocDataIt)
            {
                continue;
            }

            // For debugging purposes. If you want very verbose output move this up to L374
            // to show heap output every time we find a ptr to ntdll!TppTimerpCleanupGroupMemberVFuncs.
            if (bShowDebugOutput)
            {
                std::cout << "[+] TpAllocTimer initial heap allocation memory layout:\n";
                std::cout << "REFERENCE: ntdll!TppTimerpCleanupGroupMemberVFuncs --> 0x" << std::hex << (PVOID)pTppTimerpCleanupGroupMemberVFuncs << "\n";
                std::cout << "REFERENCE: ntdll!RtlpTpTimerFinalizationCallback --> 0x" << std::hex << (PVOID)pRtlpTpTimerFinalizationCallback << "\n";
                std::cout << "REFERENCE: ntdll!RtlpTpTimerCallback --> 0x" << std::hex << (PVOID)pRtlpTpTimerCallback << "\n";
                std::cout << "REFERENCE: ntdll!TppTimerpTaskVFuncs --> 0x" << std::hex << (PVOID)pTppTimerpTaskVFuncs << "\n";

                for (auto entry : tpAllocTimerHeapAllocData)
                {
                    std::cout << "    --> 0x" << std::hex << (PVOID)entry << "\n";
                }
            }

            // [8] At this point it is *highly* likely we have identified a timer-queue timer struct.
            // The ptr captured in [6] points to the initial heap allocation performed
            // by RtlCreateTimer, which will store the timer callback and argument.
            std::vector<ptr> rtlCreateTimerHeapAllocData(rtlCreateTimerHeapAllocMinSizeToRead);
            readProcessMemory<ptr>(hProcess, (PVOID)RtlCreateTimerHeapDataPtr, rtlCreateTimerHeapAllocMinSizeToRead, rtlCreateTimerHeapAllocData);

            // If we have a timer, heap memory will look like this:
            // 0:000 > dps @rdi
            // 0000021c`88ef3810  0000021c`88ee4c80
            // 0000021c`88ef3818  0000021c`88eef800
            // 0000021c`88ef3820  00000000`00000000
            // 0000021c`88ef3828  dddddddd`00000020
            // 0000021c`88ef3830  00007ffa`fbfcd590 ntdll!NtContinue (Callback)
            // 0000021c`88ef3838  0000008f`268fd490 ptr to CONTEXT structure (Param)
            // 0000021c`88ef3840  dddddddd`00000000 Lower bits/DWORD here are set to 0 on init but this can sometimes be set to other values (e.g. 0x2)
            // 0000021c`88ef3848  0000021c`88ee3600
            // 0000021c`88ef3850  00000000`00000000
            // 0000021c`88ef3858  00000000`00000000 This QWORD will be set to 0 [10.2]
            // 0000021c`88ef3860  00000000`00000000 This QWORD will be set to 0 [10.3]
            // 0000021c`88ef3868  00000000`dddddd00
            // 0000021c`88ef3870  dddddddd`dddddddd
            // 0000021c`88ef3878  dddddddd`dddddddd
            // 0000021c`88ef3880  dddddddd`dddddddd
            // 0000021c`88ef3888  1000520a`1e93ad46

            // For debugging purposes.
            if (bShowDebugOutput)
            {
                std::cout << "[+] RtlCreateTimer initial allocation memory layout:\n";
                int i = 0;
                for (auto entry : rtlCreateTimerHeapAllocData)
                {
                    if (i == 4)
                    {
                        std::cout << "    --> 0x" << std::hex << (PVOID)entry << " (CALLBACK)\n";
                    }
                    else if (i == 5)
                    {
                        std::cout << "    --> 0x" << std::hex << (PVOID)entry << " (PARAM)\n";
                    }
                    else
                    {
                        std::cout << "    --> 0x" << std::hex << (PVOID)entry << "\n";
                    }
                    i++;
                }
            }

            // [9] Retrieve the target callback and parameter.
            auto rtlCreateTimerHeapAllocIt = rtlCreateTimerHeapAllocData.begin();
            std::advance(rtlCreateTimerHeapAllocIt, 4);
            auto timerCallback = *rtlCreateTimerHeapAllocIt;
            std::advance(rtlCreateTimerHeapAllocIt, 1);
            auto timerParameter = *rtlCreateTimerHeapAllocIt;

            // [10] Perform basic sanity checking of this heap structure + callback.
            // NB These are rough heuristics and are bound to fail in some use cases,
            // especially as heap memory changes and timers are deallocated.
            {
                // [10.1] Sanity check timer callback actually points to something in memory
                if (IsInvalidPtr(timerCallback))
                {
                    if (bShowDebugOutput)
                    {
                        std::cout << "[-] Invalid timer callback ptr: 0x" << std::hex << timerCallback << "\n";
                    }
                    continue;
                }

                // [10.2] *(_QWORD *)(startOfHeapAlloc + 0x48) = 0i64;
                std::advance(rtlCreateTimerHeapAllocIt, 4);
                if (0 != *rtlCreateTimerHeapAllocIt)
                {
                    continue;
                }

                // [10.3] *(_QWORD *)(startOfHeapAlloc + 0x50) = 0i64;
                std::advance(rtlCreateTimerHeapAllocIt, 1);
                if (0 != *rtlCreateTimerHeapAllocIt)
                {
                    continue;
                }
            }

            // [11] If we got this far we have a timer-queue timer so print out results.
            if (printDelimiter)
            {
                std::cout << "==========================================================================\n";
                printDelimiter = false;
            }
            std::cout << "[+] Found timer-queue timer:\n";
            std::cout << "[+] Virtual address of ntdll!TppTimerpCleanupGroupMemberVFuncs ptr found on the heap: 0x" << std::hex << virtualAddrOfTimer << "\n";
            std::cout << "[+] Timer callback: 0x" << std::hex << timerCallback << "\n";
            std::cout << "[+] Timer parameter: 0x" << std::hex << timerParameter << "\n";

            // [12] Attempt to resolve symbol from timer callback address.
            std::string timerCallbackSymbol;
            if (!NT_SUCCESS(ResolveSymbolFromAddress(hProcess, timerCallback, timerCallbackSymbol)))
            {
                // If we couldn't resolve symbol then attempt basic module offset level resolution (e.g. winlogon+0x63590).
                if (!NT_SUCCESS(GetBasicSymbolFromAddress(hProcess, timerCallback, timerCallbackSymbol)))
                {
                    std::cout << "[-] Manual symbol resoluton failed\n";
                }
                else
                {
                    std::cout << "[+] Timer callback ptr (manually) resolved symbol: " << std::hex << timerCallbackSymbol << "\n";
                }
                std::cout << "==========================================================================\n";
                continue;
            }
            std::cout << "[+] Timer callback ptr resolved symbol: " << std::hex << timerCallbackSymbol << "\n";

            // [13] If the target callback is NtContinue then the parameter will be
            // a CONTEXT structure, so print out it's contents here.
            if ("NtContinue" != timerCallbackSymbol)
            {
                std::cout << "==========================================================================\n";
                continue;
            }
            CONTEXT ctx = {};
            ctx = readProcessMemory<CONTEXT>(hProcess, (PVOID)timerParameter);

            // [13.1] Perform basic sanity checking on CONTEXT structure. However,
            // as we have already resolved NtContinue it should be valid.
            if (ctx.ContextFlags & CONTEXT_CONTROL)
            {
                std::cout << "    [+] Timer CONTEXT structure details:\n";
                std::cout << "    [+] ctx.Rip: 0x" << std::hex << ctx.Rip << "\n";

                // [13.2] Resolve symbol for whatever ctx.rip is pointing at.
                std::string ctxRipSymbol;
                if (NT_SUCCESS(ResolveSymbolFromAddress(hProcess, ctx.Rip, ctxRipSymbol)))
                {
                    std::cout << "    [+] ctx.Rip resolved symbol: " << ctxRipSymbol.c_str() << "\n";

                    // [13.3] If Rip is pointing at VirtualProtect then print
                    // out information about target memory region.
                    if ("VirtualProtectEx" == ctxRipSymbol || "VirtualProtect" == ctxRipSymbol)
                    {
                        MEMORY_BASIC_INFORMATION mbi = {};
                        DWORD64 targetAddr = NULL;
                        std::string moduleName;
                        ("VirtualProtect" == ctxRipSymbol) ? targetAddr = ctx.Rcx : targetAddr = ctx.Rdx;
                        if (VirtualQueryEx(hProcess, (PVOID)targetAddr, &mbi, sizeof(mbi)))
                        {
                            std::cout << "        [+] Memory info for target region of VirtualProtect(Ex) call:\n";
                            std::cout << "        [+] BaseAddress: 0x" << std::hex << mbi.BaseAddress << "\n";
                            std::cout << "        [+] AllocationBase: 0x" << std::hex << mbi.AllocationBase << "\n";
                            std::cout << "        [+] State: 0x" << std::hex << mbi.State << "\n";
                            std::cout << "        [+] Protect: 0x" << std::hex << mbi.Protect << "\n";
                            std::cout << "        [+] Type: 0x" << std::hex << mbi.Type << "\n";

                            // [13.4] Attempt to resolve module name
                            if (NT_SUCCESS(GetModuleBaseNameWrapper(hProcess, mbi.AllocationBase, moduleName)))
                            {
                                std::cout << "        [+] Module base name: " << moduleName.c_str() << "\n";
                            }
                        }
                    }
                }
                std::cout << "    [+] ctx.Rcx: 0x" << std::hex << ctx.Rcx << "\n";
                std::cout << "    [+] ctx.Rdx: 0x" << std::hex << ctx.Rdx << "\n";
                std::cout << "    [+] ctx.R8: 0x" << std::hex << ctx.R8 << "\n";
                std::cout << "    [+] ctx.R9: 0x" << std::hex << ctx.R9 << "\n";
            }
        std::cout << "==========================================================================\n";
        }
    }
    return;
}

//
// Scans target process for timer-queue timers.
//
NTSTATUS ScanForTimerQueueTimers(DWORD pid)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    std::vector<MEMORY_BASIC_INFORMATION> processHeapVector;
    BOOL bIsWow64 = false;

    // [1] Obtain handle to target process.
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ , FALSE, pid);
    if (hProcess == NULL)
    {
        std::cout << "[-] Failed to open a handle to pid: " << std::dec << pid << "\n";
        status = STATUS_ASSERTION_FAILURE;
        goto Cleanup;
    }

    // [2] WOW64 is unsupported/untested, so skip 32 bit processes.
    if (IsWow64Process(hProcess, &bIsWow64))
    {
        if (bIsWow64)
        {
            std::cout << "[-] WOW64 is unsupported; skipping scanning pid: " << std::dec << pid << "\n";
            status = STATUS_ASSERTION_FAILURE;
            goto Cleanup;
        }
    }

    // [3] Initialise symbols for target process.
    if (!SymInitialize(hProcess, defaultSymbolPath.c_str(), TRUE))
    {
        std::cout << "[-] SymInitialize returned error: " << GetLastError() << "\n";
        return -1;
    }

    // [4] Locate process heaps for target process.
    if (!NT_SUCCESS(FindProcessHeaps(hProcess, processHeapVector)))
    {
        std::cout << "[-] Failed to locate process heaps for pid: " << pid << "\n";
        status = STATUS_ASSERTION_FAILURE;
        goto Cleanup;
    }

    // [5] Scan process heaps for timer-queue timers.
    ScanHeapMemory(hProcess, processHeapVector);

Cleanup:
    CloseHandle(hProcess);
    return status;
}

//
// Loop round processes and run memory scan.
// Based on:
// https://learn.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes
//
NTSTATUS ScanProcesses()
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE hProcessSnapshot = INVALID_HANDLE_VALUE;
    PROCESSENTRY32 processEntry32 = {};

    // [0] Take a snapshot of all running processes.
    hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnapshot == INVALID_HANDLE_VALUE)
    {
        status = STATUS_ASSERTION_FAILURE;
        goto Cleanup;
    }

    // [1] Set the size of the proc32 struct and check
    // we can retrieve information about the
    // first process and bail if not.
    processEntry32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnapshot, &processEntry32))
    {
        status = STATUS_ASSERTION_FAILURE;
        goto Cleanup;
    }

    // [2] Start looping over all processes.
    do
    {
        if (GetCurrentProcessId() == processEntry32.th32ProcessID)
        {
            continue;
        }

        // [3] Scan for timer-queue timers
        std::wcout << "[+] Scanning process: " << processEntry32.szExeFile << ", pid: " << processEntry32.th32ProcessID << "\n";
        (void)ScanForTimerQueueTimers(processEntry32.th32ProcessID);
    } while (Process32Next(hProcessSnapshot, &processEntry32));

Cleanup:

    CloseHandle(hProcessSnapshot);
    return status;
}

//
// Sets the specified privilege in the current process access token.
// Based on:
// https://docs.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
//
BOOL SetPrivilege(
    const LPCTSTR lpszPrivilege,
    const BOOL bEnablePrivilege
)
{
    TOKEN_PRIVILEGES tp = {};
    LUID luid = {};
    HANDLE hToken = NULL;

    // [1] Obtain handle to process token.
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        std::cout << "[-] Failed to OpenProcessToken \n";
        return FALSE;
    }

    // [2] Look up supplied privilege value and set if required.
    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
    {
        std::cout << "[-] SetPrivilege failed: LookupPrivilegeValue error" << GetLastError() << std::endl;
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
    {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    }
    else
    {
        tp.Privileges[0].Attributes = 0;
    }

    // [3] Enable the privilege or disable all privileges.
    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        std::cout << "[-] AdjustTokenPrivileges failed: LookupPrivilegeValue error" << GetLastError() << std::endl;
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        std::cout << "[-] SetPrivilege failed: LookupPrivilegeValue error\n";
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

//
// Parses command line arguments.
//
NTSTATUS HandleArgs(int argc, char* argv[])
{
    NTSTATUS status = STATUS_SUCCESS;

    if (argc < 2)
    {
        goto Cleanup;
    }
    else
    {
        std::string callstackArg(argv[1]);
        if (callstackArg == "--debug")
        {
            std::cout << "[+] Debug output enabled.\n";
            bShowDebugOutput = true;
        }
        else
        {
            std::cout << "[!] Error: Incorrect argument provided. The options are: --debug.\n";
            status = ERROR_INVALID_PARAMETER;
        }
    }

Cleanup:
    return status;
}

int main(int argc, char* argv[])
{
    std::cout << R"(
                ,----,                                            ,----,                             
              ,/   .`|                                          ,/   .`|                             
            ,`   .'  :                        ,-.             ,`   .'  :                        ,-.  
          ;    ;     / ,--,               ,--/ /|           ;    ;     /                    ,--/ /|  
        .'___,/    ,',--.'|             ,--. :/ |         .'___,/    ,'  ,---.            ,--. :/ |  
        |    :     | |  |,              :  : ' /          |    :     |  '   ,'\           :  : ' /   
        ;    |.';  ; `--'_       ,---.  |  '  /           ;    |.';  ; /   /   |   ,---.  |  '  /    
        `----'  |  | ,' ,'|     /     \ '  |  :           `----'  |  |.   ; ,. :  /     \ '  |  :    
            '   :  ; '  | |    /    / ' |  |   \              '   :  ;'   | |: : /    / ' |  |   \   
            |   |  ' |  | :   .    ' /  '  : |. \             |   |  ''   | .; :.    ' /  '  : |. \  
            '   :  | '  : |__ '   ; :__ |  | ' \ \            '   :  ||   :    |'   ; :__ |  | ' \ \ 
            ;   |.'  |  | '.'|'   | '.'|'  : |--'             ;   |.'  \   \  / '   | '.'|'  : |--'  
            '---'    ;  :    ;|   :    :;  |,'                '---'     `----'  |   :    :;  |,'     
                     |  ,   /  \   \  / '--'                                     \   \  / '--'       
                      ---`-'    `----'                                            `----'
                              Timer-Queue Timer Enumerator            William Burgess @joehowwolf
    )" << '\n';

    std::cout << "*** WARNING: This tool requires symbols to be correctly configured and expects a default symbol path of C:\\Symbols. ***\n";
    std::cout << "*** See https://stackoverflow.com/questions/30019889/how-to-set-up-symbols-in-windbg for instructions on how to do this with windbg. ***\n\n";

    NTSTATUS status = STATUS_SUCCESS;

    // [0] Handle command line args.
    status = HandleArgs(argc, argv);
    if (!NT_SUCCESS(status))
    {
        return -1;
    }

    // [1] Configure symbol options.
    (void)SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEBUG | SYMOPT_DEFERRED_LOADS);

    // [2] Initialise required symbols. We need to hunt for pointers
    // in heap memory so bail if we can't resolve them.
    if (!NT_SUCCESS(InitialiseScanner()))
    {
        std::cout << "[!] Failed to initialise scanner.\n";
        return -1;
    }

    // [3] Acquire SeDebugPriv.
    if (!SetPrivilege(SE_DEBUG_NAME, true))
    {
        std::cout << "[!] Failed to enable SeDebugPrivilege; only a limited set of processes will be scanned. Try re-running as admin.\n";
    }

    // [4] Start hunting for timer-queue timers.
    if (!NT_SUCCESS(ScanProcesses()))
    {
        std::cout << "[!] Failed to create a process snapshot.\n";
        return -1;
    }

    return 0;
}