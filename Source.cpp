#include <Windows.h>
#include <iostream>
#include <iomanip>
#include <winternl.h>
#include "tdiinfo.h"
#include "tcpioctl.h"
#include <vector>
#include <string>
#include <random>

#pragma comment(lib, "ntdll.lib")

typedef unsigned __int64 _QWORD;

extern "C" {
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAllocateUuids(
			_Out_ PULARGE_INTEGER Time,
			_Out_ PULONG Range,
			_Out_ PULONG Sequence,
			_Out_ PCHAR Seed
		);

    NTSTATUS NTAPI NtCreateFile(
        PHANDLE FileHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PIO_STATUS_BLOCK IoStatusBlock,
        PLARGE_INTEGER AllocationSize,
        ULONG FileAttributes,
        ULONG ShareAccess,
        ULONG CreateDisposition,
        ULONG CreateOptions,
        PVOID EaBuffer,
        ULONG EaLength
    );


    NTSTATUS NTAPI NtDeviceIoControlFile(
        HANDLE FileHandle,
        HANDLE Event,
        PIO_APC_ROUTINE ApcRoutine,
        PVOID ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock,
        ULONG IoControlCode,
        PVOID InputBuffer,
        ULONG InputBufferLength,
        PVOID OutputBuffer,
        ULONG OutputBufferLength
    );

    NTSTATUS
        NTAPI
        NtAllocateVirtualMemory(
            IN HANDLE ProcessHandle,
            IN OUT PVOID* BaseAddress,
            IN ULONG_PTR ZeroBits,
            IN OUT PSIZE_T RegionSize,
            IN ULONG AllocationType,
            IN ULONG Protect
        );

    NTSTATUS NTAPI NtClose(HANDLE Handle);

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtSetUuidSeed(
            IN PUCHAR UuidSeed
        );
}

#define NT_SUCCESS(x) ((x) >= 0)


NTSTATUS GetCachedMac(BYTE* CachedMac)
{
    ULARGE_INTEGER time = { 0 };
    ULONG range = 0;
    ULONG sequence = 0;
    CHAR seed[8] = { 0 };
    NTSTATUS status = NtAllocateUuids(&time, &range, &sequence, seed);
    if (NT_SUCCESS(status))
    {
        for (int i = 0; i < 6; ++i)
        {
            CachedMac[i] = static_cast<BYTE>(seed[i]);
        }

        CachedMac[6] = 1;
        return 6ll;
    }

    return status;
}


void PrintCachedMac(const BYTE* cachedMac)
{
    wprintf(
        L"  ADDRESS[%02X:%02X:%02X:%02X:%02X:%02X]\n",
        cachedMac[0],
        cachedMac[1],
        cachedMac[2],
        cachedMac[3],
        cachedMac[4],
        cachedMac[5]
    );
}

using u8 = uint8_t;
using u64 = uint64_t;

void sub_14000A8C0(int64_t dst, int64_t src, uint64_t len)
{
    for (uint64_t i = 0; i < len; ++i)
        *reinterpret_cast<uint8_t*>(dst + i) = *reinterpret_cast<uint8_t*>(src + i);
}

void print_mac(const uint8_t* mac)
{
    std::wcout << L"  ADDRESS[";
    for (int i = 0; i < 6; ++i)
    {
        if (i) std::wcout << L":";
        std::wcout << std::hex << std::setw(2) << std::setfill(L'0') << (int)mac[i];
    }
    std::wcout << L"]\n";
}

void dumpmacserial()
{
    WCHAR deviceName[64];
    IO_STATUS_BLOCK ioStatus{};
    OBJECT_ATTRIBUTES objAttr{};
    UNICODE_STRING deviceNameU{};
    HANDLE hDevice = nullptr;

    BYTE adapterShortWords[128]{};
    BYTE macByteBuffer[10]{};
    ULONG inBuffer = 0;
    NTSTATUS status = 0;
    wchar_t adapterName[128 + 1]{};

    //
    // =======================
    // Cached MAC
    // =======================
    //
    {
        std::cout << "Process Network [CACHE]:" << std::endl;
        unsigned char cachedMac[7] = { 0 };
        memset(cachedMac, 0, 7);
        GetCachedMac(cachedMac);
        if (cachedMac[6])
        {
            printf("  ADDRESS[%02X:%02X:%02X:%02X:%02X:%02X]\n",
                cachedMac[0], cachedMac[1], cachedMac[2],
                cachedMac[3], cachedMac[4], cachedMac[5]);
        }
    }

    //
    // =======================
    // NDIS / NDMP
    // =======================
    //
    {
        std::cout << "Process Network [NDIS]:" << std::endl;
        for (int i = 0; i < 0x14; ++i)
        {
            swprintf(deviceName, L"\\Device\\NDMP%d", i);

            RtlInitUnicodeString(&deviceNameU, deviceName);
            InitializeObjectAttributes(&objAttr, &deviceNameU, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

            status = NtCreateFile(
                &hDevice,
                GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                &objAttr,
                &ioStatus,
                nullptr,
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                nullptr,
                0
            );

            if (!NT_SUCCESS(status))
                continue;

            memset(adapterShortWords, 0, sizeof(adapterShortWords));
            memset(macByteBuffer, 0, sizeof(macByteBuffer));

            inBuffer = 131606;
            status = NtDeviceIoControlFile(
                hDevice, nullptr, nullptr, nullptr, &ioStatus,
                1507330, &inBuffer, sizeof(inBuffer),
                adapterShortWords, sizeof(adapterShortWords)
            );

            inBuffer = 16843009;
            status = NtDeviceIoControlFile(
                hDevice, nullptr, nullptr, nullptr, &ioStatus,
                1507330, &inBuffer, sizeof(inBuffer),
                macByteBuffer, sizeof(macByteBuffer)
            );

            if (NT_SUCCESS(status) && adapterShortWords[0])
            {
                wprintf(L" Adapter %s\n", reinterpret_cast<wchar_t*>(adapterShortWords));
                printf("  ADDRESS[%02X:%02X:%02X:%02X:%02X:%02X]\n",
                    macByteBuffer[0], macByteBuffer[1], macByteBuffer[2],
                    macByteBuffer[3], macByteBuffer[4], macByteBuffer[5]);
            }

            NtClose(hDevice);
            hDevice = nullptr;
        }
    }

    //
    // =======================
    // NSI SECTION
    // =======================
    //
    {
        std::cout << "Process Network [NSI]:" << std::endl;
        uint16_t v107[158]{};

        swprintf(deviceName, L"\\Device\\Nsi");
        RtlInitUnicodeString(&deviceNameU, deviceName);
        InitializeObjectAttributes(&objAttr, &deviceNameU, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        status = NtCreateFile(
            &hDevice,
            0x20100000,
            &objAttr,
            &ioStatus,
            nullptr,
            128LL,
            3,
            1LL,
            96LL,
            nullptr,
            0
        );

        if (!NT_SUCCESS(status) && hDevice)
        {
            std::cout << "failed ntcreatefile" << std::endl;
            return;
        }


        const size_t size_v33 = 9;
        const size_t size_v34 = 8;  // CHANGE IF issues HAPPENS ORIGINALY WAS [16]
        const size_t size_v35 = 16;
        const size_t size_v36 = 8;
        const size_t size_v37 = 11;
        const size_t size_v39_62 = 24;
        const size_t size_padding = 0; 

        const size_t size_v83 = 14 * sizeof(u64); // 112

        const size_t total = size_v33 + size_v34 + size_v35 + size_v36 + size_v37 + size_v39_62 + size_v83 + size_padding;
        void* region = VirtualAlloc(nullptr, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!region) {
            std::cerr << "VirtualAlloc failed: " << GetLastError() << "\n";
            CloseHandle(hDevice);
            return;
        }

        memset(region, 0, total);
        u8* cursor = (u8*)region;

        u8* v33 = cursor; cursor += size_v33;
        u8* v34 = cursor; cursor += size_v34;
        u8* v35 = cursor; cursor += size_v35;
        u8* v36 = cursor; cursor += size_v36;
        u8* v37 = cursor; cursor += size_v37;
        u8* v39_62 = cursor; cursor += size_v39_62;
        u64* v83 = reinterpret_cast<u64*>(cursor); cursor += size_v83;

        // v35[7..15] as in pseudocode
        v35[7] = 0x18;
        v35[8] = 0x00;
        v35[9] = 0x00;
        v35[10] = 0x00;
        v35[11] = 0x01;
        v35[12] = 0x00;
        v35[13] = 0x00;
        v35[14] = 0x00;
        v35[15] = 0x11;

        // v36 = "J", then bytes after
        memcpy(v36, "J", 2); // 'J' + nul (trailing space duh)
        v36[2] = 0xEB;
        v36[3] = 0x1A;
        v36[4] = 0x9B;
        v36[5] = 0xD4;
        v36[6] = 0x11;
        v36[7] = 0x91;

        // v37 = "#" then bytes
        memcpy(v37, "#", 2);
        v37[2] = 0x50; // 'P'
        v37[3] = 0x04;
        v37[4] = 0x77; // 'w'
        v37[5] = 0x59; // 'Y'
        v37[6] = 0xBC;

        // v33
        v33[0] = 0x18;
        v33[1] = 0x00;
        v33[2] = 0x00;
        v33[3] = 0x00;
        v33[4] = 0x01;
        v33[5] = 0x00;
        v33[6] = 0x00;
        v33[7] = 0x00;
        v33[8] = 0x00;

        // v34 = "J" then same bytes as v36 prefix
        memcpy(v34, "J", 2);
        if (size_v34 >= 8) {
            v34[2] = 0xEB; v34[3] = 0x1A; v34[4] = 0x9B; v34[5] = 0xD4; v34[6] = 0x11; v34[7] = 0x91;
        }

        // v35 start: strcpy(v35, "#") then set v35[2..6]
        memcpy(v35, "#", 2);
        v35[2] = 0x50; v35[3] = 0x04; v35[4] = 0x77; v35[5] = 0x59; v35[6] = 0xBC;
        // Note v35[7..15] already set above.

        // v39..v62 area fill to match pseudocode sequence:
        // We'll place the bytes in order you posted earlier. Adjust if your pseudocode differs.
        u8 v39_data[] = {
            0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00, // v39..v46
            0x01,0x4A,0x00,0xEB,0x1A,0x9B,0xD4,0x11, // continuing (0x4A = 'J' in your earlier listing used 74 decimal)
            0x91,0x23,0x00,0x50,0x04,0x77,0x59,0xBC  // finishes v56..v62 etc
        };
        if (sizeof(v39_data) == size_v39_62) {
            memcpy(v39_62, v39_data, size_v39_62);
        }
        else {
            // fallback: zeroed already
        }

        // Zero v83 first
        memset(v83, 0, size_v83);


        u64 ptr_to_v35plus7 = reinterpret_cast<u64>(v35 + 7);
        v83[2] = ptr_to_v35plus7;
        v83[3] = 1ULL;
        v83[4] = 0x100000001ULL;


        status = NtDeviceIoControlFile(
            hDevice,
            nullptr,
            nullptr,
            nullptr,
            &ioStatus,
            0x12001B,
            v83,         // input buffer pointer (pointer to QWORD array inside the region)
            (ULONG)size_v83, // 112
            v83,         // output buffer pointer
            (ULONG)size_v83  // 112
        );

        if (!NT_SUCCESS(status)) {

            //std::cerr << "Magic IOCTL failed: 0x" << std::hex << status << std::endl;

            VirtualFree(region, 0, MEM_RELEASE);
            NtClose(hDevice);
            return;
        }
        else
        {
            //std::cout << "Magic IOCTL succeeded!" << std::endl;

            u64 v63 = 0;
            v63 = v83[13] + 2;

            auto sub_140003C50 = [](u64 size) -> u64
                {
                    void* base = nullptr;
                    SIZE_T regionSize = size;
                    NTSTATUS st = NtAllocateVirtualMemory(
                        GetCurrentProcess(),
                        &base,
                        0,
                        &regionSize,
                        12288,
                        PAGE_READWRITE
                    );

                    if (!NT_SUCCESS(st))
                    {
                        std::cerr << "NtAllocateVirtualMemory failed (0x" << std::hex << st
                            << ") for size " << std::dec << size << "\n";
                        return 0;
                    }
                    return reinterpret_cast<u64>(base);
                };


            v83[5] = sub_140003C50(8 * (static_cast<uint32_t>(v83[13]) + 2));
            v83[6] = 8;

            v83[9] = sub_140003C50(656 * static_cast<int>(v63));
            v83[10] = 656;

            v83[11] = sub_140003C50(568 * static_cast<int>(v63));
            v83[12] = 568;

            v83[13] = v63;

            status = NtDeviceIoControlFile(
                hDevice,
                nullptr,
                nullptr,
                nullptr,
                &ioStatus,
                0x12001B,
                v83,
                112,
                v83,
                112
            );

            if (NT_SUCCESS(status))
            {
                int32_t v38 = 0;

                //std::cout << "entry count: " << v63 << std::endl;

                for (uint64_t j = 0; j < v63; ++j)
                {
                    uint64_t v95_qwords[13]{};

                    v95_qwords[2] = reinterpret_cast<uint64_t>(v33);
                    v95_qwords[3] = 7ULL;
                    v95_qwords[4] = 1ULL;
                    v95_qwords[5] = v83[5] + (8ULL * j);
                    v95_qwords[6] = 8ULL;

                    IO_STATUS_BLOCK iosb_local{};
                    NTSTATUS st = NtDeviceIoControlFile(
                        hDevice,
                        nullptr,
                        nullptr,
                        nullptr,
                        &iosb_local,
                        0x12000F,
                        v95_qwords,
                        sizeof(v95_qwords),
                        v95_qwords,
                        sizeof(v95_qwords)
                    );

                    if (!NT_SUCCESS(st))
                        continue;

                    int64_t v78 = 568LL * j;
                    uint32_t* v68 = reinterpret_cast<uint32_t*>(v83[11] + v78 + 536);

                    uint32_t v73 = *v68;
                    uint16_t v74 = *reinterpret_cast<uint16_t*>(v83[11] + v78 + 540);
                    uint16_t v75 = *reinterpret_cast<uint16_t*>(v83[11] + v78 + 542);
                    uint8_t v76[8]{};

                    for (int n = 0; n < 8; ++n)
                        v76[n] = *(reinterpret_cast<uint8_t*>(v68) + n + 8);

                    sub_14000A8C0(
                        reinterpret_cast<int64_t>(&v107[8 * v38 - 2]),
                        reinterpret_cast<int64_t>(&v73),
                        16LL
                    );

                    int64_t v27 = v83[10] * j + v83[9];
                    if (!v27)
                        continue;

                    bool is_zero =
                        !*reinterpret_cast<uint8_t*>(v27 + 550) &&
                        !*reinterpret_cast<uint8_t*>(v27 + 551) &&
                        !*reinterpret_cast<uint8_t*>(v27 + 552) &&
                        !*reinterpret_cast<uint8_t*>(v27 + 553) &&
                        !*reinterpret_cast<uint8_t*>(v27 + 554) &&
                        !*reinterpret_cast<uint8_t*>(v27 + 555);

                    if (is_zero)
                        continue;

                    int64_t v72 = v27 + 22;
                    if (!*reinterpret_cast<uint16_t*>(v72))
                        continue;

                    wprintf(L" Adapter[%s]\n", reinterpret_cast<wchar_t*>(v72));
                    wprintf(
                        L"  ADDRESS[%02X:%02X:%02X:%02X:%02X:%02X]\n",
                        *reinterpret_cast<uint8_t*>(v27 + 550),
                        *reinterpret_cast<uint8_t*>(v27 + 551),
                        *reinterpret_cast<uint8_t*>(v27 + 552),
                        *reinterpret_cast<uint8_t*>(v27 + 553),
                        *reinterpret_cast<uint8_t*>(v27 + 554),
                        *reinterpret_cast<uint8_t*>(v27 + 555)
                    );

                    ++v38;
                }

                //std::cout << "Second call succeeded.\n";
            }
            else
            {
                //std::cout << "Second call failed.\n";
            }

        }

        VirtualFree(region, 0, MEM_RELEASE);
        NtClose(hDevice);
    }

    //
    // =======================
    // TCP SECTION
    // =======================
    //
    {
        std::cout << "Process Network [TCP]:" << std::endl;
        swprintf(deviceName, L"\\Device\\Tcp");
        RtlInitUnicodeString(&deviceNameU, deviceName);
        InitializeObjectAttributes(&objAttr, &deviceNameU, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        status = NtCreateFile(
            &hDevice,
            537919488,
            &objAttr,
            &ioStatus,
            0LL,
            128LL,
            3,
            1LL,
            96LL,
            0,
            0
        );

        if (!NT_SUCCESS(status) || hDevice == INVALID_HANDLE_VALUE)
        {
            std::cerr << "failed NtCreateFile" << std::endl;
            return;
        }

        // Query entity list
        TCP_REQUEST_QUERY_INFORMATION_EX req{};
        req.ID.toi_entity.tei_entity = GENERIC_ENTITY;
        req.ID.toi_entity.tei_instance = 0;
        req.ID.toi_class = INFO_CLASS_GENERIC;
        req.ID.toi_type = INFO_TYPE_PROVIDER;
        req.ID.toi_id = ENTITY_LIST_ID;

        const DWORD MAX_ENTITIES = 32;
        std::vector<TDIEntityID> entityArray(MAX_ENTITIES);
        DWORD returnedLen = 0;

        if (!DeviceIoControl(
            hDevice,
            0x00120003, //IOCTL_TCP_QUERY_INFORMATION_EX
            &req,
            sizeof(req),
            entityArray.data(),
            (DWORD)(entityArray.size() * sizeof(TDIEntityID)),
            &returnedLen,
            nullptr
        ))
        {
            std::cerr << "Failed IOCTL_TCP_QUERY_INFORMATION_EX for ENTITY_LIST_ID\n";
            NtClose(hDevice);
            return;
        }

        DWORD entityCount = returnedLen / sizeof(TDIEntityID);

        for (DWORD i = 0; i < entityCount; ++i)
        {
            TDIEntityID& entity = entityArray[i];

            if (entity.tei_entity != IF_ENTITY)
                continue;

            TCP_REQUEST_QUERY_INFORMATION_EX ifReq{};
            ifReq.ID.toi_entity = entity;
            ifReq.ID.toi_class = INFO_CLASS_PROTOCOL;
            ifReq.ID.toi_type = INFO_TYPE_PROVIDER;
            ifReq.ID.toi_id = IF_MIB_STATS_ID;

            const DWORD bufSize = sizeof(IFEntry) + 128 + 1;
            std::vector<uint8_t> outBuf(bufSize);

            if (!DeviceIoControl(
                hDevice,
                IOCTL_TCP_QUERY_INFORMATION_EX,
                &ifReq,
                sizeof(ifReq),
                outBuf.data(),
                bufSize,
                &returnedLen,
                nullptr
            )) continue;

            IFEntry* ifEntry = reinterpret_cast<IFEntry*>(outBuf.data());

            sub_14000A8C0((int64_t)adapterName, (int64_t)(ifEntry->if_descr), 128);

            std::wcout << L" Adapter[" << adapterName << L"]\n";
            std::wcout << L"  ADDRESS[";
            for (int b = 0; b < 6; ++b)
            {
                if (b) std::wcout << L":";
                std::wcout << std::hex << std::uppercase << std::setw(2) << std::setfill(L'0')
                    << (int)ifEntry->if_physaddr[b];
            }
            std::wcout << L"]\n";
        }

        NtClose(hDevice);
    }
    //
    // =======================
    // NETBT SECTION
    // =======================
    //

    {

        std::cout << "Process Network [NetBT]:" << std::endl;

        unsigned __int8 NetBTMac[256]{};

        constexpr LPCWSTR baseKeyPath =
            L"SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}";

        HKEY hKey = nullptr;
        LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, baseKeyPath, 0, KEY_READ, &hKey);
        if (rc != ERROR_SUCCESS) {
            std::wcerr << L"RegOpenKeyExW failed for " << baseKeyPath << L" (error " << rc << L")\n";
            return;
        }

        // Buffer to hold subkey names
        const DWORD nameBufChars = 260;
        std::vector<wchar_t> nameBuf(nameBufChars);

        DWORD index = 0;
        while (true) {
            DWORD nameLen = (DWORD)nameBuf.size();
            FILETIME ftLastWrite{};
            rc = RegEnumKeyExW(hKey, index, nameBuf.data(), &nameLen, nullptr, nullptr, nullptr, &ftLastWrite);
            if (rc == ERROR_NO_MORE_ITEMS) break;
            if (rc != ERROR_SUCCESS) {
                std::wcerr << L"RegEnumKeyExW failed at index " << index << L" (error " << rc << L")\n";
                break;
            }

            std::wstring subkeyGuid(nameBuf.data(), nameLen);

            std::wstring ntDevicePath = L"\\Device\\NetBT_Tcpip_" + subkeyGuid;

            UNICODE_STRING ustr;
            ustr.Length = static_cast<USHORT>(ntDevicePath.size() * sizeof(WCHAR));
            ustr.MaximumLength = static_cast<USHORT>(ustr.Length + sizeof(WCHAR));
            ustr.Buffer = const_cast<PWSTR>(ntDevicePath.c_str());

            objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
            objAttr.RootDirectory = nullptr;
            objAttr.Attributes = OBJ_CASE_INSENSITIVE;
            objAttr.ObjectName = &ustr;
            objAttr.SecurityDescriptor = nullptr;
            objAttr.SecurityQualityOfService = nullptr;

            status = NtCreateFile(
                &hDevice,
                SYNCHRONIZE | GENERIC_EXECUTE,
                &objAttr,
                &ioStatus,
                nullptr,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN,
                FILE_SYNCHRONOUS_IO_NONALERT,
                nullptr,
                0
            );

            if (NT_SUCCESS(status) && hDevice && hDevice != INVALID_HANDLE_VALUE) {
                std::wcout << L"Transport name " << ntDevicePath << L"\n";
                status = NtDeviceIoControlFile(
                    hDevice,
                    nullptr,
                    nullptr,
                    nullptr,
                    &ioStatus,
                    0x210086,
                    NetBTMac,
                    256LL,
                    NetBTMac,
                    256LL
                );

                if (NT_SUCCESS(status))
                {
                    wprintf(L"  ADDRESS[%02X:%02X:%02X:%02X:%02X:%02X]\n",
                        NetBTMac[0],
                        NetBTMac[1],
                        NetBTMac[2],
                        NetBTMac[3],
                        NetBTMac[4],
                        NetBTMac[5]);
                }

                NtClose(hDevice);
            }


            ++index;
        }

        RegCloseKey(hKey);
    }
}

int main()
{
    dumpmacserial();
    system("pause");
    exit(0);
}

//#include <windows.h>
//#include <iostream>
//#include <iphlpapi.h>
//#pragma comment(lib, "iphlpapi.lib")
//
//#define IOCTL_NDIS_QUERY_GLOBAL_STATS  CTL_CODE(FILE_DEVICE_PHYSICAL_NETCARD, 0, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
//#define OID_802_3_PERMANENT_ADDRESS      0x01010101
//#define OID_802_3_CURRENT_ADDRESS      0x01010102
//
//#define OID_802_5_PERMANENT_ADDRESS      0x02010101
//#define OID_802_5_CURRENT_ADDRESS      0x02010102
//
//int main() {
//    // Step 1: Enumerate network adapters
//    IP_ADAPTER_INFO adapterInfo[16];
//    DWORD bufLen = sizeof(adapterInfo);
//    DWORD ret = GetAdaptersInfo(adapterInfo, &bufLen);
//
//    if (ret != ERROR_SUCCESS) {
//        std::cerr << "GetAdaptersInfo failed: " << ret << "\n";
//        return 1;
//    }
//
//    PIP_ADAPTER_INFO pAdapter = adapterInfo;
//    while (pAdapter) {
//        std::wcout << L"Adapter: " << pAdapter->Description << L"\n";
//
//        // Step 2: Build device name for Ndisuio
//        // "\\\\.\\{GUID}" format
//
//        // Step 2: Build device name for Ndisuio
//        int size_needed = MultiByteToWideChar(CP_ACP, 0, pAdapter->AdapterName, -1, nullptr, 0);
//        std::wstring wAdapterName(size_needed, 0);
//        MultiByteToWideChar(CP_ACP, 0, pAdapter->AdapterName, -1, &wAdapterName[0], size_needed);
//
//        std::wstring devicePath = L"\\\\.\\" + wAdapterName;
//
//        //std::wstring devicePath = L"\\\\.\\" + std::wstring(pAdapter->AdapterName);
//
//        HANDLE hDevice = CreateFileW(
//            devicePath.c_str(),
//            GENERIC_READ | GENERIC_WRITE,
//            0,
//            nullptr,
//            OPEN_EXISTING,
//            0,
//            nullptr
//        );
//
//        if (hDevice == INVALID_HANDLE_VALUE) {
//            std::cerr << "Failed to open device: " << GetLastError() << "\n";
//            pAdapter = pAdapter->Next;
//            continue;
//        }
//
//        // Step 3: Query MAC address
//        ULONG oid = OID_802_3_PERMANENT_ADDRESS;
//        BYTE mac[6] = { 0 };
//        ULONG returnedLength = 0;
//
//        BOOL success = DeviceIoControl(
//            hDevice,
//            IOCTL_NDIS_QUERY_GLOBAL_STATS,
//            &oid,
//            sizeof(oid),
//            mac,
//            sizeof(mac),
//            &returnedLength,
//            nullptr
//        );
//
//        if (success && returnedLength == 6) {
//            std::cout << "MAC: ";
//            for (int i = 0; i < 6; ++i) {
//                printf("%02X", mac[i]);
//                if (i != 5) printf(":");
//            }
//            printf("\n");
//        }
//        else {
//            std::cerr << "DeviceIoControl failed: " << GetLastError() << "\n";
//        }
//
//        CloseHandle(hDevice);
//        pAdapter = pAdapter->Next;
//    }
//
//    return 0;
//}
