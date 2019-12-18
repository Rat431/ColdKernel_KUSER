#include <ntdef.h>
#include <ntifs.h>
#include <ntdef.h>
#include <ntddk.h>
#include <wdm.h>

#define KUSER_BASE_ADDRESS 0x7FFE0000
#define KUSER_SIZE 0x1000
#define KUSER_SIZE_DWORD (KUSER_SIZE / 4)

struct KuserDataStruct
{
	uintptr_t Address;
	BOOLEAN Hook;	// Flag here
	char Data[4];
};
struct KeRestoreData
{
	uintptr_t Address;
	char Data[4];
};
struct KuserDataStruct* kuserstruct = NULL;
struct KeRestoreData* restorestruct = NULL;

void KeStoreOriginalData(PVOID Address)
{
	struct KeRestoreData* restore = restorestruct;
	struct KeRestoreData tempdata = { 0 };
	for (int i = 0; i < KUSER_SIZE_DWORD; i++, restore++)
	{
		if (RtlCompareMemory(restore, &tempdata, sizeof(struct KeRestoreData)) == sizeof(struct KeRestoreData)) {
			restore->Address = (uintptr_t)Address;
			RtlCopyMemory(restore->Data, Address, 4);
			DbgPrint("Data stored!\n");
			break;
		}
		if (restore->Address == (uintptr_t)Address) {
			DbgPrint("Original dword data at 0x%x cannot be saved.\n", restore->Address);
			break;
		}
	}
}
PVOID KeGetOriginalStoredData(PVOID Address)
{
	struct KeRestoreData* restore = restorestruct;
	for (int i = 0; i < KUSER_SIZE_DWORD; i++, restore++)
	{
		if (restore->Address == (uintptr_t)Address) {
			return restore->Data;
		}
	}
	return NULL;
}

void HookKernel(PVOID Address, PVOID data, int size)
{
	RtlCopyMemory(Address, data, size);
}

void HookKuser(struct KuserDataStruct* Configuration)
{
	// Search what we should hook
	uintptr_t Starting = KUSER_BASE_ADDRESS;
	int size = KUSER_SIZE_DWORD;
	int loop = 0;
	for (;;)
	{
		if (loop < size)
		{
			// Hook here 
			uintptr_t CurrentAddress = Starting;
			struct KuserDataStruct* Structure = Configuration;

			for (int i = 0; i < size; i++, Structure++)
			{
				if (CurrentAddress == Structure->Address)
				{
					if (Structure->Hook)
					{
						DbgPrint("The following address is being hooked: 0x%x\n", CurrentAddress);
						PMDL descriptor = IoAllocateMdl((PVOID)CurrentAddress, 4, 0, 0, 0);
						if (descriptor)
						{
							MmProbeAndLockPages(descriptor, KernelMode, IoReadAccess);
							PVOID datamap = MmMapLockedPagesSpecifyCache(descriptor, KernelMode, MmCached, NULL, 0, NormalPagePriority);
							if (datamap)
							{
								DbgPrint("All went ok, memory will be hooked in few seconds...\n");
								KeStoreOriginalData(CurrentAddress);
								HookKernel(datamap, Structure->Data, 4);

								// Free everything 
								MmUnmapLockedPages(datamap, descriptor);
								MmUnlockPages(descriptor);
								IoFreeMdl(descriptor);
							}
							else
							{
								DbgPrint("HOOK FALIED: MmMapLockedPagesSpecifyCache on address 0x%x falied.\n", CurrentAddress);
								MmUnlockPages(descriptor);
								IoFreeMdl(descriptor);
							}
						}
						else
							DbgPrint("HOOK FALIED: IoAllocateMdl on address 0x%x falied.\n", CurrentAddress);
					}
					break;
				}
			}
			loop++;
			Starting += 4;
		}
		else
			break;
	}
}
void UnHookKusser()
{
	// Search what we should unhook
	uintptr_t Starting = KUSER_BASE_ADDRESS;
	int size = KUSER_SIZE_DWORD;
	int loop = 0;
	for (;;)
	{
		if (loop < size)
		{
			// Hook here 
			uintptr_t CurrentAddress = Starting;
			struct KuserDataStruct* Structure = kuserstruct;

			for (int i = 0; i < size; i++, Structure++)
			{
				if (CurrentAddress == Structure->Address)
				{
					if (Structure->Hook)
					{
						DbgPrint("The following address is being restored: 0x%x\n", CurrentAddress);
						PMDL descriptor = IoAllocateMdl((PVOID)CurrentAddress, 4, 0, 0, 0);
						if (descriptor)
						{
							MmProbeAndLockPages(descriptor, KernelMode, IoReadAccess);
							PVOID datamap = MmMapLockedPagesSpecifyCache(descriptor, KernelMode, MmCached, NULL, 0, NormalPagePriority);
							if (datamap)
							{
								DbgPrint("All went ok, memory will be hooked in few seconds...\n");
								PVOID RestoreData = KeGetOriginalStoredData(CurrentAddress);
								if (RestoreData)
								{
									HookKernel(datamap, RestoreData, 4);
									DbgPrint("Mem restored!\n");
								}
								else
									DbgPrint("No restore data available!\n");

								// Free everything 
								MmUnmapLockedPages(datamap, descriptor);
								MmUnlockPages(descriptor);
								IoFreeMdl(descriptor);
							}
							else
							{
								DbgPrint("HOOK FALIED: MmMapLockedPagesSpecifyCache on address 0x%x falied.\n", CurrentAddress);
								MmUnlockPages(descriptor);
								IoFreeMdl(descriptor);
							}
						}
						else
							DbgPrint("HOOK FALIED: IoAllocateMdl on address 0x%x falied.\n", CurrentAddress);
					}
					break;
				}
			}
			loop++;
			Starting += 4;
		}
		else
			break;
	}
}

NTSTATUS DriverReadConfing(struct KuserDataStruct* Configuration)
{
	DbgPrint("Reading configuration\n");

	// Read from the file if present
	UNICODE_STRING name;
	OBJECT_ATTRIBUTES object;
	HANDLE hFile;
	NTSTATUS status;
	IO_STATUS_BLOCK statusblock;
	FILE_STANDARD_INFORMATION fileinfo;
	LARGE_INTEGER byteOffset;

	RtlInitUnicodeString(&name, L"\\SystemRoot\\ColdKernel.bin");
	InitializeObjectAttributes(&object, &name,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	// Check IRQL
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		return STATUS_INVALID_DEVICE_STATE;

	status = ZwCreateFile(
		&hFile, GENERIC_READ, &object, &statusblock, NULL, FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);

	if (NT_SUCCESS(status)) 
	{
		// Get File size
		status = ZwQueryInformationFile(
			hFile,
			&statusblock,
			&fileinfo,
			sizeof(FILE_STANDARD_INFORMATION),
			FileStandardInformation);
		if (NT_SUCCESS(status))
		{
			if (fileinfo.EndOfFile.QuadPart >= (sizeof(struct KuserDataStruct) * KUSER_SIZE_DWORD))
			{
				byteOffset.LowPart = byteOffset.HighPart = 0;
				status = ZwReadFile(hFile, NULL, NULL, NULL, &statusblock,
					Configuration, (sizeof(struct KuserDataStruct) * KUSER_SIZE_DWORD), &byteOffset, NULL);
				if (NT_SUCCESS(status)) {
					DbgPrint("Configuration has been readed!\n");
				}
			}
			else
				status = STATUS_ABANDONED;
		}
		ZwClose(hFile);
	}
	return status;
}

NTSTATUS DriverSystemInit()
{
	// Read Configuration firstly 
	SIZE_T kuserstructSize = sizeof(struct KuserDataStruct) * KUSER_SIZE_DWORD;
	SIZE_T kuserrestoreSize = sizeof(struct KeRestoreData) * KUSER_SIZE_DWORD;
	NTSTATUS status;

	_try
	{
		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &kuserstruct, NULL, &kuserstructSize, MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE);
		if (NT_SUCCESS(status))
		{
			status = ZwAllocateVirtualMemory(NtCurrentProcess(), &restorestruct, NULL, &kuserrestoreSize, MEM_COMMIT | MEM_RESERVE,
				PAGE_READWRITE);
			if (NT_SUCCESS(status))
			{
				status = DriverReadConfing(kuserstruct);
				if (NT_SUCCESS(status))
				{
					HookKuser(kuserstruct);
					return STATUS_SUCCESS;
				}
			}
			else
			{
				SIZE_T RSize = NULL;
				ZwFreeVirtualMemory(NtCurrentProcess(), &kuserstruct, &RSize, MEM_RELEASE);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_ACCESS_DENIED;
	}
	return status;
}
NTSTATUS DriverSystemClose()
{
	SIZE_T RSize;
	NTSTATUS status;

	_try
	{
		UnHookKusser();

		RSize = NULL;
		status = ZwFreeVirtualMemory(NtCurrentProcess(), &kuserstruct, &RSize, MEM_RELEASE);
		if (NT_SUCCESS(status))
		{
			RSize = NULL;
			status = ZwFreeVirtualMemory(NtCurrentProcess(), &restorestruct, &RSize, MEM_RELEASE);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_ACCESS_DENIED;
	}
	return status;
}

NTSTATUS Unload(_In_  struct _DRIVER_OBJECT* DriverObject)
{
	return DriverSystemClose();
}
NTSTATUS DriverEntry(_In_  struct _DRIVER_OBJECT* DriverObject, _In_  PUNICODE_STRING RegistryPath) // Driver Entry
{
	DbgPrint("DriverEntry called.\n");

	// Set unload function 
	DriverObject->DriverUnload = Unload;

	// Init system 
	return DriverSystemInit();
}
