# Remove-your-systemthread-from-PspCidTable
Remove your systemthread from PspCidTable tutorial (reuploaded because github ban me).
discord: (coming soon).

---------------------------------------------------------------------------------------------------------------------------------------------------------------------

PspCidTable & ExDestroyHandleA

1. Open up ntoskrnl.exe in Ida Pro.
2. In the functions window search for the function PspReferenceCidTableEntry (or any function that moves PspCidTable address into a register)
3. Signature an instruction that moves the address of PspCidTable into a register
![image](https://user-images.githubusercontent.com/108452509/176612581-56b13fc0-91b7-4736-b85f-c39268923890.png)
4. Test the signature and make sure it works (your signature may be different depending on your winver) (your signnature should look like something along the lines of \xE8\x00\x00\x00\x00\x49\x8B\xCC\xE8\x00\x00\x00\x00\x48\x8B\xCF. x????xxxx????xxx)

---------------------------------------------------------------------------------------------------------------------------------------------------------------------

ExDestroyHandle
for this instruction 3 bytes are the opcode and the next 4 bytes are the address

1. In the functions window search for the function ExDestroyHandle
2. Check the xrefs to ExDestroyHandle and click any of the xrefs that calls this function
![image](https://user-images.githubusercontent.com/108452509/176613375-6e17e332-6f14-4ebe-b7c0-38dff17c8402.png)
3. Signature the instruction that calls the ExDestroyHandle function
![image](https://user-images.githubusercontent.com/108452509/176613389-8be09146-48c9-4bb0-8c80-e67dae04069f.png)
4. Test the signature and make sure it works

---------------------------------------------------------------------------------------------------------------------------------------------------------------------

Now lets write a function to resolve the addresses
For this instruction 1 byte is the opcode and the next 4 bytes are the address

Exmaple:

ULONG64* resolve(const ULONG64 addressInstruction, const int opcodeBytes, int addressBytes)
{
	addressBytes += opcodeBytes;
	const ULONG32 RelativeOffset = *reinterpret_cast<ULONG32*>(addressInstruction + opcodeBytes);
	ULONG64* FinalAddress = reinterpret_cast<ULONG64*>(addressInstruction + RelativeOffset + addressBytes);
	return FinalAddress;
}

To call the ExDestroyHandle lets first define it in your definitions file

Exmaple:

typedef BOOLEAN(*func)(const PHANDLE_TABLE, const HANDLE, const PHANDLE_TABLE_ENTRY);
func ExDestroyHandle;

---------------------------------------------------------------------------------------------------------------------------------------------------------------------

As you see we need the HANDLE_TABLE structure, lets quickly get it from windbg.
1. open local kernel debug session
2. type dt _HANDLE_TABLE
![image](https://user-images.githubusercontent.com/108452509/176614057-12085e0b-0223-4874-95e8-893ea6de654c.png)
3. define this structure in your definitions file

Exmaple:

typedef struct _HANDLE_TABLE
{
    ULONG       NextHandleNeedingPool;  //Uint4B
    LONG        ExtraInfoPages;         //Int4B
    ULONG64     TableCode;              //Uint8B 
    PEPROCESS   QuotaProcess;           //Ptr64 _EPROCESS
    _LIST_ENTRY HandleTableList;        //_LIST_ENTRY
    ULONG       UniqueProcessId;        //Uint4B
} HANDLE_TABLE, * PHANDLE_TABLE;

Now before you start your thread loop write the following in your system thread function

Exmaple:

const ULONG64* pPspCidTable     = resolve(Utilities::find_pattern<ULONG64>(kernelBaseModule.baseAddress, kernelBaseModule.size, "\x4C\x8B\x35\x00\x00\x00\x00\x0F\x0D\x08", "xxx????xxx"), 3, 4);
const ULONG64* pExDestroyHandle = resolve(Utilities::find_pattern<ULONG64>(kernelBaseModule.baseAddress, kernelBaseModule.size, "\xE8\x00\x00\x00\x00\x49\x8B\xCC\xE8\x00\x00\x00\x00\x48\x8B\xCF", "x????xxxx????xxx"), 1, 4);
 
ExDestroyHandle = reinterpret_cast<func>(pExDestroyHandle);
DestroyPspCidTableEntry(pPspCidTable, PsGetCurrentThreadId());

Now lets write the function that destroys the entry

Exmaple:

void DestroyPspCidTableEntry(const ULONG64* pPspCidTable, const HANDLE threadId)
{
    ULONG64* pHandleTable = reinterpret_cast<ULONG64*>(*pPspCidTable); //deref for pointer to handle table
    const PHANDLE_TABLE_ENTRY pCidEntry = ExpLookupHandleTableEntry(pHandleTable, reinterpret_cast<LONGLONG>(threadId));
 
    if (pCidEntry != NULL)
    {
        DbgPrintEx(0, 0, "Handle table: %p", pHandleTable);
        DbgPrintEx(0, 0, "Cid entry: %p", pCidEntry);
        DbgPrintEx(0, 0, "ObjectPointerBits: %p", pCidEntry->ObjectPointerBits);
 
        ExDestroyHandle(reinterpret_cast<PHANDLE_TABLE>(pHandleTable), threadId, pCidEntry);
                
        if (pCidEntry->ObjectPointerBits == 0)
        {
            DbgPrintEx(0, 0, "Entry should be removed removed");
            DbgPrintEx(0, 0, "ObjectPointerBits now: %p", pCidEntry->ObjectPointerBits);
        }
    }
}

---------------------------------------------------------------------------------------------------------------------------------------------------------------------

This function needs ExpLookupHandleTableEntry lets find this in ida and add it to our code.
1. Search for the function in ExpLookupHandleTableEntry
2. Look at the pseudo code

Exmaple:

unsigned __int64 __fastcall ExpLookupHandleTableEntry(unsigned int *a1, __int64 a2)
{
  unsigned __int64 v2; // rdx
  __int64 v3; // r8
 
  v2 = a2 & 0xFFFFFFFFFFFFFFFCui64;
  if ( v2 >= *a1 )
    return 0i64;
  v3 = *((_QWORD *)a1 + 1);
  if ( (v3 & 3) == 1 )
    return *(_QWORD *)(v3 + 8 * (v2 >> 10) - 1) + 4 * (v2 & 0x3FF);
  if ( (v3 & 3) != 0 )
    return *(_QWORD *)(*(_QWORD *)(v3 + 8 * (v2 >> 19) - 2) + 8 * ((v2 >> 10) & 0x1FF)) + 4 * (v2 & 0x3FF);
  return v3 + 4 * v2;
}

Seem to only do some bitwise operations and checks, really simple to import in your code.

Exmaple:

PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntry(const ULONG64* pHandleTable, const LONGLONG Handle)
{
    ULONGLONG v2; // rdx
    LONGLONG v3; // r8
 
    v2 = Handle & 0xFFFFFFFFFFFFFFFC;
    if (v2 >= *pHandleTable)
        return 0;
    v3 = *(pHandleTable + 1);
    if ((v3 & 3) == 1)
        return reinterpret_cast<PHANDLE_TABLE_ENTRY>(*reinterpret_cast<ULONG_PTR*>(v3 + 8 * (v2 >> 10) - 1) + 4 * (v2 & 0x3FF));
    if ((v3 & 3) != 0)
        return reinterpret_cast<PHANDLE_TABLE_ENTRY>(*reinterpret_cast<ULONG_PTR*>(*reinterpret_cast<ULONG_PTR*>(v3 + 8 * (v2 >> 19) - 2) + 8 * ((v2 >> 10) & 0x1FF)) + 4 * (v2 & 0x3FF));
    return reinterpret_cast<PHANDLE_TABLE_ENTRY>(v3 + 4 * v2);
}

As you can see the return type is pointer to HANDLE_TABLE_ENTRY
Lets get this struct in windbg like we did before
(dt _HANDLE_TABLE_ENTRY)
![image](https://user-images.githubusercontent.com/108452509/176614605-7c4e0be7-b5b1-4735-9ef3-fe0d297f4c21.png)
As you can see offsets of some variables are the same?
This is because for example the 0x000 offset is a class which members all occupie the same memory and this class is able to hold only 1 of it's members at the same time in c++ this is an union.
So this struct will be:

typedef struct _HANDLE_TABLE_ENTRY
{
    union                                           //that special class
    {
        ULONG64 VolatileLowValue;                   //Int8B
        ULONG64 LowValue;                           //Int8B
        ULONG64 RefCountField;                      //Int8B
        _HANDLE_TABLE_ENTRY_INFO* InfoTable;        //Ptr64 _HANDLE_TABLE_ENTRY_INFO
        struct
        {
            ULONG64 Unlocked            : 1;        //1Bit
            ULONG64 RefCnt              : 16;       //16Bits
            ULONG64 Attributes          : 3;        //3Bits
            ULONG64 ObjectPointerBits   : 44;       //44Bits
        };
    };
    union
    {
        ULONG64 HighValue;                          //Int8B
        _HANDLE_TABLE_ENTRY* NextFreeHandleEntry;   //Ptr64 _HANDLE_TABLE_ENTRY
    };
} HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;

As you are able to see this structure needs the HANDLE_TABLE_ENTRY_INFO struct.
same as before look for it using windbg:

typedef struct _HANDLE_TABLE_ENTRY_INFO
{
    ULONG AuditMask;                //Uint4B
    ULONG MaxRelativeAccessMask;    //Uint4b
} HANDLE_TABLE_ENTRY_INFO, * PHANDLE_TABLE_ENTRY_INFO;

---------------------------------------------------------------------------------------------------------------------------------------------------------------------

This should be it, you can simply check using windbg to get some more information. For example comment out the part that destroys the handle and look in windbg.

Commands:
dd PspCidTable
get the memory inside PspCidTable here you can see your table handle
![image](https://user-images.githubusercontent.com/108452509/176614937-38138b2e-88bc-4b8b-8dcc-b4624a84788f.png)

dt _HANDLE_TABLE address
cast memory from address into the _HANDLE_TABLE structure
![image](https://user-images.githubusercontent.com/108452509/176615015-36d8aeb4-95d8-43a2-921c-380200cc77ee.png)

dt _HANDLE_TABLE_ENTRY address
cast memory from address into the _HANDLE_TABLE_ENTRY structure
![image](https://user-images.githubusercontent.com/108452509/176615094-d370669e-1fcd-42e4-8a43-d3e28436527a.png)

---------------------------------------------------------------------------------------------------------------------------------------------------------------------

After deleting the handle make sure the thread doesn't exit else u get a BSOD.
