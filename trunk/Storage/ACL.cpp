#include "pch.h"
#include "ACL.h"

/*
首先解释（翻译）几个名词：
Owner：拥有者，所有者。
Ownership：所有权
Authorization：授权
Authentication：认证
*/


#pragma warning(disable:28183)
#pragma warning(disable:6387)
#pragma warning(disable:6011)


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C
__declspec(dllexport)
int WINAPI FindingOwnerofFile(void)
/*
Finding the Owner of a File Object in C++
05/31/2018

The following example uses the GetSecurityInfo and LookupAccountSid functions to find and print the name of the owner of a file.
The file exists in the current working directory on the local server.

https://docs.microsoft.com/en-us/windows/win32/secauthz/finding-the-owner-of-a-file-object-in-c--
*/
{
    DWORD dwRtnCode = 0;
    PSID pSidOwner = NULL;
    BOOL bRtnBool = TRUE;
    LPTSTR AcctName = NULL;
    LPTSTR DomainName = NULL;
    DWORD dwAcctName = 1, dwDomainName = 1;
    SID_NAME_USE eUse = SidTypeUnknown;
    HANDLE hFile;
    PSECURITY_DESCRIPTOR pSD = NULL;

    // Get the handle of the file object.
    hFile = CreateFile(TEXT("myfile.txt"),
                       GENERIC_READ,
                       FILE_SHARE_READ,
                       NULL,
                       OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);
    if (hFile == INVALID_HANDLE_VALUE) {// Check GetLastError for CreateFile error code.
        DWORD dwErrorCode = 0;
        dwErrorCode = GetLastError();
        _tprintf(TEXT("CreateFile error = %d\n"), dwErrorCode);
        return -1;
    }

    // Get the owner SID of the file.
    dwRtnCode = GetSecurityInfo(hFile,
                                SE_FILE_OBJECT,
                                OWNER_SECURITY_INFORMATION,
                                &pSidOwner,
                                NULL,
                                NULL,
                                NULL,
                                &pSD);
    if (dwRtnCode != ERROR_SUCCESS) {// Check GetLastError for GetSecurityInfo error condition.
        DWORD dwErrorCode = 0;
        dwErrorCode = GetLastError();
        _tprintf(TEXT("GetSecurityInfo error = %d\n"), dwErrorCode);
        return -1;
    }

    // First call to LookupAccountSid to get the buffer sizes.
    bRtnBool = LookupAccountSid(NULL,           // local computer
                                pSidOwner,
                                AcctName,
                                (LPDWORD)&dwAcctName,
                                DomainName,
                                (LPDWORD)&dwDomainName,
                                &eUse);

    // Reallocate memory for the buffers.
    AcctName = (LPTSTR)GlobalAlloc(GMEM_FIXED, dwAcctName);
    if (AcctName == NULL) {// Check GetLastError for GlobalAlloc error condition.
        DWORD dwErrorCode = 0;
        dwErrorCode = GetLastError();
        _tprintf(TEXT("GlobalAlloc error = %d\n"), dwErrorCode);
        return -1;
    }

    DomainName = (LPTSTR)GlobalAlloc(GMEM_FIXED, dwDomainName);
    if (DomainName == NULL) {// Check GetLastError for GlobalAlloc error condition.
        DWORD dwErrorCode = 0;
        dwErrorCode = GetLastError();
        _tprintf(TEXT("GlobalAlloc error = %d\n"), dwErrorCode);
        return -1;
    }

    // Second call to LookupAccountSid to get the account name.
    bRtnBool = LookupAccountSid(
        NULL,                   // name of local or remote computer
        pSidOwner,              // security identifier
        AcctName,               // account name buffer
        (LPDWORD)&dwAcctName,   // size of account name buffer 
        DomainName,             // domain name
        (LPDWORD)&dwDomainName, // size of domain name buffer
        &eUse);                 // SID type  
    if (bRtnBool == FALSE) {// Check GetLastError for LookupAccountSid error condition.
        DWORD dwErrorCode = 0;
        dwErrorCode = GetLastError();
        if (dwErrorCode == ERROR_NONE_MAPPED)
            _tprintf(TEXT("Account owner not found for specified SID.\n"));
        else
            _tprintf(TEXT("Error in LookupAccountSid.\n"));
        return -1;
    } else if (bRtnBool == TRUE) {
        _tprintf(TEXT("Account owner = %s\n"), AcctName);// Print the account name.
    }

    return 0;
}


EXTERN_C
__declspec(dllexport)
BOOL WINAPI TakeOwnership(LPTSTR lpszOwnFile)
/*
Taking Object Ownership in C++
05/31/2018

The following example tries to change the DACL of a file object by taking ownership of that object.
This will succeed only if the caller has WRITE_DAC access to the object or is the owner of the object.
If the initial attempt to change the DACL fails, an administrator can take ownership of the object.
To give the administrator ownership, the example enables the SE_TAKE_OWNERSHIP_NAME privilege in the caller's access token,
and makes the local system's Administrators group the owner of the object.
If the caller is a member of the Administrators group, the code will then be able to change the object's DACL.

https://docs.microsoft.com/en-us/windows/win32/secauthz/taking-object-ownership-in-c--
*/
{
    BOOL bRetval = FALSE;
    HANDLE hToken = NULL;
    PSID pSIDAdmin = NULL;
    PSID pSIDEveryone = NULL;
    PACL pACL = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
    const int NUM_ACES = 2;
    EXPLICIT_ACCESS ea[NUM_ACES];
    DWORD dwRes;

    // Specify the DACL to use.
    // Create a SID for the Everyone group.
    if (!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pSIDEveryone)) {
        printf("AllocateAndInitializeSid (Everyone) error %u\n", GetLastError());
        goto Cleanup;
    }

    // Create a SID for the BUILTIN\Administrators group.
    if (!AllocateAndInitializeSid(&SIDAuthNT, 2,
                                  SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS,
                                  0, 0, 0, 0, 0, 0,
                                  &pSIDAdmin)) {
        printf("AllocateAndInitializeSid (Admin) error %u\n", GetLastError());
        goto Cleanup;
    }

    ZeroMemory(&ea, NUM_ACES * sizeof(EXPLICIT_ACCESS));

    // Set read access for Everyone.
    ea[0].grfAccessPermissions = GENERIC_READ;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName = (LPTSTR)pSIDEveryone;

    // Set full control for Administrators.
    ea[1].grfAccessPermissions = GENERIC_ALL;
    ea[1].grfAccessMode = SET_ACCESS;
    ea[1].grfInheritance = NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea[1].Trustee.ptstrName = (LPTSTR)pSIDAdmin;

    if (ERROR_SUCCESS != SetEntriesInAcl(NUM_ACES, ea, NULL, &pACL)) {
        printf("Failed SetEntriesInAcl\n");
        goto Cleanup;
    }

    // Try to modify the object's DACL.
    dwRes = SetNamedSecurityInfo(
        lpszOwnFile,                 // name of the object
        SE_FILE_OBJECT,              // type of object
        DACL_SECURITY_INFORMATION,   // change only the object's DACL
        NULL, NULL,                  // do not change owner or group
        pACL,                        // DACL specified
        NULL);                       // do not change SACL
    if (ERROR_SUCCESS == dwRes) {
        printf("Successfully changed DACL\n");
        bRetval = TRUE;
        // No more processing needed.
        goto Cleanup;
    }
    if (dwRes != ERROR_ACCESS_DENIED) {
        printf("First SetNamedSecurityInfo call failed: %u\n", dwRes);
        goto Cleanup;
    }

    // If the preceding call failed because access was denied, 
    // enable the SE_TAKE_OWNERSHIP_NAME privilege, create a SID for 
    // the Administrators group, take ownership of the object, and 
    // disable the privilege. Then try again to set the object's DACL.

    // Open a handle to the access token for the calling process.
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        printf("OpenProcessToken failed: %u\n", GetLastError());
        goto Cleanup;
    }

    // Enable the SE_TAKE_OWNERSHIP_NAME privilege.
    if (!SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, TRUE)) {
        printf("You must be logged on as Administrator.\n");
        goto Cleanup;
    }

    // Set the owner in the object's security descriptor.
    dwRes = SetNamedSecurityInfo(
        lpszOwnFile,                 // name of the object
        SE_FILE_OBJECT,              // type of object
        OWNER_SECURITY_INFORMATION,  // change only the object's owner
        pSIDAdmin,                   // SID of Administrator group
        NULL,
        NULL,
        NULL);
    if (dwRes != ERROR_SUCCESS) {
        printf("Could not set owner. Error: %u\n", dwRes);
        goto Cleanup;
    }

    // Disable the SE_TAKE_OWNERSHIP_NAME privilege.
    if (!SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, FALSE)) {
        printf("Failed SetPrivilege call unexpectedly.\n");
        goto Cleanup;
    }

    // Try again to modify the object's DACL, now that we are the owner.
    dwRes = SetNamedSecurityInfo(
        lpszOwnFile,                 // name of the object
        SE_FILE_OBJECT,              // type of object
        DACL_SECURITY_INFORMATION,   // change only the object's DACL
        NULL, NULL,                  // do not change owner or group
        pACL,                        // DACL specified
        NULL);                       // do not change SACL
    if (dwRes == ERROR_SUCCESS) {
        printf("Successfully changed DACL\n");
        bRetval = TRUE;
    } else {
        printf("Second SetNamedSecurityInfo call failed: %u\n", dwRes);
    }

Cleanup:

    if (pSIDAdmin)
        FreeSid(pSIDAdmin);

    if (pSIDEveryone)
        FreeSid(pSIDEveryone);

    if (pACL)
        LocalFree(pACL);

    if (hToken)
        CloseHandle(hToken);

    return bRetval;
}


EXTERN_C
__declspec(dllexport)
DWORD WINAPI AddAceToObjectsSecurityDescriptor(
    LPTSTR pszObjName,          // name of object
    SE_OBJECT_TYPE ObjectType,  // type of object
    LPTSTR pszTrustee,          // trustee for new ACE
    TRUSTEE_FORM TrusteeForm,   // format of trustee structure
    DWORD dwAccessRights,       // access mask for new ACE
    ACCESS_MODE AccessMode,     // type of ACE
    DWORD dwInheritance         // inheritance flags for new ACE
)
/*
Modifying the ACLs of an Object in C++
05/31/2018

The following example adds an access control entry (ACE) to the discretionary access control list (DACL) of an object.

The AccessMode parameter determines the type of new ACE and how the new ACE is combined with any existing ACEs for the specified trustee.
Use the GRANT_ACCESS, SET_ACCESS, DENY_ACCESS, or REVOKE_ACCESS flags in the AccessMode parameter.
For information about these flags, see ACCESS_MODE.

Similar code can be used to work with a system access control list (SACL).
Specify SACL_SECURITY_INFORMATION in the GetNamedSecurityInfo and SetNamedSecurityInfo functions to get and set the SACL for the object.
Use the SET_AUDIT_SUCCESS, SET_AUDIT_FAILURE, and REVOKE_ACCESS flags in the AccessMode parameter.
For information about these flags, see ACCESS_MODE.

Use this code to add an object-specific ACE to the DACL of a directory service object.
To specify the GUIDs in an object-specific ACE, set the TrusteeForm parameter to TRUSTEE_IS_OBJECTS_AND_NAME or
TRUSTEE_IS_OBJECTS_AND_SID and set the pszTrustee parameter to be a pointer to an OBJECTS_AND_NAME or OBJECTS_AND_SID structure.

This example uses the GetNamedSecurityInfo function to get the existing DACL.
Then it fills an EXPLICIT_ACCESS structure with information about an ACE and
uses the SetEntriesInAcl function to merge the new ACE with any existing ACEs in the DACL.
Finally, the example calls the SetNamedSecurityInfo function to attach the new DACL to the security descriptor of the object.

https://docs.microsoft.com/en-us/windows/win32/secauthz/modifying-the-acls-of-an-object-in-c--
*/
{
    DWORD dwRes = 0;
    PACL pOldDACL = NULL, pNewDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESS ea;

    if (NULL == pszObjName)
        return ERROR_INVALID_PARAMETER;

    // Get a pointer to the existing DACL.
    dwRes = GetNamedSecurityInfo(pszObjName, ObjectType,
                                 DACL_SECURITY_INFORMATION,
                                 NULL, NULL, &pOldDACL, NULL, &pSD);
    if (ERROR_SUCCESS != dwRes) {
        printf("GetNamedSecurityInfo Error %u\n", dwRes);
        goto Cleanup;
    }

    // Initialize an EXPLICIT_ACCESS structure for the new ACE. 
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = dwAccessRights;
    ea.grfAccessMode = AccessMode;
    ea.grfInheritance = dwInheritance;
    ea.Trustee.TrusteeForm = TrusteeForm;
    ea.Trustee.ptstrName = pszTrustee;

    // Create a new ACL that merges the new ACE into the existing DACL.
    dwRes = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL);
    if (ERROR_SUCCESS != dwRes) {
        printf("SetEntriesInAcl Error %u\n", dwRes);
        goto Cleanup;
    }

    // Attach the new ACL as the object's DACL.
    dwRes = SetNamedSecurityInfo(pszObjName, ObjectType,
                                 DACL_SECURITY_INFORMATION,
                                 NULL, NULL, pNewDACL, NULL);
    if (ERROR_SUCCESS != dwRes) {
        printf("SetNamedSecurityInfo Error %u\n", dwRes);
        goto Cleanup;
    }

Cleanup:

    if (pSD != NULL)
        LocalFree((HLOCAL)pSD);
    if (pNewDACL != NULL)
        LocalFree((HLOCAL)pNewDACL);

    return dwRes;
}


EXTERN_C
__declspec(dllexport)
BOOL WINAPI ImpersonateAndCheckAccess(
    HANDLE hNamedPipe,               // handle of pipe to impersonate
    PSECURITY_DESCRIPTOR pSD,        // security descriptor to check
    DWORD dwAccessDesired,           // access rights to check
    PGENERIC_MAPPING pGeneric,       // generic mapping for object
    PDWORD pdwAccessAllowed          // returns allowed access rights
)
/*
Verifying Client Access with ACLs in C++
05/31/2018

The following example shows how a server could check the access rights that a security descriptor allows for a client.
The example uses the ImpersonateNamedPipeClient function; however,
it would work the same using any of the other impersonation functions.
After impersonating the client, the example calls the OpenThreadToken function to get the impersonation token.
Then, it calls the MapGenericMask function to convert any generic access rights to the corresponding specific and
standard rights according to the mapping specified in the GENERIC_MAPPING structure.

The AccessCheck function checks the requested access rights against the rights allowed for the client in the DACL of the security descriptor.
To check access and generate an entry in the security event log, use the AccessCheckAndAuditAlarm function.

https://docs.microsoft.com/en-us/windows/win32/secauthz/verifying-client-access-with-acls-in-c--
*/
{
    HANDLE hToken;
    PRIVILEGE_SET PrivilegeSet;
    DWORD dwPrivSetSize = sizeof(PRIVILEGE_SET);
    BOOL fAccessGranted = FALSE;

    // Impersonate the client.
    if (!ImpersonateNamedPipeClient(hNamedPipe))
        return FALSE;

    // Get an impersonation token with the client's security context.
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &hToken)) {
        goto Cleanup;
    }

    // Use the GENERIC_MAPPING structure to convert any 
    // generic access rights to object-specific access rights.
    MapGenericMask(&dwAccessDesired, pGeneric);

    // Check the client's access rights.
    if (!AccessCheck(
        pSD,                 // security descriptor to check
        hToken,              // impersonation token
        dwAccessDesired,     // requested access rights
        pGeneric,            // pointer to GENERIC_MAPPING
        &PrivilegeSet,       // receives privileges used in check
        &dwPrivSetSize,      // size of PrivilegeSet buffer
        pdwAccessAllowed,    // receives mask of allowed access rights
        &fAccessGranted))   // receives results of access check
    {
        goto Cleanup;
    }

Cleanup:
    RevertToSelf();
    if (hToken != INVALID_HANDLE_VALUE)
        CloseHandle(hToken);
    return fAccessGranted;
}


EXTERN_C
__declspec(dllexport)
void WINAPI CheckAccessWithBusinessLogic(ULONGLONG hToken)
//  Void CheckAccess().
/*
Qualifying Access with Business Logic in C++
05/31/2018

Use business rule scripts to provide run-time logic for checking access.
For more information about business rules, see Business Rules.

To assign a business rule to a task, first set the BizRuleLanguage property of the IAzTask object that represents the task.
The script must be in Visual Basic Scripting Edition or JScript.
After you specify the script language, set the BizRule property of the IAzTask object with a string representation of the script.

When checking access for an operation contained by a task that has an associated business rule,
the application must create two arrays of the same size to be passed as the varParameterNames and
varParameterValues parameters of the IAzClientContext::AccessCheck method.
For information about creating a client context, see Establishing a Client Context with Authorization Manager in C++.

The IAzClientContext::AccessCheck method creates an AzBizRuleContext object that is passed to the business rule script.
The script then sets the BusinessRuleResult property of the AzBizRuleContext object.
A value of TRUE indicates that access is granted, and a value of FALSE indicates that access is denied.

A business rule script cannot be assigned to an IAzTask object contained by a delegated IAzScope object.

The following example shows how to use a business rule script to check a client's access to an operation.
The example assumes that there is an existing XML policy store named MyStore.xml in the root directory of drive C,
that this store contains an application named Expense,
a task named Submit Expense, and an operation named UseFormControl, and that the variable hToken contains a valid client token.

https://docs.microsoft.com/en-us/windows/win32/secauthz/qualifying-access-with-business-logic-in-c--
*/
{
    IAzAuthorizationStore * pStore = NULL;
    IAzApplication * pApp = NULL;
    IAzClientContext * pClientContext = NULL;
    IAzOperation * pOperation = NULL;
    IAzTask * pTask = NULL;
    BSTR storeName = NULL;
    BSTR appName = NULL;
    BSTR operationName = NULL;
    BSTR objectName = NULL;
    BSTR taskName = NULL;
    BSTR bizRule = NULL;
    BSTR bizRuleLanguage = NULL;
    LONG operationID;
    HRESULT hr;
    VARIANT varOperationIdArray;
    VARIANT varOperationId;
    VARIANT varResultsArray;
    VARIANT varResult;
    VARIANT varParamName;
    VARIANT varParamValue;
    VARIANT nameString;
    VARIANT expenseAmount;
    VARIANT myVar;
    VariantInit(&myVar);

    //  Initialize COM.
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize COM.");

    //  Create the AzAuthorizationStore object.
    hr = CoCreateInstance(
        __uuidof(AzAuthorizationStore),/*"b2bcff59-a757-4b0b-a1bc-ea69981da69e"*/
        NULL,
        CLSCTX_ALL,
        __uuidof(IAzAuthorizationStore),/*"edbd9ca9-9b82-4f6a-9e8b-98301e450f14"*/
        (void **)&pStore);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create AzAuthorizationStore object.");

    //  Allocate a string for the policy store.
    if (!(storeName = SysAllocString(L"msxml://c:\\MyStore.xml")))
        MyHandleError("Could not allocate string.");

    //  Initialize the store.
    hr = pStore->Initialize(0, storeName, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize store.");

    //  Create an application object.
    if (!(appName = SysAllocString(L"Expense")))
        MyHandleError("Could not allocate application name string.");
    hr = pStore->OpenApplication(appName, myVar, &pApp);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not open application.");

    //  Create a client context from a token handle.
    hr = pApp->InitializeClientContextFromToken(hToken, myVar, &pClientContext);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create client context.");

    //  Create a business rule for the Submit Expense task.

    //  Open the Submit Expense task.
    if (!(taskName = SysAllocString(L"Submit Expense")))
        MyHandleError("Could not allocate task name string.");
    hr = pApp->OpenTask(taskName, myVar, &pTask);

    //  Assign a business rule to the task.

    //  Set the business rule language to VBScript.
    if (!(bizRuleLanguage = SysAllocString(L"VBScript")))
        MyHandleError("Could not allocate business rule language string.");
    hr = pTask->put_BizRuleLanguage(bizRuleLanguage);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not allocate business rule language string.");

    //  Create a BSTR with the business rule code.
    if (!(bizRule = SysAllocString(
        L"Dim Amount \n"
        L"AzBizRuleContext.BusinessRuleResult = FALSE \n"
        L"Amount = AzBizRuleContext.GetParameter(\"ExpAmount\") \n"
        L"if Amount < 500 then AzBizRuleContext.BusinessRuleResult = TRUE")))
        MyHandleError("Could not allocate business rule string.");

    hr = pTask->put_BizRule(bizRule);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not assign business rule.");

    //  Save the new task data to the store.
    hr = pTask->Submit(0, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not save task data.");

    //  Set up parameters for access check.

    //  Set up the object name.
    if (!(operationName = SysAllocString(L"UseFormControl")))
        MyHandleError("Could not allocate operation name string.");

    //  Get the ID of the operation to check.
    hr = pApp->OpenOperation(operationName, myVar, &pOperation);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not open operation.");

    hr = pOperation->get_OperationID(&operationID);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not get operation ID.");

    //  Create a SAFEARRAY for the operation ID.
    varOperationIdArray.parray = SafeArrayCreateVector(VT_VARIANT, 0, 1);

    //  Create an array of indexes.
    LONG * index = new LONG[1];
    index[0] = 0;

    //  Populate a SAFEARRAY with the operation ID.
    varOperationId.vt = VT_I4;
    varOperationId.lVal = operationID;

    hr = SafeArrayPutElement(varOperationIdArray.parray, index, &varOperationId);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not put operation ID in array.");

    //  Set SAFEARRAY type.
    varOperationIdArray.vt = VT_ARRAY | VT_VARIANT;

    //  Create business rule parameters.

    //  Create array of business rule parameter names.
    varParamName.parray = SafeArrayCreateVector(VT_VARIANT, 0, 1);
    varParamName.vt = VT_ARRAY | VT_VARIANT;
    nameString.vt = VT_BSTR;
    nameString.bstrVal = SysAllocString(L"ExpAmount");
    (void)SafeArrayPutElement(varParamName.parray, index, &nameString);

    //  Create array of business rule parameter values.
    varParamValue.parray = SafeArrayCreateVector(VT_VARIANT, 0, 1);
    varParamValue.vt = VT_ARRAY | VT_VARIANT;
    expenseAmount.vt = VT_I4;
    expenseAmount.lVal = 100;  // access denied if 500 or more
    (void)SafeArrayPutElement(varParamValue.parray, index, &expenseAmount);

    if (!(objectName = SysAllocString(L"UseFormControl")))//used for audit
        MyHandleError("Could not allocate object name string.");

    //  Check access.
    hr = pClientContext->AccessCheck(
        objectName,
        myVar,                  // use default application scope
        varOperationIdArray,
        varParamName,
        varParamValue,
        myVar,
        myVar,
        myVar,
        &varResultsArray);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not complete access check.");

    hr = SafeArrayGetElement(varResultsArray.parray, index, &varResult);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not get result from array.");

    if (varResult.lVal == 0)
        printf("Access granted.\n");
    else
        printf("Access denied.\n");

    //  Clean up resources.
    pStore->Release();
    pApp->Release();
    pOperation->Release();
    pClientContext->Release();
    pTask->Release();
    SysFreeString(storeName);
    SysFreeString(appName);
    SysFreeString(operationName);
    SysFreeString(objectName);
    SysFreeString(taskName);
    SysFreeString(bizRule);
    SysFreeString(bizRuleLanguage);
    VariantClear(&myVar);
    VariantClear(&varOperationIdArray);
    VariantClear(&varOperationId);
    VariantClear(&varResultsArray);
    VariantClear(&varResult);
    VariantClear(&varParamName);
    VariantClear(&varParamValue);
    VariantClear(&nameString);
    VariantClear(&expenseAmount);
    CoUninitialize();
}


EXTERN_C
__declspec(dllexport)
void WINAPI ExpenseCheck(ULONGLONG hToken)
/*
Establishing a Client Context with Authorization Manager in C++
05/31/2018

In Authorization Manager,
an application determines whether a client is given access to an operation by calling the AccessCheck method of an IAzClientContext object,
which represents a client context.

An application can create a client context with a handle to a token, a domain and user name,
or a string representation of the security identifier (SID) of the client.

Use the InitializeClientContextFromToken, InitializeClientContextFromName,
and InitializeClientContextFromStringSid methods of the IAzApplication interface to create a client context.

The following example shows how to create an IAzClientContext object from a client token.
The example assumes that there is an existing XML policy store named MyStore.xml in the root directory of drive C,
that this store contains an application named Expense, and that the variable hToken contains a valid client token.

https://docs.microsoft.com/en-us/windows/win32/secauthz/establishing-a-client-context-with-authorization-manager-in-c--
*/
{
    IAzAuthorizationStore * pStore = NULL;
    IAzApplication * pApp = NULL;
    IAzClientContext * pClientContext = NULL;
    BSTR storeName = NULL;
    BSTR appName = NULL;
    HRESULT hr;

    //  Create a null VARIANT for function parameters.
    VARIANT myVar;
    VariantInit(&myVar);

    //  Initialize COM.
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize COM.");

    //  Create the AzAuthorizationStore object.
    hr = CoCreateInstance(
        __uuidof(AzAuthorizationStore),/*"b2bcff59-a757-4b0b-a1bc-ea69981da69e"*/
        NULL,
        CLSCTX_ALL,
        __uuidof(IAzAuthorizationStore),/*"edbd9ca9-9b82-4f6a-9e8b-98301e450f14"*/
        (void **)&pStore);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create AzAuthorizationStore object.");

    //  Allocate a string for the policy store.
    if (!(storeName = SysAllocString(L"msxml://c:\\MyStore.xml")))
        MyHandleError("Could not allocate string.");

    //  Initialize the store.
    hr = pStore->Initialize(0, storeName, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize store.");

    //  Create an application object.
    if (!(appName = SysAllocString(L"Expense")))
        MyHandleError("Could not allocate application name string.");
    hr = pStore->OpenApplication(appName, myVar, &pApp);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not open application.");

    //  Create a client context from a token handle.
    hr = pApp->InitializeClientContextFromToken(hToken, myVar, &pClientContext);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create client context.");

    //  Use the client context as needed.

    //  Clean up resources.
    pStore->Release();
    pApp->Release();
    pClientContext->Release();
    SysFreeString(storeName);
    SysFreeString(appName);
    VariantClear(&myVar);
    CoUninitialize();
}


//////////////////////////////////////////////////////////////////////////////////////////////////
//Creating an Authorization Policy Store in C++


void CreatingActiveDirectoryStore(void)
/*
Creating an Active Directory Store
To use Active Directory to store the authorization policy,
the domain must be in the Windows Server 2003 domain functional level.
The authorization policy store cannot be located in a Non-Domain Naming Context (also called an application partition).
It is recommended that the store be located in the Program Data container under a new organizational unit created specifically for the authorization policy store.
It is also recommended that the store be located within the same local area network as application servers that run applications that use the store.

The following example shows how to create an AzAuthorizationStore object that represents an authorization policy store in Active Directory.
The example assumes that there is an existing Active Directory organizational unit named Program Data in a domain named authmanager.com.

https://docs.microsoft.com/en-us/windows/win32/secauthz/creating-an-authorization-policy-store-object-in-c--
*/
{
    IAzAuthorizationStore * pStore = NULL;
    HRESULT hr;
    BSTR storeName = NULL;

    //  Initialize COM.
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize COM.");

    //  Create the AzAuthorizationStore object.
    hr = CoCreateInstance(
        __uuidof(AzAuthorizationStore),/*"b2bcff59-a757-4b0b-a1bc-ea69981da69e"*/
        NULL,
        CLSCTX_ALL,
        __uuidof(IAzAuthorizationStore),/*"edbd9ca9-9b82-4f6a-9e8b-98301e450f14"*/
        (void **)&pStore);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create AzAuthorizationStore object.");

    //  Create a null VARIANT for function parameters.
    VARIANT myVar;
    VariantInit(&myVar);

    //  Allocate a string for the distinguished name of the Active Directory store.
    if (!(storeName = SysAllocString(L"msldap://CN=MyAzStore,CN=Program Data,DC=authmanager,DC=com")))
        MyHandleError("Could not allocate string.");

    //  Initialize the store in Active Directory. Use the
 //  AZ_AZSTORE_FLAG_CREATE flag.
    hr = pStore->Initialize(AZ_AZSTORE_FLAG_CREATE, storeName, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize store.");

    //  Call the submit method to save changes to the new store.
    hr = pStore->Submit(0, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not save data to the store.");

    //  Clean up resources.
    pStore->Release();
    VariantClear(&myVar);
    SysFreeString(storeName);
    CoUninitialize();
}


void CreatingSQLServerStore(void)
/*
Creating a SQL Server Store
Authorization Manager supports creating a Microsoft SQL Server–based authorization policy store.
To create a SQL Server–based authorization store, use a URL that begins with the prefix MSSQL://.
The URL must contain a valid SQL connection string, a database name,
and the name of the authorization policy store: **MSSQL://ConnectionString/DatabaseName/**PolicyStoreName.

If the instance of SQL Server does not contain the specified Authorization Manager database,
Authorization Manager creates a new database with that name.

 Note
Connections to a SQL Server store are not encrypted unless you explicitly set up SQL encryption for the connection or set up encryption of the network traffic that uses Internet Protocol Security (IPsec).

The following example shows how to create an AzAuthorizationStore object that represents an authorization policy store in a SQL Server database.

https://docs.microsoft.com/en-us/windows/win32/secauthz/creating-an-authorization-policy-store-object-in-c--
*/
{
    IAzAuthorizationStore * pStore = NULL;
    HRESULT hr;
    BSTR storeName = NULL;

    //  Initialize COM.
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize COM.");

    //  Create the AzAuthorizationStore object.
    hr = CoCreateInstance(
        __uuidof(AzAuthorizationStore),/*"b2bcff59-a757-4b0b-a1bc-ea69981da69e"*/
        NULL,
        CLSCTX_ALL,
        __uuidof(IAzAuthorizationStore),/*"edbd9ca9-9b82-4f6a-9e8b-98301e450f14"*/
        (void **)&pStore);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create AzAuthorizationStore object.");

    VARIANT myVar;
    myVar.vt = VT_NULL;

    //  Allocate a string for the SQL Server store.
    if (!(storeName = SysAllocString(L"MSSQL://Driver={SQL Server};Server={AzServer};/AzDB/MyStore")))
        MyHandleError("Could not allocate string.");

    //  Initialize the store. Use the AZ_AZSTORE_FLAG_CREATE flag.
    hr = pStore->Initialize(AZ_AZSTORE_FLAG_CREATE, storeName, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize store.");

    //  Call the submit method to save changes to the new store.
    hr = pStore->Submit(0, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not save data to the store.");

    //  Clean up resources.
    pStore->Release();
    SysFreeString(storeName);
    CoUninitialize();
}


void CreatingXMLStore(void)
/*
Creating an XML Store
Authorization Manager supports creating an authorization policy store in XML format.
The XML store can be located on the same computer where the application runs, or it can be stored remotely.
Editing the XML file directly is not supported.
Use the Authorization Manager MMC snap-in or the Authorization Manager API to edit the policy store.

Authorization Manager does not support delegating administration of an XML policy store.
For information about delegation, see Delegating the Defining of Permissions in C++.

The following example shows how to create an AzAuthorizationStore object that represents an authorization policy store in an XML file.

https://docs.microsoft.com/en-us/windows/win32/secauthz/creating-an-authorization-policy-store-object-in-c--
*/
{
    IAzAuthorizationStore * pStore = NULL;
    HRESULT hr;
    BSTR storeName = NULL;

    //  Initialize COM.
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize COM.");

    //  Create the AzAuthorizationStore object.
    hr = CoCreateInstance(
        __uuidof(AzAuthorizationStore),/*"b2bcff59-a757-4b0b-a1bc-ea69981da69e"*/
        NULL,
        CLSCTX_ALL,
        __uuidof(IAzAuthorizationStore),/*"edbd9ca9-9b82-4f6a-9e8b-98301e450f14"*/
        (void **)&pStore);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create AzAuthorizationStore object.");

    VARIANT myVar;
    myVar.vt = VT_NULL;

    //  Allocate a string for the distinguished name of the XML store.
    if (!(storeName = SysAllocString(L"msxml://C:\\MyStore.xml")))
        MyHandleError("Could not allocate string.");

    //  Initialize the store in an XML file. Use the AZ_AZSTORE_FLAG_CREATE flag.
    hr = pStore->Initialize(AZ_AZSTORE_FLAG_CREATE, storeName, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize store.");

    //  Call the submit method to save changes to the new store.
    hr = pStore->Submit(0, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not save data to the store.");

    //  Clean up resources.
    pStore->Release();
    SysFreeString(storeName);
    CoUninitialize();
}


void CreatingApplicationObject(void)
/*
Creating an Application Object in C++
05/31/2018

An authorization policy store contains authorization policy information for one or more applications.
For each application that uses that policy store, you must create an IAzApplication object and save it to a policy store.

The following example shows how to create an IAzApplication object that represents an application and how to add
the IAzApplication object to the authorization policy store the application uses.
The example assumes that there is an existing XML policy store named MyStore.xml in the root directory of drive C.

https://docs.microsoft.com/en-us/windows/win32/secauthz/creating-an-application-object-in-c--
*/
{
    IAzAuthorizationStore * pStore = NULL;
    IAzApplication * pApp = NULL;
    HRESULT hr;
    BSTR storeName = NULL;
    BSTR appName = NULL;

    //  Initialize COM.
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize COM.");

    //  Create the AzAuthorizationStore object.
    hr = CoCreateInstance(
        __uuidof(AzAuthorizationStore),/*"b2bcff59-a757-4b0b-a1bc-ea69981da69e"*/
        NULL,
        CLSCTX_ALL,
        __uuidof(IAzAuthorizationStore),/*"edbd9ca9-9b82-4f6a-9e8b-98301e450f14"*/
        (void **)&pStore);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create AzAuthorizationStore object.");

    //  Create null VARIANT for parameters.
    VARIANT myVar;
    VariantInit(&myVar);

    //  Allocate a string for the name of the store.
    if (!(storeName = SysAllocString(L"msxml://c:\\MyStore.xml")))
        MyHandleError("Could not allocate string.");

    //  Initialize the existing store.
    hr = pStore->Initialize(AZ_AZSTORE_FLAG_MANAGE_STORE_ONLY, storeName, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize store.");

    //  Create an application object.
    if (!(appName = SysAllocString(L"Expense")))
        MyHandleError("Could not allocate application name string");
    hr = pStore->CreateApplication(appName, myVar, &pApp);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create application.");

    //  Save changes to the store.
    hr = pApp->Submit(0, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not save changes to store.");

    //  Clean up resources.
    pStore->Release();
    pApp->Release();
    SysFreeString(storeName);
    SysFreeString(appName);
    VariantClear(&myVar);
    CoUninitialize();
}


void DefiningOperations(void)
/*
Defining Operations in C++
05/31/2018

In Authorization Manager, an operation is a low-level function or method of an application.
These operations are grouped together as tasks.
Users of the application request permission to complete tasks.
An operation is represented by an IAzOperation object.
For more information about operations, see Operations and Tasks.

The following example shows how to define operations in an authorization policy store.
The example assumes that there is an existing XML policy store named MyStore.xml in the root directory of drive C,
and that this store contains an application named Expense.

https://docs.microsoft.com/en-us/windows/win32/secauthz/defining-operations-in-c--
*/
{
    IAzAuthorizationStore * pStore = NULL;
    IAzApplication * pApp = NULL;
    IAzOperation * pOp = NULL;
    HRESULT hr;
    BSTR storeName = NULL;
    BSTR appName = NULL;
    BSTR opName = NULL;

    //  Initialize COM.
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize COM.");

    //  Create the AzAuthorizationStore object.
    hr = CoCreateInstance(
        __uuidof(AzAuthorizationStore),/*"b2bcff59-a757-4b0b-a1bc-ea69981da69e"*/
        NULL,
        CLSCTX_ALL,
        __uuidof(IAzAuthorizationStore),/*"edbd9ca9-9b82-4f6a-9e8b-98301e450f14"*/
        (void **)&pStore);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create AzAuthorizationStore object.");

    //  Create null VARIANT for parameters.
    VARIANT myVar;
    VariantInit(&myVar);

    //  Allocate a string for the name of the store.
    if (!(storeName = SysAllocString(L"msxml://c:\\MyStore.xml")))
        MyHandleError("Could not allocate string.");

    //  Initialize the store.
    hr = pStore->Initialize(AZ_AZSTORE_FLAG_MANAGE_STORE_ONLY, storeName, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize store.");

    //  Create an application object.
    if (!(appName = SysAllocString(L"Expense")))
        MyHandleError("Could not allocate application name string.");
    hr = pStore->OpenApplication(appName, myVar, &pApp);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not open application.");

    //  Create operations.

    //  Create first operation.
    if (!(opName = SysAllocString(L"RetrieveForm")))
        MyHandleError("Could not allocate operation name string.");
    hr = pApp->CreateOperation(opName, myVar, &pOp);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create operation.");

    //  Set the OperationID property.
    hr = pOp->put_OperationID(1);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not set operation ID.");

    //  Save the operation to the store.
    hr = pOp->Submit(0, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not save operation.");
    SysFreeString(opName);

    //  Create second operation.
    if (!(opName = SysAllocString(L"EnqueRequest")))
        MyHandleError("Could not allocate operation name string.");
    hr = pApp->CreateOperation(opName, myVar, &pOp);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create operation.");

    //  Set the OperationID property.
    hr = pOp->put_OperationID(2);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not set operation ID.");

    //  Save the operation to the store.
    hr = pOp->Submit(0, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not save operation.");
    SysFreeString(opName);

    //  Create third operation.
    if (!(opName = SysAllocString(L"DequeRequest")))
        MyHandleError("Could not allocate operation name string.");
    hr = pApp->CreateOperation(opName, myVar, &pOp);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create operation.");

    //  Set the OperationID property.
    hr = pOp->put_OperationID(3);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not set operation ID.");

    //  Save the operation to the store.
    hr = pOp->Submit(0, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not save operation.");
    SysFreeString(opName);

    //  Create fourth operation.
    if (!(opName = SysAllocString(L"UseFormControl")))
        MyHandleError("Could not allocate operation name string.");
    hr = pApp->CreateOperation(opName, myVar, &pOp);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create operation.");

    //  Set the OperationID property.
    hr = pOp->put_OperationID(4);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not set operation ID.");

    //  Save the operation to the store.
    hr = pOp->Submit(0, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not save operation.");
    SysFreeString(opName);

    //  Create fifth operation.
    if (!(opName = SysAllocString(L"MarkFormApproved")))
        MyHandleError("Could not allocate operation name string.");
    hr = pApp->CreateOperation(opName, myVar, &pOp);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create operation.");

    //  Set the OperationID property.
    hr = pOp->put_OperationID(5);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not set operation ID.");

    //  Save the operation to the store.
    hr = pOp->Submit(0, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not save operation.");
    SysFreeString(opName);

    //  Create sixth operation.
    if (!(opName = SysAllocString(L"SendApprovalNotify")))
        MyHandleError("Could not allocate operation name string.");
    hr = pApp->CreateOperation(opName, myVar, &pOp);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create operation.");

    //  Set the OperationID property.
    hr = pOp->put_OperationID(6);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not set operation ID.");

    //  Save the operation to the store.
    hr = pOp->Submit(0, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not save operation.");
    SysFreeString(opName);

    //  Clean up resources.
    pStore->Release();
    pApp->Release();
    pOp->Release();
    SysFreeString(storeName);
    SysFreeString(appName);
    VariantClear(&myVar);
    CoUninitialize();
}


void GroupingOperationsTasks(void)
/*
Grouping Operations into Tasks in C++
05/31/2018

In Authorization Manager, a task is a high-level action that users of an application need to complete.
Tasks are made up of operations, which are low-level functions and methods of the application.
A task is then assigned to those roles that must perform that task. A task is represented by an IAzTask object.
For more information about operations and tasks, see Operations and Tasks.

The following example shows how to group operations to create a task.
The example assumes that there is an existing XML policy store named MyStore.xml in the root directory of drive C,
that this store contains an application named Expense,
and that this application contains operations defined in the topic Defining Operations in C++.

https://docs.microsoft.com/en-us/windows/win32/secauthz/grouping-operations-into-tasks-in-c--
*/
{
    IAzAuthorizationStore * pStore = NULL;
    IAzApplication * pApp = NULL;
    IAzTask * pTask = NULL;
    HRESULT hr;
    BSTR storeName = NULL;
    BSTR appName = NULL;
    BSTR taskName = NULL;
    BSTR opName = NULL;

    //  Initialize COM.
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize COM.");

    //  Create the AzAuthorizationStore object.
    hr = CoCreateInstance(
        __uuidof(AzAuthorizationStore),/*"b2bcff59-a757-4b0b-a1bc-ea69981da69e"*/
        NULL,
        CLSCTX_ALL,
        __uuidof(IAzAuthorizationStore),/*"edbd9ca9-9b82-4f6a-9e8b-98301e450f14"*/
        (void **)&pStore);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create AzAuthorizationStore object.");

    //  Create null VARIANT for parameters.
    VARIANT myVar;
    VariantInit(&myVar);

    //  Allocate a string for the name of the store.
    if (!(storeName = SysAllocString(L"msxml://c:\\MyStore.xml")))
        MyHandleError("Could not allocate string.");

    //  Initialize the store.
    hr = pStore->Initialize(AZ_AZSTORE_FLAG_MANAGE_STORE_ONLY, storeName, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize store.");

    //  Create an application object.
    if (!(appName = SysAllocString(L"Expense")))
        MyHandleError("Could not allocate application name string.");
    hr = pStore->OpenApplication(appName, myVar, &pApp);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not open application.");

    //  Create a task object.
    if (!(taskName = SysAllocString(L"Submit Expense")))
        MyHandleError("Could not allocate task name string.");
    hr = pApp->CreateTask(taskName, myVar, &pTask);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create task.");

    //  Add operations to the task.
    if (!(opName = SysAllocString(L"RetrieveForm")))
        MyHandleError("Could not allocate operation name string.");
    hr = pTask->AddOperation(opName, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not add 1st operation to the task.");
    SysFreeString(opName);

    if (!(opName = SysAllocString(L"EnqueRequest")))
        MyHandleError("Could not allocate operation name string.");
    hr = pTask->AddOperation(opName, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not add 2nd operation to the task.");
    SysFreeString(opName);

    if (!(opName = SysAllocString(L"UseFormControl")))
        MyHandleError("Could not allocate operation name string.");
    hr = pTask->AddOperation(opName, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not add 3rd operation to the task.");
    SysFreeString(opName);

    //  Save information to the store.
    hr = pTask->Submit(0, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not save task data to the store.");

    //  Clean up resources.
    pStore->Release();
    pApp->Release();
    pTask->Release();
    SysFreeString(storeName);
    SysFreeString(appName);
    VariantClear(&myVar);
    CoUninitialize();
}


void GroupingTasksRoles(void)
/*
Grouping Tasks into Roles in C++
05/31/2018

In Authorization Manager,
a role represents a category of users and the tasks those users are authorized to perform.
Tasks are grouped together and assigned to a role definition,
which is represented by an IAzTask object with its IsRoleDefinition property set to TRUE.
The role definition can then be assigned to an IAzRole object,
and users or groups of users are then assigned to that object.
For more information about tasks and roles, see Roles.

The following example shows how to assign tasks to a role definition, create a role object,
and assign the role definition to the role object.
The example assumes that there is an existing XML policy store named MyStore.xml in the root directory of drive C,
that this store contains an application named Expense,
and that this application contains tasks named Submit Expense and Approve Expense.

https://docs.microsoft.com/en-us/windows/win32/secauthz/grouping-tasks-into-roles-in-c--
*/
{
    IAzAuthorizationStore * pStore = NULL;
    IAzApplication * pApp = NULL;
    IAzTask * pTaskRoleDef = NULL;
    IAzRole * pRole = NULL;
    HRESULT hr;
    BSTR storeName = NULL;
    BSTR appName = NULL;
    BSTR taskNameSubmit = NULL;
    BSTR taskNameApprove = NULL;
    BSTR roleDefName = NULL;
    BSTR roleName = NULL;

    //  Initialize COM.
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize COM.");

    //  Create the AzAuthorizationStore object.
    hr = CoCreateInstance(
        __uuidof(AzAuthorizationStore),/*"b2bcff59-a757-4b0b-a1bc-ea69981da69e"*/
        NULL,
        CLSCTX_ALL,
        __uuidof(IAzAuthorizationStore),/*"edbd9ca9-9b82-4f6a-9e8b-98301e450f14"*/
        (void **)&pStore);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create AzAuthorizationStore object.");

    //  Create null VARIANT for parameters.
    VARIANT myVar;
    VariantInit(&myVar);

    //  Allocate a string for the name of the policy store.
    storeName = SysAllocString(L"msxml://c:\\myStore.xml");
    if (!storeName)
        MyHandleError("Could not allocate string.");

    //  Initialize the store.
    hr = pStore->Initialize(AZ_AZSTORE_FLAG_MANAGE_STORE_ONLY, storeName, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize store.");

    //  Create an application object.
    appName = SysAllocString(L"Expense");
    if (!appName)
        MyHandleError("Could not allocate application name string.");
    hr = pStore->OpenApplication(appName, myVar, &pApp);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not open application.");

    //  Allocate strings for the task names.
    taskNameSubmit = SysAllocString(L"Submit Expense");
    if (!taskNameSubmit)
        MyHandleError("Could not allocate first task name string.");

    taskNameApprove = SysAllocString(L"Approve Expense");
    if (!taskNameApprove)
        MyHandleError("Could not allocate second task name string.");

    //  Create a third task object to act as a role definition.
    roleDefName = SysAllocString(L"Expense Admin");
    if (!roleDefName)
        MyHandleError("Could not allocate role definition name.");
    hr = pApp->CreateTask(roleDefName, myVar, &pTaskRoleDef);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create role definition.");

    //  Set the IsRoleDefinition property of pTaskRoleDef to TRUE.
    hr = pTaskRoleDef->put_IsRoleDefinition(true);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not set role definition property.");

    //  Add two tasks to the role definition.
    hr = pTaskRoleDef->AddTask(taskNameSubmit, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not add submit task.");
    hr = pTaskRoleDef->AddTask(taskNameApprove, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not add approve task.");

    //  Save information to the store.
    hr = pTaskRoleDef->Submit(0, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not save task data to the store.");

    //  Create an IAzRole object.
    roleName = SysAllocString(L"Expense Administrator");
    if (!roleName)
        MyHandleError("Could not allocate role name.");
    hr = pApp->CreateRole(roleName, myVar, &pRole);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create a role object.");

    //  Add the role definition to the role object.
    hr = pRole->AddTask(roleDefName, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could add role definition to the role.");

    //  Save information to the store.
    hr = pRole->Submit(0, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not save role data to the store.");

    //  Clean up resources.
    pStore->Release();
    pApp->Release();
    pTaskRoleDef->Release();
    pRole->Release();
    SysFreeString(storeName);
    SysFreeString(appName);
    SysFreeString(taskNameSubmit);
    SysFreeString(taskNameApprove);
    SysFreeString(roleDefName);
    SysFreeString(roleName);
    VariantClear(&myVar);
    CoUninitialize();
}


void CreatingBasicGroup(void)
/*
Creating a Basic Group
A basic application group is defined by the members included in the Members and
NonMembers properties of the IAzApplicationGroup object that represents the group.
Users and groups listed in the Members property are included in the application group,
and users and groups listed in the NonMembers property are excluded from the application group.
Being listed in the NonMembers property supersedes being listed in the Members property.

The following example shows how to create a basic application group and add all local users as members of that group.
The example assumes that there is an existing XML policy store named MyStore.xml in the root directory of drive C.

https://docs.microsoft.com/en-us/windows/win32/secauthz/defining-groups-of-users-in-c--
*/
{
    IAzAuthorizationStore * pStore = NULL;
    IAzApplicationGroup * pAppGroup = NULL;
    HRESULT hr;
    BSTR storeName = NULL;
    BSTR groupName = NULL;
    BSTR sidString = NULL;

    //  Initialize COM.
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize COM.");

    //  Create the AzAuthorizationStore object.
    hr = CoCreateInstance(
        __uuidof(AzAuthorizationStore),/*"b2bcff59-a757-4b0b-a1bc-ea69981da69e"*/
        NULL,
        CLSCTX_ALL,
        __uuidof(IAzAuthorizationStore),/*"edbd9ca9-9b82-4f6a-9e8b-98301e450f14"*/
        (void **)&pStore);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create AzAuthorizationStore object.");

    //  Create null VARIANT for parameters.
    VARIANT myVar;
    VariantInit(&myVar);

    //  Allocate a string for the name of the store.
    if (!(storeName = SysAllocString(L"msxml://c:\\MyStore.xml")))
        MyHandleError("Could not allocate string.");

    //  Initialize the store.
    hr = pStore->Initialize(AZ_AZSTORE_FLAG_MANAGE_STORE_ONLY, storeName, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize store.");

    //  Create an application group object.
    if (!(groupName = SysAllocString(L"Trusted Users")))
        MyHandleError("Could not allocate group name string");
    hr = pStore->CreateApplicationGroup(groupName, myVar, &pAppGroup);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create application group.");

    //  Add well-known SID for all local users to the group.
    if (!(sidString = SysAllocString(L"S-1-2-0")))
        MyHandleError("Could not allocate SID string name");
    hr = pAppGroup->AddMember(sidString, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not add member to group");

    //  Save changes to the store.
    pAppGroup->Submit(0, myVar);

    //  Clean up resources.
    pStore->Release();
    pAppGroup->Release();
    SysFreeString(storeName);
    SysFreeString(groupName);
    SysFreeString(sidString);
    VariantClear(&myVar);
    CoUninitialize();
}


void CreatingLDAPQueryGroup(void)
/*
Creating an LDAP Query Group
An LDAP query group has a membership defined by the query contained in the value of its LdapQuery property.

The following example shows how to create an LDAP query application group and add all users as members of that group.
The example assumes that there is an existing XML policy store named MyStore.xml in the root directory of drive C.

https://docs.microsoft.com/en-us/windows/win32/secauthz/defining-groups-of-users-in-c--
*/
{
    IAzAuthorizationStore * pStore = NULL;
    IAzApplicationGroup * pAppGroup = NULL;
    HRESULT hr;
    BSTR storeName = NULL;
    BSTR groupName = NULL;
    BSTR ldapString = NULL;

    //  Initialize COM.
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize COM.");

    //  Create the AzAuthorizationStore object.
    hr = CoCreateInstance(
        __uuidof(AzAuthorizationStore),/*"b2bcff59-a757-4b0b-a1bc-ea69981da69e"*/
        NULL,
        CLSCTX_ALL,
        __uuidof(IAzAuthorizationStore),/*"edbd9ca9-9b82-4f6a-9e8b-98301e450f14"*/
        (void **)&pStore);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create AzAuthorizationStore object.");

    VARIANT myVar;
    myVar.vt = VT_NULL;

    //  Allocate a string for the name of the store.
    if (!(storeName = SysAllocString(L"msxml://c:\\MyStore.xml")))
        MyHandleError("Could not allocate string.");

    //  Initialize the store.
    hr = pStore->Initialize(AZ_AZSTORE_FLAG_MANAGE_STORE_ONLY, storeName, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize store.");

    //  Create an application group object.
    if (!(groupName = SysAllocString(L"Trusted Users3")))
        MyHandleError("Could not allocate group name string");
    hr = pStore->CreateApplicationGroup(groupName, myVar, &pAppGroup);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create application group.");

    //  Set the Type property to AZ_GROUPTYPE_LDAP_QUERY.
    hr = pAppGroup->put_Type(AZ_GROUPTYPE_LDAP_QUERY);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Error changing type to LDAP query");

    //  Add LDAP query for all users.
    if (!(ldapString = SysAllocString(L"(&(objectCategory=person)(objectClass=user))")))
        MyHandleError("Could not allocate LDAP query string");
    hr = pAppGroup->put_LdapQuery(ldapString);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not add query to group");

    //  Save changes to the store.
    hr = pAppGroup->Submit(0, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not save changes to store.");

    //  Clean up resources.
    pStore->Release();
    pAppGroup->Release();
    SysFreeString(storeName);
    SysFreeString(groupName);
    SysFreeString(ldapString);
    CoUninitialize();
}


void AddingUsersToApplicationGroup(void)
/*
Adding Users to an Application Group in C++
05/31/2018

In Authorization Manager, an application group is a group of users and user groups.
An application group can contain other application groups, so groups of users can be nested.
An application group is represented by an IAzApplicationGroup object.

To allow members of an application group to perform a task or set of tasks,
assign that application group to a role that contains those tasks.
Roles are represented by IAzRole objects.

The following example shows how to create an application group, add a user as a member of the application group,
and assign the application group to an existing role.
The example assumes that there is an existing XML policy store named MyStore.xml in the root directory of drive C,
that this store contains an application named Expense,
and that this application contains a role named Expense Administrator.

https://docs.microsoft.com/en-us/windows/win32/secauthz/adding-users-to-an-application-group-in-c--
*/
{
    IAzAuthorizationStore * pStore = NULL;
    IAzApplication * pApp = NULL;
    IAzApplicationGroup * pAppGroup = NULL;
    IAzRole * pRole = NULL;
    HRESULT hr;
    BSTR storeName = NULL;
    BSTR appName = NULL;
    BSTR groupName = NULL;
    BSTR userName = NULL;
    BSTR roleName = NULL;

    //  Initialize COM.
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize COM.");

    //  Create the AzAuthorizationStore object.
    hr = CoCreateInstance(
        __uuidof(AzAuthorizationStore),/*"b2bcff59-a757-4b0b-a1bc-ea69981da69e"*/
        NULL,
        CLSCTX_ALL,
        __uuidof(IAzAuthorizationStore),/*"edbd9ca9-9b82-4f6a-9e8b-98301e450f14"*/
        (void **)&pStore);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create AzAuthorizationStore object.");

    //  Create null VARIANT for parameters.
    VARIANT myVar;
    VariantInit(&myVar);

    //  Allocate a string for the name of the policy store.
    if (!(storeName = SysAllocString(L"msxml://c:\\MyStore.xml")))
        MyHandleError("Could not allocate string.");

    //  Initialize the store.
    hr = pStore->Initialize(AZ_AZSTORE_FLAG_MANAGE_STORE_ONLY, storeName, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize store.");

    //  Create an application object.
    if (!(appName = SysAllocString(L"Expense")))
        MyHandleError("Could not allocate application name string.");
    hr = pStore->OpenApplication(appName, myVar, &pApp);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not open application.");

    //  Allocate a string for the group name.
    if (!(groupName = SysAllocString(L"Approvers")))
        MyHandleError("Could not allocate group name string.");

    //  Create an IAzApplicationGroup object.
    hr = pApp->CreateApplicationGroup(groupName, myVar, &pAppGroup);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create application group.");

    //  Add a member to the group.
 //  Replace with valid domain and user name.
    if (!(userName = SysAllocString(L"domain\\username")))
        MyHandleError("Could not allocate user name string.");

    hr = pAppGroup->AddMemberName(userName, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not add user to application group.");

    //  Save information to the store.
    hr = pAppGroup->Submit(0, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not save group information.");

    //  Open an IAzRole object.
    if (!(roleName = SysAllocString(L"Expense Administrator")))
        MyHandleError("Could not allocate role name string.");

    hr = pApp->OpenRole(roleName, myVar, &pRole);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not open role object.");

    //  Add the group to the role.
    hr = pRole->AddAppMember(groupName, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not add the application group to the role.");

    //  Save information to the store.
    hr = pRole->Submit(0, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not save role data to the store.");

    //  Clean up resources.
    pStore->Release();
    pApp->Release();
    pAppGroup->Release();
    pRole->Release();
    SysFreeString(storeName);
    SysFreeString(appName);
    SysFreeString(groupName);
    SysFreeString(roleName);
    SysFreeString(userName);
    VariantClear(&myVar);
    CoUninitialize();
}


//////////////////////////////////////////////////////////////////////////////////////////////////


void DelegatingDefiningPermissions(void)
/*
Delegating the Defining of Permissions in C++
05/31/2018

Authorization policy stores that are stored in Active Directory support delegation of administration.
Administration can be delegated to users and groups at the store, application, or scope level.

At each level, there is a list of administrators and readers. Administrators of a store, application,
or scope can read and modify the policy store at the delegated level.
Readers can read the policy store at the delegated level but cannot modify the store.

A user or group that is either an administrator or a reader of an application must also be added as a delegated user of the policy store that contains that application.
Similarly, a user or group that is an administrator or a reader of a scope must be added as a delegated user of the application that contains that scope.

For example, to delegate administration of a scope,
first add the user or group to the list of delegated users of the store that contains the scope by calling the IAzAuthorizationStore::AddDelegatedPolicyUser method.
Then add the user or group to the list of delegated users of the application that contains the scope by calling the IAzApplication::AddDelegatedPolicyUser method. Finally,
add the user or group to the list of administrators of the scope by calling the IAzScope::AddPolicyAdministrator method.

XML-based policy stores do not support delegation at any level.

A scope within an authorization store that is stored in Active Directory cannot be delegated if the scope contains task definitions that include authorization rules or role definitions that include authorization rules.

The following example shows how to delegate administration of an application.
The example assumes that there is an existing Active Directory authorization policy store at the specified location,
that this policy store contains an application named Expense,
and that this application contains no tasks with business rule scripts.

https://docs.microsoft.com/en-us/windows/win32/secauthz/delegating-the-defining-of-permissions-in-c--
*/
{
    IAzAuthorizationStore * pStore = NULL;
    IAzApplication * pApp = NULL;
    HRESULT hr;
    BSTR storeName = NULL;
    BSTR appName = NULL;
    BSTR userName = NULL;
    VARIANT myVar;

    //  Initialize COM.
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize COM.");

    //  Create the AzAuthorizationStore object.
    hr = CoCreateInstance(
        __uuidof(AzAuthorizationStore),/*"b2bcff59-a757-4b0b-a1bc-ea69981da69e"*/
        NULL,
        CLSCTX_ALL,
        __uuidof(IAzAuthorizationStore),/*"edbd9ca9-9b82-4f6a-9e8b-98301e450f14"*/
        (void **)&pStore);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create AzAuthorizationStore object.");

    //  Create null VARIANT for parameters.
    myVar.vt = VT_NULL;

    //  Allocate a string for the distinguished name of the Active Directory store.
    if (!(storeName = SysAllocString(L"msldap://CN=MyAzStore,CN=Program Data,DC=authmanager,DC=com")))
        MyHandleError("Could not allocate string.");

    //  Initialize the store.
    hr = pStore->Initialize(AZ_AZSTORE_FLAG_MANAGE_STORE_ONLY, storeName, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize store.");

    //  Create an application object.
    if (!(appName = SysAllocString(L"Expense")))
        MyHandleError("Could not allocate application name string.");
    hr = pStore->OpenApplication(appName, myVar, &pApp);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not open application.");

    //  Add a delegated policy user to the store.
    if (!(userName = SysAllocString(L"ExampleDomain\\UserName")))
        MyHandleError("Could not allocate username string.");
    hr = pStore->AddDelegatedPolicyUserName(userName, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not add user to store as delegated policy user.");

    //  Add the user as an administrator of the application.
    hr = pApp->AddPolicyAdministratorName(userName, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not add user to application as administrator.");

    //  Clean up resources.
    pStore->Release();
    pApp->Release();
    SysFreeString(storeName);
    SysFreeString(appName);
    SysFreeString(userName);
    CoUninitialize();
}


void CheckAccess(ULONGLONG hToken)
/*
Verifying Client Access to a Requested Resource in C++
05/31/2018

Call the AccessCheck method of the IAzClientContext interface to check if the client has access to one or more operations.
A client might have membership in more than one role, and an operation might be assigned to more than one task,
so Authorization Manager checks for all roles and tasks.
If any role to which the client belongs contains any task that contains an operation, access to that operation is granted.

To check access for only a single role to which the client belongs,
set the RoleForAccessCheck property of the IAzClientContext interface.

When initializing the authorization policy store for access check,
you must pass zero as the value of the lFlags parameter of the IAzAuthorizationStore::Initialize method.

The following example shows how to check a client's access to an operation.
The example assumes that there is an existing XML policy store named MyStore.xml in the root directory of drive C,
that this store contains an application named Expense and an operation named UseFormControl,
and that the variable hToken contains a valid client token.

https://docs.microsoft.com/en-us/windows/win32/secauthz/verifying-client-access-to-a-requested-resource-in-c--
*/
{
    IAzAuthorizationStore * pStore = NULL;
    IAzApplication * pApp = NULL;
    IAzClientContext * pClientContext = NULL;
    IAzOperation * pOperation = NULL;
    BSTR storeName = NULL;
    BSTR appName = NULL;
    BSTR operationName = NULL;
    BSTR objectName = NULL;
    LONG operationID;
    HRESULT hr;
    VARIANT varOperationIdArray;
    VARIANT varOperationId;
    VARIANT varResultsArray;
    VARIANT varResult;

    VARIANT myVar;
    VariantInit(&myVar);//.vt) = VT_NULL;

    //  Initialize COM.
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize COM.");

    //  Create the AzAuthorizationStore object.
    hr = CoCreateInstance(
        __uuidof(AzAuthorizationStore),/*"b2bcff59-a757-4b0b-a1bc-ea69981da69e"*/
        NULL,
        CLSCTX_ALL,
        __uuidof(IAzAuthorizationStore),/*"edbd9ca9-9b82-4f6a-9e8b-98301e450f14"*/
        (void **)&pStore);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create AzAuthorizationStore object.");

    //  Allocate a string for the  policy store.
    if (!(storeName = SysAllocString(L"msxml://c:\\myStore.xml")))
        MyHandleError("Could not allocate string.");

    //  Initialize the store.
    hr = pStore->Initialize(0, storeName, myVar);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not initialize store.");

    //  Create an application object.
    if (!(appName = SysAllocString(L"Expense")))
        MyHandleError("Could not allocate application name string.");
    hr = pStore->OpenApplication(appName, myVar, &pApp);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not open application.");

    //  Create a client context from a token handle.
    hr = pApp->InitializeClientContextFromToken(hToken, myVar, &pClientContext);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not create client context.");

    //  Set up parameters for access check.

    //  Set up the object name.
    if (!(operationName = SysAllocString(L"UseFormControl")))
        MyHandleError("Could not allocate operation name string.");

    //  Get the ID of the operation to check.
    hr = pApp->OpenOperation(operationName, myVar, &pOperation);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not open operation.");

    hr = pOperation->get_OperationID(&operationID);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not get operation ID.");

    //  Create a SAFEARRAY for the operation ID.
    varOperationIdArray.parray = SafeArrayCreateVector(VT_VARIANT, 0, 1);

    //  Set SAFEARRAY type.
    varOperationIdArray.vt = VT_ARRAY | VT_VARIANT;

    //  Create an array of indexes.
    LONG * index = new LONG[1];
    index[0] = 0;

    //  Populate a SAFEARRAY with the operation ID.
    varOperationId.vt = VT_I4;
    varOperationId.lVal = operationID;

    hr = SafeArrayPutElement(varOperationIdArray.parray, index, &varOperationId);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not put operation ID in array.");

    if (!(objectName = SysAllocString(L"UseFormControl")))//used for audit
        MyHandleError("Could not allocate object name string.");

    //  Check access.
    hr = pClientContext->AccessCheck(
        objectName,
        myVar,
        varOperationIdArray,
        myVar,               // use default application scope
        myVar,
        myVar,
        myVar,
        myVar,
        &varResultsArray);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not complete access check.");

    hr = SafeArrayGetElement(varResultsArray.parray, index, &varResult);
    if (!(SUCCEEDED(hr)))
        MyHandleError("Could not get result from array.");

    if (varResult.lVal == 0)
        printf("Access granted.\n");
    else
        printf("Access denied.\n");

    //  Clean up resources.
    pStore->Release();
    pApp->Release();
    pClientContext->Release();
    pOperation->Release();
    SysFreeString(storeName);
    SysFreeString(appName);
    SysFreeString(operationName);
    SysFreeString(objectName);
    VariantClear(&myVar);
    VariantClear(&varOperationIdArray);
    VariantClear(&varOperationId);
    VariantClear(&varResultsArray);
    VariantClear(&varResult);
    CoUninitialize();
}


//////////////////////////////////////////////////////////////////////////////////////////////////


BOOL AddAccessRights(TCHAR * lpszFileName, TCHAR * lpszAccountName, DWORD dwAccessMask)
/*
功能：给一个文件添加一个用户即相应的权限。

http://support.microsoft.com/kb/102102/zh-cn?wa=wsignin1.0
*/
{
    // SID variables.
    SID_NAME_USE   snuType;
    TCHAR * szDomain = NULL;
    DWORD          cbDomain = 0;
    LPVOID         pUserSID = NULL;
    DWORD          cbUserSID = 0;

    // File SD variables.
    PSECURITY_DESCRIPTOR pFileSD = NULL;
    DWORD          cbFileSD = 0;

    // New SD variables.
    SECURITY_DESCRIPTOR  newSD;

    // ACL variables.
    PACL           pACL = NULL;
    BOOL           fDaclPresent;
    BOOL           fDaclDefaulted;
    ACL_SIZE_INFORMATION AclInfo;

    // New ACL variables.
    PACL           pNewACL = NULL;
    DWORD          cbNewACL = 0;

    // Temporary ACE.
    LPVOID         pTempAce = NULL;
    UINT           CurrentAceIndex = 0;

    UINT           newAceIndex = 0;

    // Assume function will fail.
    BOOL           fResult = FALSE;
    BOOL           fAPISuccess;

    SECURITY_INFORMATION secInfo = DACL_SECURITY_INFORMATION;

    // New APIs available only in Windows 2000 and above for setting SD control
    SetSecurityDescriptorControlFnPtr _SetSecurityDescriptorControl = NULL;

    __try {
        // STEP 1: Get SID of the account name specified.
        //返回一些需要的内存大小。
        fAPISuccess = LookupAccountName(NULL, lpszAccountName, pUserSID, &cbUserSID, szDomain, &cbDomain, &snuType);
        if (fAPISuccess)
            __leave;
        else if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {// API should have failed with insufficient buffer.
            _tprintf(TEXT("LookupAccountName() failed. Error %d\n"), GetLastError());
            __leave;
        }

        pUserSID = myheapalloc(cbUserSID);//申请内存。
        if (!pUserSID) {
            _tprintf(TEXT("HeapAlloc() failed. Error %d\n"), GetLastError());
            __leave;
        }

        szDomain = (TCHAR *)myheapalloc(cbDomain * sizeof(TCHAR));//申请内存。
        if (!szDomain) {
            _tprintf(TEXT("HeapAlloc() failed. Error %d\n"), GetLastError());
            __leave;
        }

        //再来一次。获取到了域名 。
        fAPISuccess = LookupAccountName(NULL, lpszAccountName, pUserSID, &cbUserSID, szDomain, &cbDomain, &snuType);
        if (!fAPISuccess) {
            _tprintf(TEXT("LookupAccountName() failed. Error %d\n"), GetLastError());
            __leave;
        }

        // STEP 2: Get security descriptor (SD) of the file specified.
        fAPISuccess = GetFileSecurity(lpszFileName, secInfo, pFileSD, 0, &cbFileSD); //返回需要的大小。       
        if (fAPISuccess)
            __leave;
        else if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {// API should have failed with insufficient buffer.
            _tprintf(TEXT("GetFileSecurity() failed. Error %d\n"), GetLastError());
            __leave;
        }

        pFileSD = myheapalloc(cbFileSD);
        if (!pFileSD) {
            _tprintf(TEXT("HeapAlloc() failed. Error %d\n"), GetLastError());
            __leave;
        }

        fAPISuccess = GetFileSecurity(lpszFileName, secInfo, pFileSD, cbFileSD, &cbFileSD); //这时成功了。
        if (!fAPISuccess) {
            _tprintf(TEXT("GetFileSecurity() failed. Error %d\n"), GetLastError());
            __leave;
        }

        // STEP 3: Initialize new SD.
        if (!InitializeSecurityDescriptor(&newSD, SECURITY_DESCRIPTOR_REVISION)) {
            _tprintf(TEXT("InitializeSecurityDescriptor() failed.")   TEXT("Error %d\n"), GetLastError());
            __leave;
        }

        // STEP 4: Get DACL from the old SD.
        if (!GetSecurityDescriptorDacl(pFileSD, &fDaclPresent, &pACL, &fDaclDefaulted)) {
            _tprintf(TEXT("GetSecurityDescriptorDacl() failed. Error %d\n"), GetLastError());
            __leave;
        }

        // STEP 5: Get size information for DACL.
        AclInfo.AceCount = 0; // Assume NULL DACL.
        AclInfo.AclBytesFree = 0;
        AclInfo.AclBytesInUse = sizeof(ACL);

        if (pACL == NULL)
            fDaclPresent = FALSE;

        // If not NULL DACL, gather size information from DACL.
        if (fDaclPresent) {
            if (!GetAclInformation(pACL, &AclInfo, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation)) {
                _tprintf(TEXT("GetAclInformation() failed. Error %d\n"), GetLastError());
                __leave;
            }
        }

        // STEP 6: Compute size needed for the new ACL.
        cbNewACL = AclInfo.AclBytesInUse + sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(pUserSID) - sizeof(DWORD);

        // STEP 7: Allocate memory for new ACL.
        pNewACL = (PACL)myheapalloc(cbNewACL);
        if (!pNewACL) {
            _tprintf(TEXT("HeapAlloc() failed. Error %d\n"), GetLastError());
            __leave;
        }

        // STEP 8: Initialize the new ACL.
        if (!InitializeAcl(pNewACL, cbNewACL, ACL_REVISION2)) {
            _tprintf(TEXT("InitializeAcl() failed. Error %d\n"), GetLastError());
            __leave;
        }

        // STEP 9 If DACL is present, copy all the ACEs from the old DACL to the new DACL.
        // 
        // The following code assumes that the old DACL is already in Windows 2000 preferred order. 
        // To conform to the new Windows 2000 preferred order, 
        // first we will copy all non-inherited ACEs from the old DACL to the new DACL, 
        // irrespective of the ACE type.

        newAceIndex = 0;

        if (fDaclPresent && AclInfo.AceCount) {
            for (CurrentAceIndex = 0; CurrentAceIndex < AclInfo.AceCount; CurrentAceIndex++) {
                // STEP 10: Get an ACE.
                if (!GetAce(pACL, CurrentAceIndex, &pTempAce)) {
                    _tprintf(TEXT("GetAce() failed. Error %d\n"), GetLastError());
                    __leave;
                }

                // STEP 11: Check if it is a non-inherited ACE.
                // If it is an inherited ACE, break from the loop so that the new access allowed non-inherited ACE can
                // be added in the correct position, immediately after all non-inherited ACEs.
                if (((ACCESS_ALLOWED_ACE *)pTempAce)->Header.AceFlags & INHERITED_ACE)
                    break;

                // STEP 12: Skip adding the ACE, if the SID matches with the account specified, as we are going to 
                // add an access allowed ACE with a different access mask.
                if (EqualSid(pUserSID, &(((ACCESS_ALLOWED_ACE *)pTempAce)->SidStart)))
                    continue;

                // STEP 13: Add the ACE to the new ACL.
                if (!AddAce(pNewACL, ACL_REVISION, MAXDWORD, pTempAce, ((PACE_HEADER)pTempAce)->AceSize)) {
                    _tprintf(TEXT("AddAce() failed. Error %d\n"), GetLastError());
                    __leave;
                }

                newAceIndex++;
            }
        }

        // STEP 14: Add the access-allowed ACE to the new DACL.
        // The new ACE added here will be in the correct position,immediately after all existing non-inherited ACEs.
        if (!AddAccessAllowedAce(pNewACL, ACL_REVISION2, dwAccessMask, pUserSID)) {
            _tprintf(TEXT("AddAccessAllowedAce() failed. Error %d\n"), GetLastError());
            __leave;
        }

        // STEP 15: To conform to the new Windows 2000 preferred order,
        // we will now copy the rest of inherited ACEs from the old DACL to the new DACL.
        if (fDaclPresent && AclInfo.AceCount) {
            for (; CurrentAceIndex < AclInfo.AceCount; CurrentAceIndex++) {
                // STEP 16: Get an ACE.
                if (!GetAce(pACL, CurrentAceIndex, &pTempAce)) {
                    _tprintf(TEXT("GetAce() failed. Error %d\n"), GetLastError());
                    __leave;
                }

                // STEP 17: Add the ACE to the new ACL.
                if (!AddAce(pNewACL, ACL_REVISION, MAXDWORD, pTempAce, ((PACE_HEADER)pTempAce)->AceSize)) {
                    _tprintf(TEXT("AddAce() failed. Error %d\n"), GetLastError());
                    __leave;
                }
            }
        }

        // STEP 18: Set the new DACL to the new SD.
        if (!SetSecurityDescriptorDacl(&newSD, TRUE, pNewACL, FALSE)) {
            _tprintf(TEXT("SetSecurityDescriptorDacl() failed. Error %d\n"), GetLastError());
            __leave;
        }

        // STEP 19: Copy the old security descriptor control flags regarding DACL automatic inheritance for Windows 2000 or 
        // later where SetSecurityDescriptorControl() API is available in advapi32.dll.
        _SetSecurityDescriptorControl = (SetSecurityDescriptorControlFnPtr)
            GetProcAddress(GetModuleHandle(TEXT("advapi32.dll")), "SetSecurityDescriptorControl");
        if (_SetSecurityDescriptorControl) {
            SECURITY_DESCRIPTOR_CONTROL controlBitsOfInterest = 0;
            SECURITY_DESCRIPTOR_CONTROL controlBitsToSet = 0;
            SECURITY_DESCRIPTOR_CONTROL oldControlBits = 0;
            DWORD dwRevision = 0;

            if (!GetSecurityDescriptorControl(pFileSD, &oldControlBits, &dwRevision)) {
                _tprintf(TEXT("GetSecurityDescriptorControl() failed.")  TEXT("Error %d\n"), GetLastError());
                __leave;
            }

            if (oldControlBits & SE_DACL_AUTO_INHERITED) {
                controlBitsOfInterest = SE_DACL_AUTO_INHERIT_REQ | SE_DACL_AUTO_INHERITED;
                controlBitsToSet = controlBitsOfInterest;
            } else if (oldControlBits & SE_DACL_PROTECTED) {
                controlBitsOfInterest = SE_DACL_PROTECTED;
                controlBitsToSet = controlBitsOfInterest;
            }

            if (controlBitsOfInterest) {
                if (!_SetSecurityDescriptorControl(&newSD, controlBitsOfInterest, controlBitsToSet)) {
                    _tprintf(TEXT("SetSecurityDescriptorControl() failed.") TEXT("Error %d\n"), GetLastError());
                    __leave;
                }
            }
        }

        // STEP 20: Set the new SD to the File.
        if (!SetFileSecurity(lpszFileName, secInfo, &newSD)) {
            _tprintf(TEXT("SetFileSecurity() failed. Error %d\n"), GetLastError());
            __leave;
        }

        fResult = TRUE;
    } __finally {
        // STEP 21: Free allocated memory
        if (pUserSID)
            myheapfree(pUserSID);

        if (szDomain)
            myheapfree(szDomain);

        if (pFileSD)
            myheapfree(pFileSD);

        if (pNewACL)
            myheapfree(pNewACL);
    }

    return fResult;
}


int AddAccessRightsTest(int argc, TCHAR * argv[])
{
    if (argc < 3) {
        _tprintf(TEXT("usage: \"%s\" <FileName> <AccountName>\n"), argv[0]);
        return 1;
    }

    // argv[1] - FileName
    // argv[2] - Name of the User or Group account to add access
    if (!AddAccessRights(argv[1], argv[2], GENERIC_ALL)) {
        _tprintf(TEXT("AddAccessRights() failed.\n"));
        return 1;
    } else {
        _tprintf(TEXT("AddAccessRights() succeeded.\n"));
        return 0;
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////
//Using Authz API


BOOL AuthzInitFromToken(AUTHZ_CLIENT_CONTEXT_HANDLE * phClientContext)
/*
Initializing a Client Context

The following example initializes the Authz resource manager and
calls the AuthzInitializeContextFromToken function to create a client context from the logon token associated with the current process.

https://docs.microsoft.com/zh-cn/windows/win32/secauthz/initializing-a-client-context
*/
{
    HANDLE                            hToken = NULL;
    LUID                            Luid = {0, 0};
    ULONG                            uFlags = 0;
    AUTHZ_RESOURCE_MANAGER_HANDLE   g_hResourceManager;

    //Initialize Resource Manager
    if (!AuthzInitializeResourceManager(AUTHZ_RM_FLAG_NO_AUDIT,
                                        NULL,
                                        NULL,
                                        NULL,
                                        L"My Resource Manager",
                                        &g_hResourceManager)) {
        printf_s("AuthzInitializeResourceManager failed with %d\n", GetLastError());
        return FALSE;
    }

    //Get the current token.
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
        printf_s("OpenProcessToken failed with %d\n", GetLastError());
        return FALSE;
    }

    //Initialize the client context
    if (!AuthzInitializeContextFromToken(0, hToken, g_hResourceManager, NULL, Luid, NULL, phClientContext)) {
        printf_s("AuthzInitializeContextFromToken failed with %d\n", GetLastError());
        return FALSE;
    }

    printf_s("Initialized client context. \n");
    return TRUE;
}


BOOL GetGroupsFromContext(AUTHZ_CLIENT_CONTEXT_HANDLE hClientContext)
/*
Querying a Client Context

The following example queries the client context created in the example from Initializing a Client Context to retrieve the list of SIDs of groups associated with that client context.

https://docs.microsoft.com/zh-cn/windows/win32/secauthz/querying-a-client-context
*/
{
    DWORD                cbSize = 0;
    PTOKEN_GROUPS        pTokenGroups = NULL;
    LPTSTR                StringSid = NULL;
    BOOL                bResult = FALSE;
    int i = 0;

    //Call the AuthzGetInformationFromContext function with a NULL output buffer to get the required buffer size.
    AuthzGetInformationFromContext(hClientContext, AuthzContextInfoGroupsSids, 0, &cbSize, NULL);

    //Allocate the buffer for the TOKEN_GROUPS structure.
    pTokenGroups = (PTOKEN_GROUPS)malloc(cbSize);
    if (!pTokenGroups)
        return FALSE;

    //Get the SIDs of groups associated with the client context. 
    if (!AuthzGetInformationFromContext(hClientContext, AuthzContextInfoGroupsSids, cbSize, &cbSize, pTokenGroups)) {
        printf_s("AuthzGetInformationFromContext failed with %d\n", GetLastError());
        free(pTokenGroups);
        return FALSE;
    }

    //Enumerate and display the group SIDs.
    for (i = pTokenGroups->GroupCount - 1; i >= 0; --i) {
        //Convert a SID to a string.
        if (!ConvertSidToStringSid(pTokenGroups->Groups[i].Sid, &StringSid)) {
            LocalFree(StringSid);
            return FALSE;
        }

        wprintf_s(L"%s \n", StringSid);
    }

    free(pTokenGroups);

    return TRUE;
}


BOOL AddSidsToContext(AUTHZ_CLIENT_CONTEXT_HANDLE * phClientContext)
/*
Adding SIDs to a Client Context

The following example adds a SID and a restricting SID to the client context created by the example in Initializing a Client Context.

https://docs.microsoft.com/zh-cn/windows/win32/secauthz/adding-sids-to-a-client-context
*/
{
    AUTHZ_CLIENT_CONTEXT_HANDLE        NewContext = NULL;
    PSID                            pEveryoneSid = NULL;
    PSID                            pLocalSid = NULL;
    SID_AND_ATTRIBUTES                Sids;
    SID_AND_ATTRIBUTES                RestrictedSids;
    DWORD                            SidCount = 0;
    DWORD                            RestrictedSidCount = 0;

    //Create a PSID from the "Everyone" well-known SID.
    if (!ConvertStringSidToSid(L"S-1-1-0", &pEveryoneSid)) {
        printf_s("ConvertStringSidToSid failed with %d\n", GetLastError());
        return FALSE;
    }

    //Create a PSID from the "Local" well-known SID.
    if (!ConvertStringSidToSid(L"S-1-2-0", &pLocalSid)) {
        printf_s("ConvertStringSidToSid failed with %d\n", GetLastError());
        return FALSE;
    }

    //Set the members of the SID_AND_ATTRIBUTES structure to be added.
    Sids.Sid = pEveryoneSid;
    Sids.Attributes = SE_GROUP_ENABLED;

    //Set the members of the SID_AND_ATTRIBUTES structure for the restricting SID.
    RestrictedSids.Sid = pLocalSid;
    RestrictedSids.Attributes = SE_GROUP_ENABLED;

    //Create a new context with the new "Everyone" SID and "Local" restricting SID.
    if (!AuthzAddSidsToContext(*phClientContext, &Sids, 1, &RestrictedSids, 1, &NewContext)) {
        printf_s("AuthzAddSidsToContext failed with %d\n", GetLastError());
        if (pEveryoneSid) {
            FreeSid(pEveryoneSid);
        }
        if (pLocalSid) {
            FreeSid(pLocalSid);
        }
        return FALSE;
    }

    if (pEveryoneSid) {
        FreeSid(pEveryoneSid);
    }
    if (pLocalSid) {
        FreeSid(pLocalSid);
    }

    AuthzFreeContext(*phClientContext);
    *phClientContext = NewContext;
    return TRUE;
}


BOOL CheckAccess(AUTHZ_CLIENT_CONTEXT_HANDLE hClientContext)
/*
Checking Access with Authz API

The following example creates a SECURITY_DESCRIPTOR that allows READ_CONTROL access to built-in administrators.
It uses that security descriptor to check access for the client specified by the client context created in the example in Initializing a Client Context.

https://docs.microsoft.com/zh-cn/windows/win32/secauthz/checking-access-with-authz-api
*/
{
#define MY_MAX 4096
    PSECURITY_DESCRIPTOR    pSecurityDescriptor = NULL;
    ULONG                    cbSecurityDescriptorSize = 0;
    AUTHZ_ACCESS_REQUEST    Request;
    CHAR                    ReplyBuffer[MY_MAX];
    PAUTHZ_ACCESS_REPLY        pReply = (PAUTHZ_ACCESS_REPLY)ReplyBuffer;
    DWORD                    AuthzError = 0;

    //Allocate memory for the access request structure.
    RtlZeroMemory(&Request, sizeof(AUTHZ_ACCESS_REQUEST));

    //Set up the access request structure.
    Request.DesiredAccess = READ_CONTROL;

    //Allocate memory for the access reply structure.
    RtlZeroMemory(ReplyBuffer, MY_MAX);

    //Set up the access reply structure.
    pReply->ResultListLength = 1;
    pReply->Error = (PDWORD)((PCHAR)pReply + sizeof(AUTHZ_ACCESS_REPLY));
    pReply->GrantedAccessMask = (PACCESS_MASK)(pReply->Error + pReply->ResultListLength);
    pReply->SaclEvaluationResults = NULL;

    //Create security descriptor.
    if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
        L"O:LAG:BAD:(A;;RC;;;BA)",
        SDDL_REVISION_1,
        &pSecurityDescriptor,
        NULL)) {
        printf_s("ConvertStringSecurityDescriptorToSecurityDescriptor failed with %d\n", GetLastError());
        return FALSE;
    }

    //Call AuthzAccessCheck.
    if (!AuthzAccessCheck(0,
                          hClientContext,
                          &Request,
                          NULL,
                          pSecurityDescriptor,
                          NULL,
                          0,
                          pReply,
                          NULL)) {
        printf_s("AuthzAccessCheck failed with %d\n", GetLastError());
        LocalFree(pSecurityDescriptor);
        return FALSE;
    }

    //Print results.
    if (*pReply->GrantedAccessMask & READ_CONTROL) {
        printf_s("Access granted.\n");
    } else {
        printf_s("Access denied.\n");
    }

    LocalFree(pSecurityDescriptor);
    return TRUE;
}


BOOL CheckCachedAccess(AUTHZ_CLIENT_CONTEXT_HANDLE hClientContext)
/*
Caching Access Checks

The following example checks access against a cached result from a previous access check.
The previous access check was performed in the example in Checking Access with Authz API.

https://docs.microsoft.com/zh-cn/windows/win32/secauthz/caching-access-checks
*/
{
#define MY_MAX 4096
    PSECURITY_DESCRIPTOR                pSecurityDescriptor = NULL;
    ULONG                                cbSecurityDescriptorSize = 0;
    AUTHZ_ACCESS_REQUEST                Request;
    CHAR                                ReplyBuffer[MY_MAX];
    CHAR                                CachedReplyBuffer[MY_MAX];
    PAUTHZ_ACCESS_REPLY                    pReply = (PAUTHZ_ACCESS_REPLY)ReplyBuffer;
    PAUTHZ_ACCESS_REPLY                    pCachedReply = (PAUTHZ_ACCESS_REPLY)CachedReplyBuffer;
    DWORD                                AuthzError = 0;
    AUTHZ_ACCESS_CHECK_RESULTS_HANDLE    hCached;

    //Allocate memory for the access request structure.
    RtlZeroMemory(&Request, sizeof(AUTHZ_ACCESS_REQUEST));

    //Set up the access request structure.
    Request.DesiredAccess = READ_CONTROL;

    //Allocate memory for the initial access reply structure.
    RtlZeroMemory(ReplyBuffer, MY_MAX);

    //Set up the access reply structure.
    pReply->ResultListLength = 1;
    pReply->Error = (PDWORD)((PCHAR)pReply + sizeof(AUTHZ_ACCESS_REPLY));
    pReply->GrantedAccessMask = (PACCESS_MASK)(pReply->Error + pReply->ResultListLength);
    pReply->SaclEvaluationResults = NULL;

    //Allocate memory for the cached access reply structure.
    RtlZeroMemory(ReplyBuffer, MY_MAX);

    //Set up the cached access reply structure.
    pCachedReply->ResultListLength = 1;
    pCachedReply->Error = (PDWORD)((PCHAR)pCachedReply + sizeof(AUTHZ_ACCESS_REPLY));
    pCachedReply->GrantedAccessMask = (PACCESS_MASK)(pCachedReply->Error + pCachedReply->ResultListLength);
    pCachedReply->SaclEvaluationResults = NULL;

    //Create security descriptor.
    if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
        L"O:LAG:BAD:(A;;RC;;;BA)",
        SDDL_REVISION_1,
        &pSecurityDescriptor,
        NULL)) {
        printf_s("ConvertStringSecurityDescriptorToSecurityDescriptor failed with %d\n", GetLastError());
        return FALSE;
    }

    //Call AuthzAccessCheck and cache results.
    if (!AuthzAccessCheck(0,
                          hClientContext,
                          &Request,
                          NULL,
                          pSecurityDescriptor,
                          NULL,
                          0,
                          pReply,
                          &hCached)) {
        printf_s("AuthzAccessCheck failed with %d\n", GetLastError());
        LocalFree(pSecurityDescriptor);
        return FALSE;
    }

    //Call AuthzCachedAccessCheck with the cached result from the previous call.
    if (!AuthzCachedAccessCheck(0, hCached, &Request, NULL, pCachedReply)) {
        printf_s("AuthzCachedAccessCheck failed with %d\n", GetLastError());
        LocalFree(pSecurityDescriptor);
        AuthzFreeHandle(hCached);
        return FALSE;
    }

    //Print results.
    if (*pCachedReply->GrantedAccessMask & READ_CONTROL) {
        printf_s("Access granted.\n");
    } else {
        printf_s("Access denied.\n");
    }

    LocalFree(pSecurityDescriptor);
    AuthzFreeHandle(hCached);
    return TRUE;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID usage(LPWSTR wszAppName)
// Utility function that outputs this application's usage instructions.
{
    wprintf(L"\n%s: adds users to encrypted files.\n", wszAppName);
    wprintf(L"\nUsage:\tadduser <file> <user name> <subject name>\n\n");
    wprintf(L"\t<file> is the name of the file\n");
    wprintf(L"\t<user name> is the name of the user's account\n");
    wprintf(L"\t\tExample: for name@example.com, use \"name\"\n");
    wprintf(L"\t<subject name> is the \"IssuedTo\" name on the ");
    wprintf(L"certificate\n\t\tfrom the TrustedPeople store.\n");
    exit(1);
}


void __cdecl AddsUserToEncryptedFile(int argc, wchar_t * argv[])
//  Adduser.c: adds a user to an encrypted file.
//
//  Note: Build project must link Crypt32.lib

/*
Adding Users to an Encrypted File
2018/05/31

The code sample in this topic adds a new user to an existing encrypted file by using the AddUsersToEncryptedFile function.
It requires the user's Encrypting File System (EFS) certificate (from the Active Directory) to exist in the Trusted People user certificate store.

This sample adds a new Data Recovery Field to the encrypted file.
As a result, the newly added user can decrypt the encrypted file.
The caller must already have access to the encrypted file, either as the original owner,
the data recovery agent, or as a user who was previously added to the encrypted file.

https://docs.microsoft.com/zh-cn/windows/win32/fileio/adding-users-to-an-encrypted-file
*/
{
    LPWSTR wszFile = NULL;
    LPWSTR wszAccount = NULL;
    LPWSTR wszSubject = NULL;
    PSID   pSid = NULL;
    DWORD  cbSid = 0;
    LPWSTR wszDomain = NULL;
    DWORD  cchDomain = 0;
    SID_NAME_USE SidType = SidTypeUser;
    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    PENCRYPTION_CERTIFICATE      pEfsEncryptionCert = NULL;
    PENCRYPTION_CERTIFICATE_LIST pEfsEncryptionCertList = NULL;
    DWORD dwResult = ERROR_SUCCESS;

    // Simple check whether to explain usage to the user.
    if (argc != 4) {
        usage(argv[0]);
    }

    // TODO: Check the parameters for correctness.
    wszFile = argv[1];
    wszAccount = argv[2];
    wszSubject = argv[3];

    // First, look up the user's SID using the specified account name.
    // Call LookupAccountName twice; first to find the size of the 
    // SID, and a second time to retrieve the SID.
    LookupAccountName(NULL, wszAccount, pSid, &cbSid, wszDomain, &cchDomain, &SidType);
    if (0 == cbSid) {
        ErrorExit(L"LookupAccountName did not return the SID size.", GetLastError());
    }
    pSid = (PSID)malloc(cbSid);
    if (!pSid) {
        ErrorExit(L"Failed to allocate SID.", GetLastError());
    }
    wszDomain = (LPWSTR)malloc(cchDomain * sizeof(WCHAR));
    if (!wszDomain) {
        ErrorExit(L"Failed to allocate string.", GetLastError());
    }
    if (!LookupAccountName(NULL, wszAccount, pSid, &cbSid, wszDomain, &cchDomain, &SidType)) {
        ErrorExit(L"LookupAccountName failed.", GetLastError());
    }

    // Obtain the user's certificate.
    // Search the TrustedPeople store for the specified subject name.
    // Anyone who has encrypted a file on the computer has an 
    // encryption certificate placed the TrustedPeople store by the 
    // system. It is likely that the user has a matching private key.
    hStore = CertOpenSystemStore((HCRYPTPROV)NULL, L"TrustedPeople");
    if (!hStore) {
        ErrorExit(L"OpenSystemStore failed.", GetLastError());
    }

    pCertContext = CertFindCertificateInStore(hStore,
                                              X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                              0,
                                              CERT_FIND_SUBJECT_STR,
                                              (VOID *)wszSubject,
                                              NULL);
    if (!pCertContext) {
        ErrorExit(L"FindCertificateInStore failed.", GetLastError());
    }

    // Create the ENCRYPTION_CERTIFICATE using the cert context and the user's SID.
    pEfsEncryptionCert = (PENCRYPTION_CERTIFICATE)malloc(sizeof(ENCRYPTION_CERTIFICATE));
    if (!pEfsEncryptionCert) {
        ErrorExit(L"Failed to allocate structure.", GetLastError());
    }
    pEfsEncryptionCert->cbTotalLength = sizeof(ENCRYPTION_CERTIFICATE);
    pEfsEncryptionCert->pUserSid = (SID *)pSid;
    pEfsEncryptionCert->pCertBlob = (PEFS_CERTIFICATE_BLOB)malloc(sizeof(EFS_CERTIFICATE_BLOB));
    if (!pEfsEncryptionCert->pCertBlob) {
        ErrorExit(L"Failed to allocate cert blob.", GetLastError());
    }
    pEfsEncryptionCert->pCertBlob->dwCertEncodingType = pCertContext->dwCertEncodingType;
    pEfsEncryptionCert->pCertBlob->cbData = pCertContext->cbCertEncoded;
    pEfsEncryptionCert->pCertBlob->pbData = pCertContext->pbCertEncoded;

    // AddUsersToEncryptedFile takes an ENCRYPTION_CERTIFICATE_LIST; 
    // create one with only one ENCRYPTION_CERTIFICATE in it.
    pEfsEncryptionCertList = (PENCRYPTION_CERTIFICATE_LIST)malloc(sizeof(ENCRYPTION_CERTIFICATE_LIST));
    if (!pEfsEncryptionCertList) {
        ErrorExit(L"Failed to allocate structure.", GetLastError());
    }
    pEfsEncryptionCertList->nUsers = 1;
    pEfsEncryptionCertList->pUsers = &pEfsEncryptionCert;

    // Call the API to add the user.
    dwResult = AddUsersToEncryptedFile(wszFile, pEfsEncryptionCertList);
    if (ERROR_SUCCESS == dwResult) {
        wprintf(L"The user was successfully added to the file.\n");
    } else {
        ErrorExit(L"AddUsersToEncryptedFile failed.", dwResult);
    }

    // Clean up all allocated resources.
    if (wszDomain) free(wszDomain);
    if (pSid) free(pSid);
    if (pCertContext) CertFreeCertificateContext(pCertContext);
    if (hStore) CertCloseStore(hStore, CERT_CLOSE_STORE_FORCE_FLAG);

    if (pEfsEncryptionCertList) {
        if (pEfsEncryptionCertList->pUsers) {
            if (pEfsEncryptionCertList->pUsers[0]) {
                if ((pEfsEncryptionCertList->pUsers[0])->pCertBlob)
                    free((pEfsEncryptionCertList->pUsers[0])->pCertBlob);
                free(pEfsEncryptionCertList->pUsers[0]);
            }
            free(pEfsEncryptionCertList->pUsers);
        }
        free(pEfsEncryptionCertList);
    }

    wprintf(L"The program ran to completion without error.\n");
    exit(0);
}


//////////////////////////////////////////////////////////////////////////////////////////////////
