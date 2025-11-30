#include "Commands.h"
#include <tchar.h>


#pragma comment(lib, "crypt32.lib")


char* CurrentUser;
char* CurrentUsersDirectory;
BOOLEAN isUserLoggedIn;


NTSTATUS WINAPI
SafeStorageInit(
    VOID
)
{
    CurrentUser = calloc(11, sizeof(char));
    CurrentUsersDirectory = calloc(260, sizeof(char));
    isUserLoggedIn = FALSE;
    return STATUS_SUCCESS;
}


VOID WINAPI
SafeStorageDeinit(
    VOID
)
{
    free(CurrentUser);
    free(CurrentUsersDirectory);

    return;
}


NTSTATUS WINAPI
HashPassword(
    const char* Password,
    const int PasswordLength,
    char* HashedPassword,
    int* HashedPasswordLength
)
{    
    UNREFERENCED_PARAMETER(HashedPasswordLength);

    NTSTATUS status;
    BCRYPT_ALG_HANDLE hAlgorithm;
    DWORD bytesCopied;

    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);

    if (!NT_SUCCESS(status)) {
        printf("Failed to get algorithm provider, status: %08x\n", status);
        return STATUS_UNSUCCESSFUL;
    }

    status = BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, (PUCHAR)HashedPasswordLength, sizeof(DWORD), &bytesCopied, 0);
    //printf("HASH LENGTH: %d\n", *HashedPasswordLength);

    if (!NT_SUCCESS(status)) {
        printf("Failed to get algorithm property, status: %08x\n", status);
        return STATUS_UNSUCCESSFUL;
    }

    status = BCryptHash(hAlgorithm, NULL, 0, (PUCHAR)Password, PasswordLength, (PUCHAR)HashedPassword, *HashedPasswordLength);

    if (!NT_SUCCESS(status)) {
        printf("Failed to use hash algorithm, status: %08x\n", status);
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}


NTSTATUS WINAPI
SafeStorageHandleRegister(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
)
{
    if (isUserLoggedIn == TRUE) {
        printf("Not possible\n");
        return STATUS_UNSUCCESSFUL;
    }

    if (UsernameLength >= 5 && UsernameLength <= 10) {
        for (int i = 0; i < UsernameLength; i++) {
            if (!((Username[i] >= 'a' && Username[i] <= 'z') || (Username[i] >= 'A' && Username[i] <= 'Z'))) {
                printf("Username contains wrong characters!\n");
                return STATUS_UNSUCCESSFUL;
            }
        }
    }
    else {
        printf("Username length is incorrect!\n");
        return STATUS_UNSUCCESSFUL;
    }

    BOOLEAN atLeastOneLowercase = FALSE;
    BOOLEAN atLeastOneUppercase = FALSE;
    BOOLEAN atLeastOneDigit = FALSE;
    BOOLEAN atLeastOneSpecialCharacter = FALSE;

    if (PasswordLength >= 5 && PasswordLength <= 64) {
        for (int i = 0; i < PasswordLength; i++) {
            if (Password[i] >= 'a' && Password[i] <= 'z') {
                atLeastOneLowercase = TRUE;
            }
            else if (Password[i] >= 'A' && Password[i] <= 'Z') {
                atLeastOneUppercase = TRUE;
            }
            else if (Password[i] >= '0' && Password[i] <= '9') {
                atLeastOneDigit = TRUE;
            }
            else if (Password[i] == '!' || Password[i] == '@' || Password[i] == '#' || Password[i] == '$' || Password[i] == '%' || Password[i] == '^' || Password[i] == '&') {
                atLeastOneSpecialCharacter = TRUE;
            }
            else {
                printf("Password contains wrong characters!\n");
                return STATUS_UNSUCCESSFUL;
            }
        }
        if (!(atLeastOneLowercase == TRUE && atLeastOneUppercase == TRUE && atLeastOneDigit == TRUE && atLeastOneSpecialCharacter == TRUE)) {
            printf("%d", atLeastOneLowercase);
            printf("%d", atLeastOneUppercase);
            printf("%d", atLeastOneDigit);
            printf("%d", atLeastOneSpecialCharacter);
            printf("Password isn't correct format\n");
            return STATUS_UNSUCCESSFUL;
        }
    }
    else {
        printf("Password length is incorrect!\n");
        return STATUS_UNSUCCESSFUL;
    }

    char* hashedPassword = malloc(32 * sizeof(BYTE));
    int hashedPasswordLength;
    int status = HashPassword(Password, PasswordLength, hashedPassword, &hashedPasswordLength);

    if (!NT_SUCCESS(status)) {
        printf("Encountered issues with hashing!\n");
        return STATUS_UNSUCCESSFUL;
    }

    int encryptedPasswordLength = 0;
    CryptBinaryToStringA((BYTE *)hashedPassword, hashedPasswordLength, CRYPT_STRING_HEX | CRYPT_STRING_NOCRLF, NULL, (DWORD *)&encryptedPasswordLength);
    char* encryptedPassword = malloc(encryptedPasswordLength);
    CryptBinaryToStringA((BYTE*)hashedPassword, hashedPasswordLength, CRYPT_STRING_HEX | CRYPT_STRING_NOCRLF, encryptedPassword, (DWORD*)&encryptedPasswordLength);

    printf("Encryted password: %s\n", encryptedPassword);
    printf("Encryted password length: %d\n", encryptedPasswordLength);

    char CurrentDirectoryName[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, CurrentDirectoryName);

    //printf("%s\n", CurrentDirectoryName);

    char UsersFile[MAX_PATH] = {0};
    StringCchCopyA(UsersFile, MAX_PATH, CurrentDirectoryName);
    StringCchCatA(UsersFile, MAX_PATH, "\\users.txt");
    //printf("%s\n", UsersFile);

    char* UserData;
    int UserDataSize = UsernameLength + encryptedPasswordLength + 5;
    printf("%d\n", UserDataSize);
    UserData = calloc(UserDataSize, sizeof(char));
    UserData[0] = '\0';

    StringCchCatA(UserData, UserDataSize, Username);
    printf("UserData: %s\n", UserData);
    StringCchCatA(UserData, UserDataSize, ":");
    printf("UserData: %s\n", UserData);
    StringCchCatA(UserData, UserDataSize, encryptedPassword);
    printf("UserData: %s\n", UserData);
    StringCchCatA(UserData, UserDataSize, "\r\n");

    //printf("UserData: %s\n", UserData);

    DWORD NumberOfBytesWrittenInUserDataFile;

    HANDLE UserDataFile = CreateFileA(UsersFile, FILE_APPEND_DATA, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    WriteFile(UserDataFile, UserData, strlen(UserData), &NumberOfBytesWrittenInUserDataFile, NULL);
    CloseHandle(UserDataFile);

    free(encryptedPassword);

    char* UsersDirectoryPath;
    StringCchCatA(CurrentDirectoryName, MAX_PATH, "\\users");
    UsersDirectoryPath = calloc(MAX_PATH, sizeof(char));
    StringCchCopyA(UsersDirectoryPath, MAX_PATH, CurrentDirectoryName);
    CreateDirectoryA(UsersDirectoryPath, NULL);

    StringCchCatA(UsersDirectoryPath, MAX_PATH, "\\");
    StringCchCatA(UsersDirectoryPath, MAX_PATH, Username);
    StringCchCatA(UsersDirectoryPath, MAX_PATH, "\0");

    CreateDirectoryA(UsersDirectoryPath, NULL);

    return STATUS_SUCCESS;
}


NTSTATUS WINAPI
SafeStorageHandleLogin(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
)
{
    if (isUserLoggedIn == TRUE) {
        printf("Not possible\n");
        return STATUS_UNSUCCESSFUL;
    }

    char* hashedPassword = malloc(32 * sizeof(BYTE));
    int hashedPasswordLength;
    int status = HashPassword(Password, PasswordLength, hashedPassword, &hashedPasswordLength);

    if (!NT_SUCCESS(status)) {
        printf("Encountered issues with hashing!\n");
        return STATUS_UNSUCCESSFUL;
    }

    int encryptedPasswordLength = 0;
    CryptBinaryToStringA((BYTE*)hashedPassword, hashedPasswordLength, CRYPT_STRING_HEX | CRYPT_STRING_NOCRLF, NULL, (DWORD*)&encryptedPasswordLength);
    char* encryptedPassword = malloc(encryptedPasswordLength);
    CryptBinaryToStringA((BYTE*)hashedPassword, hashedPasswordLength, CRYPT_STRING_HEX | CRYPT_STRING_NOCRLF, encryptedPassword, (DWORD*)&encryptedPasswordLength);

    printf("Encrypted password: %s\n", encryptedPassword);

    HANDLE UserDataFile = CreateFileA("users.txt", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (UserDataFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open file, error %lu\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    DWORD NumberOfBytesRead;
    char DataBuffer[256];
    char LineBuffer[512];
    int length = 0;

    while (ReadFile(UserDataFile, DataBuffer, 256, &NumberOfBytesRead, NULL) && NumberOfBytesRead > 0) {
        printf("Read %d bytes\n", NumberOfBytesRead);

        for (int i = 0; i < (int)NumberOfBytesRead; i++) {
            if (DataBuffer[i] == '\n') {
                printf("DA\n");
                LineBuffer[length] = '\0';
               
                char FileUsername[15] = { 0 };
                char FilePassword[150] = { 0 };

                int ok = 0;
                int j;
                int k = 0;
                for (j = 0; j < length; j++) {
                    if (LineBuffer[j] == ':') {
                        ok = 1;
                        FileUsername[j] = '\0';
                    }
                    if (ok == 0) {
                        FileUsername[j] = LineBuffer[j];
                    }
                    else if (ok == 1 && LineBuffer[j] != '\r' && LineBuffer[j] != '\n' && LineBuffer[j] != ':') {
                        FilePassword[k++] = LineBuffer[j];
                    }
                }
                FilePassword[k] = '\0';

                printf("Username: %s, Password %s\n", FileUsername, FilePassword);

                if (strncmp(FileUsername, Username, UsernameLength) == 0 && strncmp(FilePassword, encryptedPassword, encryptedPasswordLength) == 0) {
                    strncpy(CurrentUser, FileUsername, UsernameLength);

                    char CurrentDirectoryName[MAX_PATH];
                    GetCurrentDirectoryA(MAX_PATH, CurrentDirectoryName);
                    char* UsersDirectoryPath;
                    UsersDirectoryPath = calloc(MAX_PATH, sizeof(char));
                    UsersDirectoryPath[0] = '\0';

                    StringCchCatA(CurrentDirectoryName, MAX_PATH, "\\users");
                    StringCchCopyA(UsersDirectoryPath, MAX_PATH, CurrentDirectoryName);

                    printf("UsersDirectoryPath: %s\n", UsersDirectoryPath);

                    StringCchCatA(UsersDirectoryPath, MAX_PATH, "\\");
                    StringCchCatA(UsersDirectoryPath, MAX_PATH, FileUsername);
                    StringCchCatA(UsersDirectoryPath, MAX_PATH, "\\");
                    StringCchCatA(UsersDirectoryPath, MAX_PATH, "\0");

                    strncpy(CurrentUsersDirectory, UsersDirectoryPath, MAX_PATH);

                    printf("Welcome %s\n", FileUsername);

                    isUserLoggedIn = TRUE;

                    break;
                }

                length = 0;
            }
            else if (DataBuffer[i] != '\r') {
                //printf("DAr");
                LineBuffer[length++] = DataBuffer[i];
            }
        }
    }

    CloseHandle(UserDataFile);

    return STATUS_SUCCESS;
}


NTSTATUS WINAPI
SafeStorageHandleLogout(
    VOID
)
{
    if (isUserLoggedIn == FALSE) {
        printf("Not possible\n");
        return STATUS_UNSUCCESSFUL;
    }

    isUserLoggedIn = FALSE;

    for (int i = 0; i < 11; i++) {
        CurrentUser[i] = '\0';
    }

    for (int i = 0; i < 260; i++) {
        CurrentUsersDirectory[i] = '\0';
    }

    return STATUS_SUCCESS;
}


VOID
CALLBACK
MyWorkCallback(
    PTP_CALLBACK_INSTANCE Instance,
    PVOID                 Parameter,
    PTP_WORK              Work
)
{
    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(Work);

    PFILE_CHUNK_CONTEXT pv = (PFILE_CHUNK_CONTEXT)Parameter;

    OVERLAPPED ov = { 0 };
    ov.Offset = pv->offset.LowPart;
    ov.OffsetHigh = pv->offset.HighPart;

    DWORD bytesWritten = 0;
    BOOL ok = WriteFile(pv->hDest, pv->buffer, pv->bufferSize, &bytesWritten, &ov);

    if (!ok) {
        DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING) {
            printf("WriteFile failed. LastError: %u\n", err);

            free(pv->buffer);
            free(pv);
        }
    }

    // For debugging purposes
    /*printf("Thread %d\n", GetCurrentThreadId());
    Sleep(3000);
    printf("Thread %d\n", GetCurrentThreadId());
    printf("A\n");*/

    free(pv->buffer);
    free(pv);
}


NTSTATUS WINAPI
SafeStorageHandleStore(
    const char* SubmissionName,
    uint16_t SubmissionNameLength,
    const char* SourceFilePath,
    uint16_t SourceFilePathLength
)
{
    if (isUserLoggedIn == FALSE) {
        printf("Not possible\n");
        return STATUS_UNSUCCESSFUL;
    }

    UNREFERENCED_PARAMETER(SubmissionNameLength);
    UNREFERENCED_PARAMETER(SourceFilePathLength);

    PTP_POOL pool = NULL;
    TP_CALLBACK_ENVIRON CallBackEnviron;
    BOOL bRet = FALSE;
    PTP_WORK_CALLBACK workcallback = MyWorkCallback;
    PFILE_CHUNK_CONTEXT pv;

    //printf("%s\n", SourceFilePath);

    HANDLE hSrc = CreateFileA(SourceFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    //printf("Path: %s\n", SourceFilePath);

    if (hSrc == INVALID_HANDLE_VALUE) {
        printf("CreateFileA for source failed. LastError: %u\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    char submissionPath[MAX_PATH];
    strcpy_s(submissionPath, MAX_PATH, CurrentUsersDirectory);
    StringCchCatA(submissionPath, MAX_PATH, SubmissionName);
    StringCchCatA(submissionPath, MAX_PATH, "\0");

    //printf("Submissions path: %s\n", submissionPath);

    HANDLE hDest = CreateFileA(submissionPath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);

    if (hDest == INVALID_HANDLE_VALUE) {
        printf("CreateFileA for destination failed. LastError: %u\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    //printf("DA\n");

    InitializeThreadpoolEnvironment(&CallBackEnviron);

    pool = CreateThreadpool(NULL);

    if (pool == NULL) {
        printf("CreateThreadpool failed. LastError: %u\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    SetThreadpoolThreadMaximum(pool, 4);
   
    bRet = SetThreadpoolThreadMinimum(pool, 4);

    if (bRet == FALSE) {
        printf("SetThreadpoolThreadMinimum failed. LastError: %u\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    SetThreadpoolCallbackPool(&CallBackEnviron, pool);

    DWORD bytesRead = 0;
    LARGE_INTEGER size = { 0 };

    GetFileSizeEx(hSrc, &size);

    //printf("File size: %d\n", size.LowPart);
    //printf("File size: %d\n", size.HighPart);
    //printf("File size: %llu\n", size.QuadPart);


    DWORD numberOfChunks;
    DWORD chunkSize;
    uint64_t testSize = size.QuadPart;

    if (testSize > 64000000) {
        numberOfChunks = (DWORD)(testSize / 64000000);
        chunkSize = 64000000;
    }
    else {
        numberOfChunks = 1;
        chunkSize = (DWORD)size.QuadPart;
    }
    

    ULONGLONG fileOffset = 0;

    BYTE* buf = malloc(chunkSize * sizeof(char));
    if (!buf) {
        return STATUS_UNSUCCESSFUL;
    }

    //printf("Chunk size: %d\n", chunkSize);

    int n = numberOfChunks;

    if (n <= 0) {
        return STATUS_UNSUCCESSFUL;
    }

    //printf("N=%d\n", n);
    PTP_WORK work[300];

    int workIndex = 0;
    while (ReadFile(hSrc, buf, chunkSize, &bytesRead, NULL) && bytesRead > 0) {
        pv = malloc(sizeof(FILE_CHUNK_CONTEXT));

        pv->hDest = hDest;

        printf("Bytes read: %d\n", bytesRead);

        pv->buffer = malloc(bytesRead);

        memcpy(pv->buffer, buf, bytesRead);
        
        //printf("%s\n", buf);
        //printf("%d\n", bytesRead);

        pv->bufferSize = bytesRead;
        pv->offset.QuadPart = fileOffset;

        work[workIndex] = CreateThreadpoolWork(workcallback, (PVOID)pv, &CallBackEnviron);

        if (work[workIndex] == NULL) {
            printf("CreateThreadpoolWork failed. LastError: %u\n", GetLastError());
        }

        printf("Sent %d bytes\n", bytesRead);

        SubmitThreadpoolWork(work[workIndex]);

        fileOffset += bytesRead;

        workIndex += 1;
    }

    CloseHandle(hSrc);
    free(buf);

    for (int i = 0; i < n; i++) {
        WaitForThreadpoolWorkCallbacks(work[i], FALSE);

        CloseThreadpoolWork(work[i]);
    }

    //free(work);

    CloseHandle(hDest);

    return STATUS_SUCCESS;
}


NTSTATUS WINAPI
SafeStorageHandleRetrieve(
    const char* SubmissionName,
    uint16_t SubmissionNameLength,
    const char* DestinationFilePath,
    uint16_t DestinationFilePathLength
)
{
    if (isUserLoggedIn == FALSE) {
        printf("Not possible\n");
        return STATUS_UNSUCCESSFUL;
    }

    UNREFERENCED_PARAMETER(SubmissionNameLength);
    UNREFERENCED_PARAMETER(DestinationFilePathLength);

    PTP_POOL pool = NULL;
    TP_CALLBACK_ENVIRON CallBackEnviron;
    BOOL bRet = FALSE;
    PTP_WORK_CALLBACK workcallback = MyWorkCallback;
    PFILE_CHUNK_CONTEXT pv;

    //printf("%s\n", SourceFilePath);

    char submissionPath[MAX_PATH];
    strcpy_s(submissionPath, MAX_PATH, CurrentUsersDirectory);
    StringCchCatA(submissionPath, MAX_PATH, SubmissionName);
    StringCchCatA(submissionPath, MAX_PATH, "\0");

    //printf("Submissions path: %s\n", submissionPath);

    HANDLE hSrc = CreateFileA(submissionPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hSrc == INVALID_HANDLE_VALUE) {
        printf("CreateFileA for source failed. LastError: %u\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    HANDLE hDest = CreateFileA(DestinationFilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);

    if (hDest == INVALID_HANDLE_VALUE) {
        printf("CreateFileA for desination failed. LastError: %u\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    //printf("DA\n");

    InitializeThreadpoolEnvironment(&CallBackEnviron);

    pool = CreateThreadpool(NULL);

    if (pool == NULL) {
        printf("CreateThreadpool failed. LastError: %u\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    SetThreadpoolThreadMaximum(pool, 4);

    bRet = SetThreadpoolThreadMinimum(pool, 4);

    if (bRet == FALSE) {
        printf("SetThreadpoolThreadMinimum failed. LastError: %u\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    SetThreadpoolCallbackPool(&CallBackEnviron, pool);

    DWORD bytesRead = 0;
    LARGE_INTEGER size = { 0 };

    GetFileSizeEx(hSrc, &size);

    //printf("File size: %d\n", size.LowPart);
    //printf("File size: %d\n", size.HighPart);
    //printf("File size: %llu\n", size.QuadPart);


    DWORD numberOfChunks;
    DWORD chunkSize;
    uint64_t testSize = size.QuadPart;

    if (testSize > 64000000) {
        numberOfChunks = (DWORD)(testSize / 64000000);
        chunkSize = 64000000;
    }
    else {
        numberOfChunks = 1;
        chunkSize = (DWORD)size.QuadPart;
    }


    ULONGLONG fileOffset = 0;

    BYTE* buf = malloc(chunkSize * sizeof(char));
    if (!buf) {
        return STATUS_UNSUCCESSFUL;
    }

    //printf("Chunk size: %d\n", chunkSize);

    int n = numberOfChunks;

    if (n <= 0) {
        return STATUS_UNSUCCESSFUL;
    }

    //printf("N=%d\n", n);
    PTP_WORK work[300];

    int workIndex = 0;
    while (ReadFile(hSrc, buf, chunkSize, &bytesRead, NULL) && bytesRead > 0) {
        pv = malloc(sizeof(FILE_CHUNK_CONTEXT));

        pv->hDest = hDest;
        pv->buffer = malloc(bytesRead);
        memcpy(pv->buffer, buf, bytesRead);

        //printf("%s\n", buf);
        //printf("%d\n", bytesRead);

        pv->bufferSize = bytesRead;
        pv->offset.QuadPart = fileOffset;

        work[workIndex] = CreateThreadpoolWork(workcallback, (PVOID)pv, &CallBackEnviron);

        if (work[workIndex] == NULL) {
            printf("CreateThreadpoolWork failed. LastError: %u\n", GetLastError());
        }

        printf("Sent %d bytes\n", bytesRead);

        SubmitThreadpoolWork(work[workIndex]);

        fileOffset += bytesRead;

        workIndex += 1;
    }

    CloseHandle(hSrc);

    for (int i = 0; i < n; i++) {
        WaitForThreadpoolWorkCallbacks(work[i], FALSE);
        CloseThreadpoolWork(work[i]);
    }

    CloseHandle(hDest);

    return STATUS_SUCCESS;
}
