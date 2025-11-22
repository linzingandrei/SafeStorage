#include "Commands.h"
#include <tchar.h>


char* CurrentUser;
char* CurrentUsersDirectory;

NTSTATUS WINAPI
SafeStorageInit(
    VOID
)
{
    CurrentUser = calloc(11, sizeof(char));
    CurrentUsersDirectory = calloc(260, sizeof(char));
    return STATUS_SUCCESS;
}


VOID WINAPI
SafeStorageDeinit(
    VOID
)
{
    /* The function is not implemented. It is your responsibility. */
    /* Here you can clean up any global objects you have created earlier. */

    return;
}


NTSTATUS WINAPI
SafeStorageHandleRegister(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
)
{
    char CurrentDirectoryName[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, CurrentDirectoryName);

    printf("%s\n", CurrentDirectoryName);

    char UsersFile[MAX_PATH] = {0};
    lstrcpyA(UsersFile, CurrentDirectoryName);
    lstrcatA(UsersFile, "\\users.txt");
    printf("%s\n", UsersFile);

    char* UserData;
    int UserDataSize = UsernameLength + PasswordLength + 2;
    UserData = calloc(UserDataSize, sizeof(char));

    lstrcatA(UserData, Username);
    lstrcatA(UserData, ":");
    lstrcatA(UserData, Password);
    lstrcatA(UserData, "\r\n");

    DWORD NumberOfBytesWrittenInUserDataFile;

    HANDLE UserDataFile = CreateFileA(UsersFile, FILE_APPEND_DATA, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    WriteFile(UserDataFile, UserData, strlen(UserData), &NumberOfBytesWrittenInUserDataFile, NULL);
    CloseHandle(UserDataFile);

    char* UsersDirectoryPath;
    UsersDirectoryPath = lstrcatA(CurrentDirectoryName, "\\users");
    CreateDirectoryA(UsersDirectoryPath, NULL);

    lstrcatA(UsersDirectoryPath, "\\");
    lstrcatA(UsersDirectoryPath, Username);
    lstrcatA(UsersDirectoryPath, "\0");
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
    HANDLE UserDataFile = CreateFileA("users.txt", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    DWORD NumberOfBytesRead;
    char DataBuffer[4096];
    char LineBuffer[512];
    int length = 0;

    while (ReadFile(UserDataFile, DataBuffer, 4096, &NumberOfBytesRead, NULL) && NumberOfBytesRead > 0) {
        for (int i = 0; i < (int)NumberOfBytesRead; i++) {
            if (DataBuffer[i] == '\n') {
                LineBuffer[length] = '\0';
                

                char FileUsername[30] = { 0 };
                char FilePassword[50] = { 0 };

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

                if (strncmp(FileUsername, Username, UsernameLength) == 0 && strncmp(FilePassword, Password, PasswordLength) == 0) {
                    strncpy(CurrentUser, FileUsername, UsernameLength);

                    char CurrentDirectoryName[MAX_PATH];
                    GetCurrentDirectoryA(MAX_PATH, CurrentDirectoryName);
                    char* UsersDirectoryPath;
                    UsersDirectoryPath = lstrcatA(CurrentDirectoryName, "\\users");

                    lstrcatA(UsersDirectoryPath, "\\");
                    lstrcatA(UsersDirectoryPath, FileUsername);
                    lstrcatA(UsersDirectoryPath, "\\");
                    lstrcatA(UsersDirectoryPath, "\0");

                    strncpy(CurrentUsersDirectory, UsersDirectoryPath, MAX_PATH);

                    printf("Welcome %s\n", FileUsername);
                    break;
                }

                length = 0;
            }
            else if (DataBuffer[i] != '\r') {
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

    // Not working. Not sure how to display them without waiting in the worker which would make no sense
    // printf("Wrote %d bytes\n", bytesWritten); 

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
    UNREFERENCED_PARAMETER(SubmissionNameLength);
    UNREFERENCED_PARAMETER(SourceFilePathLength);

    PTP_POOL pool = NULL;
    TP_CALLBACK_ENVIRON CallBackEnviron;
    BOOL bRet = FALSE;
    PTP_WORK_CALLBACK workcallback = MyWorkCallback;
    PFILE_CHUNK_CONTEXT pv;

    //printf("%s\n", SourceFilePath);

    HANDLE hSrc = CreateFileA(SourceFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hSrc == INVALID_HANDLE_VALUE) {
        printf("CreateFileA for source failed. LastError: %u\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    char submissionPath[MAX_PATH];
    strcpy_s(submissionPath, MAX_PATH, CurrentUsersDirectory);
    lstrcatA(submissionPath, SubmissionName);
    lstrcatA(submissionPath, "\0");

    printf("Submissions path: %s\n", submissionPath);

    HANDLE hDest = CreateFileA(submissionPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);

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
    printf("File size: %llu\n", size.QuadPart);


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

    printf("N=%d\n", n);
    PTP_WORK* work = malloc(n * sizeof(PTP_WORK));

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


NTSTATUS WINAPI
SafeStorageHandleRetrieve(
    const char* SubmissionName,
    uint16_t SubmissionNameLength,
    const char* DestinationFilePath,
    uint16_t DestinationFilePathLength
)
{
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
    lstrcatA(submissionPath, SubmissionName);
    lstrcatA(submissionPath, "\0");

    printf("Submissions path: %s\n", submissionPath);

    HANDLE hSrc = CreateFileA(submissionPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hSrc == INVALID_HANDLE_VALUE) {
        printf("CreateFileA for source failed. LastError: %u\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    HANDLE hDest = CreateFileA(DestinationFilePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);

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
    printf("File size: %llu\n", size.QuadPart);


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

    printf("N=%d\n", n);
    PTP_WORK* work = malloc(n * sizeof(PTP_WORK));

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
