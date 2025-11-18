#include "Commands.h"
#include <tchar.h>


char* CurrentUser;

NTSTATUS WINAPI
SafeStorageInit(
    VOID
)
{
    CurrentUser = calloc(11, sizeof(char));
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
    HANDLE UserDataFile = CreateFileA(UsersFile, FILE_APPEND_DATA, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    char* UserData;
    int UserDataSize = UsernameLength + PasswordLength + 2;
    UserData = calloc(UserDataSize, sizeof(char));

    lstrcatA(UserData, Username);
    lstrcatA(UserData, ":");
    lstrcatA(UserData, Password);
    lstrcatA(UserData, "\r\n");

    DWORD NumberOfBytesWrittenInUserDataFile;
    WriteFile(UserDataFile, UserData, strlen(UserData), &NumberOfBytesWrittenInUserDataFile, NULL);

    char* UsersDirectoryPath;
    UsersDirectoryPath = lstrcatA(CurrentDirectoryName, "\\users");
    CreateDirectoryA(UsersDirectoryPath, NULL);

    lstrcatA(UsersDirectoryPath, "\\");
    lstrcatA(UsersDirectoryPath, Username);
    CreateDirectoryA(UsersDirectoryPath, NULL);
    //CreateDirectoryA(Username, NULL);


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
                    strncpy(CurrentUser, Username, UsernameLength);
                    printf("Welcome %s\n", CurrentUser);
                    break;
                }

                length = 0;
            }
            else if (DataBuffer[i] != '\r') {
                LineBuffer[length++] = DataBuffer[i];
            }
        }
    }

    return STATUS_SUCCESS;
}


NTSTATUS WINAPI
SafeStorageHandleLogout(
    VOID
)
{
    CurrentUser = calloc(11, sizeof(char));

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

    printf("Wrote %d bytes\n", bytesWritten);

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


    HANDLE hDest = CreateFileA(SubmissionName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);

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

    DWORD chunkSize = (DWORD)(size.QuadPart / 4 + 1);

    ULONGLONG fileOffset = 0;

    BYTE* buf = (BYTE*)malloc(chunkSize);
    if (!buf) {
        return STATUS_UNSUCCESSFUL;
    }

    //printf("Chunk size: %d\n", chunkSize);

    PTP_WORK work[4];

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

        printf("Read %d bytes\n", bytesRead);

        SubmitThreadpoolWork(work[workIndex]);

        fileOffset += bytesRead;

        workIndex += 1;
    }

    for (int i = 0; i < 4; i++) {
        WaitForThreadpoolWorkCallbacks(work[i], FALSE);
        CloseThreadpoolWork(work[i]);
    }

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
    /* The function is not implemented. It is your responsibility. */
    /* After you implement the function, you can remove UNREFERENCED_PARAMETER(x). */
    /* This is just to prevent a compilation warning that the parameter is unused. */

    UNREFERENCED_PARAMETER(SubmissionName);
    UNREFERENCED_PARAMETER(SubmissionNameLength);
    UNREFERENCED_PARAMETER(DestinationFilePath);
    UNREFERENCED_PARAMETER(DestinationFilePathLength);

    return STATUS_NOT_IMPLEMENTED;
}
