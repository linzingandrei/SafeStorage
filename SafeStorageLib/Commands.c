#include "Commands.h"


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


NTSTATUS WINAPI
SafeStorageHandleStore(
    const char* SubmissionName,
    uint16_t SubmissionNameLength,
    const char* SourceFilePath,
    uint16_t SourceFilePathLength
)
{
    /* The function is not implemented. It is your responsibility. */
    /* After you implement the function, you can remove UNREFERENCED_PARAMETER(x). */
    /* This is just to prevent a compilation warning that the parameter is unused. */

    UNREFERENCED_PARAMETER(SubmissionName);
    UNREFERENCED_PARAMETER(SubmissionNameLength);
    UNREFERENCED_PARAMETER(SourceFilePath);
    UNREFERENCED_PARAMETER(SourceFilePathLength);

    return STATUS_NOT_IMPLEMENTED;
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
