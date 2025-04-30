#pragma once
#include <aclapi.h>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fmt/format.h>
#include <functional>
#include <iomanip>
#include <iostream>
#include <optional>
#include <regex>
#include <sddl.h>
#include <shlwapi.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <variant>
#include <windows.h>

namespace AMPathTools
{
    namespace fs = std::filesystem;
    constexpr char *exc1 = "am1sp2exg6";
    constexpr char *exc2 = "amtmpexc5";
    constexpr char *exc3 = "atmasdapxch";
    constexpr char *exc4 = "amtmasdapaexch";
    constexpr char *exc5 = "amtessixhxch";
    constexpr char *exc6 = "amtasdmpexsch";
    namespace ENUMS
    {
        enum class PathType
        {
            BlockDevice = -1,
            CharacterDevice = -2,
            Socket = -3,
            FIFO = -4,
            Unknown = -5,
            DIR = 0,
            FILE = 1,
            SYMLINK = 2
        };

        enum class PathFormat
        {
            Absolute = 1,
            Relative = 2,
            User = 3
        };

        enum class SearchType
        {
            All = 0,
            File = 1,
            Directory = 2
        };
    }

    std::string ShapePath(std::string path, std::string sep = "")
    {
        path = path.erase(0, path.find_first_not_of(" "));
        path = path.erase(path.find_last_not_of(" ") + 1);
        if (path.size() < 2)
            return path;
        std::string head = path.substr(0, 2);
        if (sep.empty())
        {
            int slash_count = 0;
            int anti_slash_count = 0;

            for (auto c : path)
            {
                switch (c)
                {
                case '/':
                    slash_count++;
                    break;
                case '\\':
                    anti_slash_count++;
                    break;
                }
            }

            if (slash_count < anti_slash_count)
            {
                sep = "\\";
            }
            else
            {
                sep = "/";
            }
        }

        std::regex slash_pt("[\\\\/]+");
        path = head + std::regex_replace(path.substr(2), slash_pt, sep);
        return path;
    }

    std::string regex_escape(const std::string &input)
    {
        std::string escaped;
        escaped.reserve(input.size() * 2); // 预分配内存优化性能

        for (char c : input)
        {
            // 匹配需要转义的正则元字符
            switch (c)
            {
            case '\\':
            case '^':
            case '$':
            case '.':
            case '|':
            case '?':
            case '*':
            case '+':
            case '(':
            case ')':
            case '[':
            case ']':
            case '{':
            case '}':
                escaped += '\\'; // 添加转义符
                break;
            default:
                break;
            }
            escaped += c; // 追加当前字符
        }

        return escaped;
    }

    bool is_valid_utf8(const std::string &str)
    {
        int remaining = 0;
        for (unsigned char c : str)
        {
            if (remaining > 0)
            {
                if ((c & 0xC0) != 0x80)
                    return false;
                --remaining;
            }
            else
            {
                if ((c & 0x80) == 0x00)
                    continue; // 单字节 0xxxxxxx
                else if ((c & 0xE0) == 0xC0)
                    remaining = 1; // 双字节 110xxxxx
                else if ((c & 0xF0) == 0xE0)
                    remaining = 2; // 三字节 1110xxxx
                else if ((c & 0xF8) == 0xF0)
                    remaining = 3; // 四字节 11110xxx
                else
                    return false;
            }
        }
        return (remaining == 0);
    }

    std::string AMstr(const std::wstring &wstr)
    {
        int codePage = GetACP();
        int len = WideCharToMultiByte(codePage, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (len <= 0)
            return "";
        std::string result(len - 1, 0);
        WideCharToMultiByte(codePage, 0, wstr.c_str(), -1, &result[0], len, nullptr, nullptr);
        return result;
    };

    std::wstring AMwstr(const std::string &str)
    {
        int codePage = CP_ACP;
        if (is_valid_utf8(str))
        {
            codePage = CP_UTF8;
        }
        int len = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, nullptr, 0);
        if (len <= 0)
            return L"";
        std::wstring result(len - 1, 0);
        MultiByteToWideChar(codePage, 0, str.c_str(), -1, &result[0], len);
        return result;
    };

    namespace WinAPI
    {
        uint64_t FileTimeToUnixTime(const FILETIME &ft)
        {
            ULARGE_INTEGER uli;
            uli.LowPart = ft.dwLowDateTime;
            uli.HighPart = ft.dwHighDateTime;
            return (uli.QuadPart / 10000000ULL) - 11644473600ULL;
        }

        std::string GetFileOwner(const std::wstring &path)
        {
            PSID pSidOwner = NULL;
            PSECURITY_DESCRIPTOR pSD = NULL;
            DWORD dwRtnCode = GetNamedSecurityInfoW(
                path.c_str(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &pSidOwner,
                NULL,
                NULL,
                NULL,
                &pSD);

            std::wstring owner = L"unknown";
            if (dwRtnCode == ERROR_SUCCESS)
            {
                wchar_t szOwnerName[256];
                wchar_t szDomainName[256];
                DWORD dwNameLen = 256;
                DWORD dwDomainLen = 256;
                SID_NAME_USE eUse;

                if (LookupAccountSidW(
                        NULL,
                        pSidOwner,
                        szOwnerName,
                        &dwNameLen,
                        szDomainName,
                        &dwDomainLen,
                        &eUse))
                {
                    owner = szOwnerName;
                }
            }

            if (pSD)
            {
                LocalFree(pSD);
            }

            return AMPathTools::AMstr(owner);
        }

        std::pair<uint64_t, uint64_t> GetTime(const std::wstring &path)
        {
            HANDLE hFile = CreateFileW(
                path.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ,
                NULL,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                NULL);
            if (hFile == INVALID_HANDLE_VALUE)
            {
                return std::make_pair(0, 0);
            }
            FILETIME ftAccess, ftModify;
            GetFileTime(hFile, NULL, &ftAccess, &ftModify);
            CloseHandle(hFile); // 立即释放句柄
            ULARGE_INTEGER uliAccess{
                ftAccess.dwLowDateTime,
                ftAccess.dwHighDateTime};
            ULARGE_INTEGER uliModify{
                ftModify.dwLowDateTime,
                ftModify.dwHighDateTime};
            return std::make_pair((uliAccess.QuadPart - 116444736000000000ULL) / 1e7, (uliModify.QuadPart - 116444736000000000ULL) / 1e7);
        }

        bool is_readonly(const std::wstring &path)
        {
            DWORD attributes = GetFileAttributesW(path.c_str());
            if (attributes != INVALID_FILE_ATTRIBUTES && attributes & FILE_ATTRIBUTE_READONLY)
            {
                return true;
            }
            return false;
        }
    }

    bool _match(std::string name, std::string pattern, bool use_regex)
    {
        if (!use_regex)
        {
            pattern = std::regex_replace(pattern, std::regex("\\*"), std::string(exc1));
            pattern = regex_escape(pattern);
            pattern = std::regex_replace(pattern, std::regex(exc1), ".*");
            return std::regex_search(name, std::regex(pattern));
        }
        else
        {
            std::regex pattern_f(pattern);
            // 检测是否为合法的正则表达式
            try
            {
                return std::regex_search(name, pattern_f);
            }
            catch (const std::exception &e)
            {
                return false;
            }
        }
    }
}

namespace AMPath
{
    namespace fs = std::filesystem;
    constexpr char *AMERROR = "ERROR";
    constexpr char *AMWARNING = "WARNING";

    struct PathInfo
    {
    public:
        std::string name;
        std::string path;
        std::string dir;
        std::string uname;
        uint64_t size = 0;
        uint64_t atime = 0;
        uint64_t mtime = 0;
        AMPathTools::ENUMS::PathType type = AMPathTools::ENUMS::PathType::FILE;
        uint64_t mode_int = 0777;
        std::string mode_str = "rwxrwxrwx";
        PathInfo() : name(""), path(""), dir(""), uname("") {}
        PathInfo(std::string name, std::string path, std::string dir, std::string uname, uint64_t size = 0, uint64_t atime = 0, uint64_t mtime = 0, AMPathTools::ENUMS::PathType type = AMPathTools::ENUMS::PathType::FILE, uint64_t mode_int = 0777, std::string mode_str = "rwxrwxrwx") : name(name), path(path), dir(dir), uname(uname), size(size), atime(atime), mtime(mtime), type(type), mode_int(mode_int), mode_str(mode_str) {}
        std::string FormatTime(const uint64_t &time, const std::string &format = "%Y-%m-%d %H:%M:%S") const
        {
            time_t timeT = static_cast<time_t>(time);

            struct tm timeInfo;

#ifdef _WIN32

            localtime_s(&timeInfo, &timeT);
#else
            localtime_r(&timeT, &timeInfo);
#endif

            std::ostringstream oss;
            oss << std::put_time(&timeInfo, format.c_str());

            return oss.str();
        }
    };

    std::string ModeTrans(uint64_t mode_int)
    {
        // 把mode_int转换为8进制字符串, 长度为9
        if (mode_int > 0777 || mode_int == 0777)
        {
            return "rwxrwxrwx";
        }
        std::string out = "";
        uint64_t tmp_int;
        uint64_t start = 8 * 8 * 8;
        for (int i = 3; i > 0; i--)
        {
            tmp_int = (mode_int % start) / (start / 8);
            start /= 8;
            switch (tmp_int)
            {
            case 1:
                out += "--x";
                break;
            case 2:
                out += "-w-";
                break;
            case 3:
                out += "-wx";
                break;
            case 4:
                out += "r--";
                break;
            case 5:
                out += "r-x";
                break;
            case 6:
                out += "rw-";
                break;
            case 7:
                out += "rwx";
                break;
            default:
                out += "---";
            }
        }
        return out;
    }

    uint64_t ModeTrans(std::string mode_str)
    {
        std::regex pattern("^[r?\\-][w?\\-][x?\\-][r?\\-][w?\\-][x?\\-][r?\\-][w?\\-][x?\\-]$");
        if (!std::regex_match(mode_str, pattern))
        {
            throw std::invalid_argument(fmt::format("Invalid mode string: {}", mode_str));
        }
        uint64_t mode_int = 0;
        for (int i = 0; i < 9; i++)
        {
            if (mode_str[i] != '?' && mode_str[i] != '-')
            {
                mode_int += (1ULL << (8 - i));
            }
        }
        return mode_int;
    }

    std::string MergeModeStr(std::string base_mode_str, std::string new_mode_str);

    std::string MergeModeStr(std::string base_mode_str, std::string new_mode_str)
    {
        std::string pattern_f = "^[r?\\-][w?\\-][x?\\-][r?\\-][w?\\-][x?\\-][r?\\-][w?\\-][x?\\-]$";
        std::regex pattern(pattern_f);

        if (!std::regex_match(base_mode_str, pattern))
        {
            throw std::invalid_argument(fmt::format("Invalid base mode string: {}", base_mode_str));
        }

        if (!std::regex_match(new_mode_str, pattern))
        {
            throw std::invalid_argument(fmt::format("Invalid new mode string: {}", new_mode_str));
        }

        std::string mode_str = "";
        for (int i = 0; i < 9; i++)
        {
            mode_str += (new_mode_str[i] == '?' ? base_mode_str[i] : new_mode_str[i]);
        }
        return mode_str;
    }

    bool IsModeValid(std::string mode_str)
    {
        return std::regex_match(mode_str, std::regex("^[r?\\-][w?\\-][x?\\-][r?\\-][w?\\-][x?\\-][r?\\-][w?\\-][x?\\-]$"));
    }

    bool IsModeValid(uint64_t mode_int)
    {
        return mode_int <= 0777;
    }

    bool is_absolute(const std::string &path)
    {
        std::regex regex1("^[A-Za-z]:[/\\\\]?");
        std::regex regex2("^/");
        std::regex regex3("^\\\\\\\\");
        return std::regex_search(path, regex1) || std::regex_search(path, regex2) || std::regex_search(path, regex3);
    }

    std::vector<std::string> split(std::string path)
    {
        path = AMPathTools::ShapePath(path);
        if (path.size() < 2)
        {
            return {path};
        }
        std::vector<std::string> result{};

        if (path.substr(0, 2) == "//")
        {
            result.push_back("//");
            path = path.substr(2);
        }
        else if (path.front() == '/')
        {
            result.push_back("/");
            path = path.substr(1);
        }
        else if (path.substr(0, 2) == "\\\\")
        {
            result.push_back("\\\\");
            path = path.substr(2);
        }
        std::string cur = "";
        for (auto c : path)
        {
            if (c == '\\' || c == '/')
            {
                if (!cur.empty())
                {
                    result.push_back(cur);
                    cur = "";
                }
            }
            else
            {
                cur += c;
            }
        }
        if (!cur.empty())
        {
            result.push_back(cur);
        }

        return result;
    }

    template <typename... Args>
    std::string join(Args &&...args)
    {
        std::vector<std::string> segments;
        fs::path combined;

        auto process_arg = [&](auto &&arg)
        {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, std::filesystem::path>)
            {
                if (!arg.empty())
                {
                    segments.push_back(arg.string());
                }
            }
            else if constexpr (std::is_same_v<T, std::string>)
            {
                if (!arg.empty())
                {
                    segments.push_back(arg);
                }
            }
            else if constexpr (std::is_same_v<T, std::vector<std::string>>)
            {
                for (auto &seg : arg)
                {
                    if (!seg.empty())
                    {
                        segments.push_back(seg);
                    }
                }
            }
            else if constexpr (std::is_same_v<T, const char *>)
            {
                std::string s = std::string(arg);
                if (!s.empty())
                {
                    segments.push_back(s);
                }
            }
        };

        (process_arg(std::forward<Args>(args)), ...);

        if (segments.empty())
            return "";
        else if (segments.size() == 1)
        {
            return segments.front();
        }

        std::string result;
        for (auto seg : segments)
        {
            result += seg + "/";
        }
        result.pop_back();
        int slash_count = 1 - result.size();
        int anti_slash_count = 0;

        for (auto c : result)
        {
            switch (c)
            {
            case '/':
                slash_count++;
                break;
            case '\\':
                anti_slash_count++;
                break;
            }
        }

        std::string sep;
        if (slash_count < anti_slash_count)
        {
            sep = "\\";
        }
        else
        {
            sep = "/";
        }

        return AMPathTools::ShapePath(result, sep);
    }

    std::string realpath(std::string path, bool force_absolute = false, std::string sep = "")
    {
        if (path.size() < 2)
        {
            return path;
        }

        path = AMPathTools::ShapePath(path, sep);
        std::string new_sep;
        if (path.find("\\") != std::string::npos)
        {
            new_sep = "\\";
        }
        else
        {
            new_sep = "/";
        }

        if (!is_absolute(path))
        {
            std::string head = path.substr(0, 2);
            if (head == "~/" || head == "~\\")
            {
                path = std::getenv("USERPROFILE") + path.substr(1);
            }
            else
            {
                path = fs::current_path().string() + path;
            }
        }

        std::vector<std::string> parts = AMPath::split(path);
        if (parts.empty())
        {
            return "";
        }

        std::vector<std::string> new_parts;
        for (const auto &part : parts)
        {
            if (part == ".")
            {
                continue;
            }
            else if (part == "..")
            {
                if (!new_parts.empty())
                {
                    new_parts.pop_back();
                }
            }
            else
            {
                new_parts.push_back(part);
            }
        }
        std::string result;
        for (const auto &part : new_parts)
        {
            result += part + new_sep;
        }
        result.pop_back();
        return result;
    }

    std::string dirname(const std::string &path)
    {
        fs::path p(realpath(path));
        if (p.parent_path().empty())
        {
            return "";
        }
        return p.parent_path().string();
    }

    std::string basename(const std::string &path)
    {
        fs::path p(path);
        return p.filename().string();
    }

    std::optional<std::pair<std::string, std::exception>> mkdirs(const std::string &path)
    {
        try
        {
            fs::path p(path);
            fs::create_directories(p);
            return std::nullopt;
        }
        catch (const std::exception e)
        {
            return std::make_pair("Mkdir error", e);
        }
    }

    std::variant<PathInfo, std::pair<std::string, std::exception>> stat(const std::string &path, bool trace_link = false)
    {
        PathInfo info;
        fs::path p(path);
        std::wstring wpath = AMPathTools::AMwstr(path);
        info.name = p.filename().string();
        info.path = realpath(path);
        info.dir = p.parent_path().string();
        fs::file_status status;
        try
        {
            if (trace_link)
            {
                status = fs::status(p);
            }
            else
            {
                status = fs::symlink_status(p);
            }
        }
        catch (const std::exception &e)
        {
            return std::make_pair("Stat error: " + path, e);
        }

        switch (status.type())
        {
        case fs::file_type::directory:
            info.type = AMPathTools::ENUMS::PathType::DIR;
            break;
        case fs::file_type::symlink:
            info.type = AMPathTools::ENUMS::PathType::SYMLINK;
            break;
        case fs::file_type::regular:
            info.type = AMPathTools::ENUMS::PathType::FILE;
            break;
        case fs::file_type::block:
            info.type = AMPathTools::ENUMS::PathType::BlockDevice;
            break;
        case fs::file_type::character:
            info.type = AMPathTools::ENUMS::PathType::CharacterDevice;
            break;
        case fs::file_type::fifo:
            info.type = AMPathTools::ENUMS::PathType::FIFO;
            break;
        case fs::file_type::socket:
            info.type = AMPathTools::ENUMS::PathType::Socket;
            break;
        case fs::file_type::unknown:
            info.type = AMPathTools::ENUMS::PathType::Unknown;
            break;
        default:
            info.type = AMPathTools::ENUMS::PathType::Unknown;
            break;
        }

        if (info.type == AMPathTools::ENUMS::PathType::FILE)
        {
            try
            {
                info.size = fs::file_size(p);
            }
            catch (const std::exception)
            {
            }
        }

        if (AMPathTools::WinAPI::is_readonly(AMPathTools::AMwstr(path)))
        {
            info.mode_int = 0333;
            info.mode_str = "r-xr-xr-x";
        }
        else
        {
            info.mode_int = 0666;
            info.mode_str = "rwxrwxrwx";
        }

        auto [atime, mtime] = AMPathTools::WinAPI::GetTime(wpath);
        info.atime = atime;
        info.mtime = mtime;
        info.uname = AMPathTools::WinAPI::GetFileOwner(wpath);
        return info;
    }

    std::vector<PathInfo> listdir(const std::string &path)
    {
        std::vector<PathInfo> result = {};
        fs::path p(path);
        if (!fs::exists(p))
        {
            return result;
        }
        if (!fs::is_directory(p))
        {
            return result;
        }
        std::variant<PathInfo, std::pair<std::string, std::exception>> sr;
        for (const auto &entry : fs::directory_iterator(p))
        {
            sr = stat(entry.path().string(), false);
            if (std::holds_alternative<PathInfo>(sr))
            {
                result.push_back(std::get<PathInfo>(sr));
            }
        }
        return result;
    }

    void _walk(std::string path, std::vector<PathInfo> &result, bool ignore_sepcial_file, bool trace_link)
    {
        fs::path p(path);
        fs::file_status status;
        if (!fs::exists(p))
        {
            return;
        }
        auto sr = stat(path, trace_link);
        if (std::holds_alternative<PathInfo>(sr))
        {
            result.push_back(std::get<PathInfo>(sr));
        }
    }

    std::vector<PathInfo> walk(const std::string &path, bool ignore_sepcial_file, bool trace_link)
    {
        std::vector<PathInfo> results = {};

        _walk(path, results, ignore_sepcial_file, trace_link);

        return results;
    }

    void _getsize(const std::string &path, uint64_t &result, bool trace_link)
    {
        fs::path p(path);
        if (!fs::exists(p))
        {
            return;
        }
        if (fs::is_directory(p))
        {
            for (const auto &entry : fs::directory_iterator(p))
            {
                _getsize(entry.path().string(), result, trace_link);
            }
        }
        else if (fs::is_symlink(p))
        {
            if (trace_link)
            {
                _getsize(fs::read_symlink(p).string(), result, trace_link);
            }
        }
        else if (fs::is_regular_file(p))
        {
            result += fs::file_size(p);
        }
    }

    uint64_t getsize(const std::string &path, bool trace_link = false)
    {
        uint64_t result = 0;
        _getsize(path, result, trace_link);
        return result;
    }

    std::tuple<std::vector<std::string>, std::string, bool> preprocess(std::string path, bool use_regex)
    {
        auto path_parts_ori = AMPath::split(path);
        std::vector<std::string> path_parts = {};

        bool is2star = false;
        bool is_recursive = false;
        for (int i = 0; i < path_parts_ori.size(); i++)
        {
            auto part = path_parts_ori[i];
            if (part == "**")
            {
                is_recursive = true;
                if (is2star)
                {
                    path_parts.erase(path_parts.begin() + i);
                    continue;
                }
                else
                {
                    is2star = true;
                    path_parts.push_back(part);
                }
            }
            else
            {
                is2star = false;
                path_parts.push_back(part);
            }
        }

        std::vector<std::string> match_parts;
        std::vector<std::string> root_parts;
        int num_i = 0;
        bool is_match;
        bool is_end = false;
        for (int i = 0; i < path_parts.size(); i++)
        {
            auto part = path_parts[i];
            if (use_regex)
            {
                is_match = std::regex_search(part, std::regex("[\\*\\?<>\\+]"));
            }
            else
            {
                is_match = part.find("*") != std::string::npos;
            }
            if (is_match)
            {
                match_parts.push_back(part);
                is_end = true;
            }
            else
            {
                if (is_end)
                {
                    match_parts.push_back(part);
                }
                else
                {
                    root_parts.push_back(part);
                }
            }
        }

        return std::make_tuple(match_parts, AMPath::join(root_parts), is_recursive);
    }

    void search(std::vector<std::string> &results, fs::path root, std::string name, std::vector<std::string> remains, AMPathTools::ENUMS::SearchType type, bool use_regex, bool silence, std::function<void(std::string, std::exception)> callback)
    {
        if (!remains.empty())
        {
            if (!fs::is_directory(root))
            {
                return;
            }
            try
            {
                fs::path cur_path;
                std::string cur_name;
                bool is_dir;
                bool is_match;
                bool next_match;
                for (auto &entry : fs::directory_iterator(root))
                {
                    cur_name = entry.path().filename().string();
                    cur_path = AMPath::join(root, cur_name);
                    is_dir = fs::is_directory(cur_path);

                    if (name == "**")
                    {
                        next_match = AMPathTools::_match(cur_name, remains.front(), use_regex);
                        if (is_dir)
                        {
                            search(results, cur_path, name, remains, type, use_regex, silence, callback);
                            if (next_match)
                            {
                                auto new_name = remains.front();
                                auto new_remains = remains;
                                new_remains.erase(new_remains.begin());
                                search(results, cur_path, new_name, new_remains, type, use_regex, silence, callback);
                            }
                        }
                        else
                        {
                            if (next_match)
                            {
                                results.push_back(cur_path.string());
                            }
                        }
                        continue;
                    }

                    search(results, cur_path, name, remains, type, use_regex, silence, callback);
                    if (is_match)
                    {
                        auto new_name = remains.front();
                        auto new_remains = remains;
                        new_remains.erase(new_remains.begin());
                        search(results, cur_path, new_name, new_remains, type, use_regex, silence, callback);
                    }
                    continue;
                }
                is_match = AMPathTools::_match(cur_name, name, use_regex);

                if (is_match && is_dir)
                {
                    std::string new_name = remains[0];
                    auto new_remains = remains;
                    new_remains.erase(new_remains.begin());
                    search(results, cur_path, new_name, new_remains, type, use_regex, silence, callback);
                }
            }

            catch (const std::exception e)
            {
                std::cout << "error: " << e.what() << std::endl;
                if (!silence && callback)
                {
                    callback(AMERROR, e);
                }
            }
        }
        else
        {
            if (!fs::is_directory(root))
            {
                if (type != AMPathTools::ENUMS::SearchType::Directory && AMPathTools::_match(root.filename().string(), name, use_regex))
                {
                    results.push_back(root.string());
                }
                return;
            }

            if (name == "**")
            {
                fs::path cur_path;
                std::string cur_name;
                bool is_dir;
                for (auto &entry : fs::directory_iterator(root))
                {
                    cur_name = entry.path().filename().string();
                    cur_path = AMPath::join(root, cur_name);
                    is_dir = fs::is_directory(cur_path);
                    if (!is_dir)
                    {
                        if (type != AMPathTools::ENUMS::SearchType::Directory)
                        {
                            results.push_back(cur_path.string());
                        }
                        continue;
                    }
                    if (fs::is_empty(cur_path))
                    {
                        if (type != AMPathTools::ENUMS::SearchType::File)
                        {
                            results.push_back(cur_path.string());
                        }
                        continue;
                    }
                    search(results, cur_path, "**", {}, type, use_regex, silence, callback);
                }
                return;
            }

            bool is_dir2;
            std::string cur_name;
            fs::path cur_path;
            try
            {
                for (auto &entry : fs::directory_iterator(root))
                {
                    cur_name = entry.path().filename().string();
                    cur_path = AMPath::join(root, cur_name);
                    if (!AMPathTools::_match(cur_name, name, use_regex))
                    {
                        continue;
                    }
                    is_dir2 = fs::is_directory(cur_path);
                    if (is_dir2 && type != AMPathTools::ENUMS::SearchType::File)
                    {
                        results.push_back(cur_path.string());
                    }
                    else if (!is_dir2 && type != AMPathTools::ENUMS::SearchType::Directory)
                    {
                        results.push_back(cur_path.string());
                    }
                }
            }
            catch (const std::exception e)
            {
                std::cout << "error: " << e.what() << std::endl;
                if (!silence && callback)
                {
                    callback(AMERROR, e);
                }
            }
        }
    }

    std::variant<std::vector<std::string>, std::pair<std::string, std::string>> find(std::string path, AMPathTools::ENUMS::SearchType type = AMPathTools::ENUMS::SearchType::All, bool use_regex = false, bool silence = false, std::function<void(std::string, std::exception)> callback = nullptr)
    {
        path = AMPath::realpath(AMPathTools::ShapePath(path), false);
        if (fs::exists(path) && !use_regex)
        {
            return std::vector<std::string>{path};
        }
        auto pre_result = preprocess(path, use_regex);
        auto match_parts = std::get<0>(pre_result);
        auto root_path = std::get<1>(pre_result);
        bool is_recursive = std::get<2>(pre_result);
        std::vector<std::string> results;

        if (root_path.empty())
        {
            return std::make_pair(AMERROR, fmt::format("Can't parse the root of the path: {}", path));
        }

        if (!fs::exists(root_path))
        {
            return {};
        }

        if (match_parts.empty())
        {
            return std::vector<std::string>{root_path};
        }
        std::string name_first = match_parts.front();
        match_parts.erase(match_parts.begin());
        if (root_path.back() != '\\' && root_path.back() != '/')
        {
            root_path = root_path + "\\";
        }

        AMPath::search(results, fs::path(root_path), name_first, match_parts, type, use_regex, silence, callback);
        return results;
    }
}
