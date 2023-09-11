#include <iostream>
#include <windows.h>
#include <wtsapi32.h>
#include <cassert>
#include <stdexcept>
#include <fmt/format.h>
#include <fmt/xchar.h>
#include <fmt/os.h>
#include <UserEnv.h>
#include <CLI/CLI.hpp>
#include "scope_guard.hpp"

std::string error_to_string(DWORD err)
{
  return std::system_category().message(err);
}

struct Win32CallError : public std::exception
{
  std::string _msg;
  Win32CallError(std::string context, DWORD err_code) : _msg(fmt::format("{}: {} ({})", context, err_code, error_to_string(err_code)))
  {
  }
  ~Win32CallError() noexcept {}
  const char *what() const throw() { return _msg.c_str(); }
};

void print_sessions()
{
  PWTS_SESSION_INFO_1 session;
  DWORD cnt;
  DWORD pLevel = 1;
  BOOL ret = WTSEnumerateSessionsEx(WTS_CURRENT_SERVER_HANDLE, &pLevel, 0, &session, &cnt);
  if (!ret)
    throw Win32CallError("Failed to enumerate sessions", GetLastError());
  auto sg = sg::make_scope_guard([=]() noexcept
                                 { WTSFreeMemoryEx(WTSTypeSessionInfoLevel1, session, cnt); });
  for (int i = 0; i < cnt; ++i)
  {
    auto sid = session[i].SessionId;
    auto sname = session[i].pSessionName ? session[i].pSessionName : L"n/a";
    auto dname = session[i].pDomainName ? session[i].pDomainName : L"";
    auto uname = session[i].pUserName ? session[i].pUserName : L"";
    fmt::println("Session: {} ({}): {}/{}", sid, CLI::narrow(sname), CLI::narrow(dname), CLI::narrow(uname));
  }
}

HANDLE get_token_for_session(ULONG session_id)
{
  HANDLE hToken;
  BOOL ret = WTSQueryUserToken(session_id, &hToken);
  if (!ret)
  {
    auto err = GetLastError();
    throw Win32CallError(fmt::format("Failed to get user token for session {}", session_id), err);
  }
  return hToken;
}

HANDLE load_user_profile(ULONG session_id, HANDLE hToken)
{
  LPWSTR uname, dname;
  DWORD bret;
  auto ret = WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, session_id, WTSUserName, &uname, &bret);
  if (!ret)
  {
    auto err = GetLastError();
    throw Win32CallError(fmt::format("Failed to query username of session {}", session_id), err);
  }
  auto _sg = sg::make_scope_guard([=]() noexcept
                                  { WTSFreeMemory(uname); });
  ret = WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, session_id, WTSDomainName, &dname, &bret);
  if (!ret)
  {
    auto err = GetLastError();
    throw Win32CallError(fmt::format("Failed to query domain name of session {}", session_id), err);
  }
  auto _sg2 = sg::make_scope_guard([=]() noexcept
                                   { WTSFreeMemory(dname); });
  PROFILEINFO pi;
  ZeroMemory(&pi, sizeof(pi));
  pi.dwSize = sizeof(pi);
  pi.lpUserName = uname;
  pi.lpServerName = dname;
  ret = LoadUserProfile(hToken, &pi);
  if (!ret)
  {
    auto err = GetLastError();
    throw Win32CallError(fmt::format("Failed to load profile of user {}/{} (session id: {})", CLI::narrow(uname), CLI::narrow(dname), session_id), err);
  }
  return pi.hProfile;
}

void run_in_user_session(std::wstring cmd_line, ULONG session_id, bool no_window)
{
  auto hToken = get_token_for_session(session_id);
  auto _sg = sg::make_scope_guard([=]() noexcept
                                  { CloseHandle(hToken); });
  auto hProfile = load_user_profile(session_id, hToken);
  auto _sg4 = sg::make_scope_guard([=]() noexcept
                                   { UnloadUserProfile(hToken, hProfile); });
  void *lpEnvironment;
  auto ret = CreateEnvironmentBlock(&lpEnvironment, hToken, false);
  if (!ret)
    throw Win32CallError("Failed to create environment for new process", GetLastError());
  auto _sg5 = sg::make_scope_guard([=]() noexcept
                                   { DestroyEnvironmentBlock(lpEnvironment); });
  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  ZeroMemory(&pi, sizeof(pi));

  LPWSTR cmd_line_pass = std::bit_cast<LPWSTR>(calloc(cmd_line.length() + 1, sizeof(wchar_t)));
  auto _sg3 = sg::make_scope_guard([=]() noexcept
                                   { free(cmd_line_pass); });
  wcscpy(cmd_line_pass, cmd_line.c_str());
  DWORD procflags = CREATE_UNICODE_ENVIRONMENT;
  if (no_window)
    procflags |= CREATE_NO_WINDOW;
  ret = CreateProcessAsUser(hToken, nullptr, cmd_line_pass, nullptr, nullptr, false, procflags, lpEnvironment, nullptr, &si, &pi);
  if (!ret)
    throw Win32CallError("Failed to create process with obtained token", GetLastError());
  auto _sg2 = sg::make_scope_guard([=]() noexcept
                                   {CloseHandle( pi.hProcess ); CloseHandle( pi.hThread ); });
  FreeConsole();
  auto ret2 = WaitForSingleObject(pi.hProcess, INFINITE);
}

int main()
{
  std::string command = "powershell.exe";
  std::string log_path = "C:\\log.txt";
  DWORD sid = 1;
  bool no_window = false;
  try
  {
    SetConsoleOutputCP(CP_UTF8);
    CLI::App app("Execute a command in the session of another user", "RunInSession");
    app.add_subcommand("list", "List active session on the local host");
    auto run = app.add_subcommand("run", "Run command in session");
    run->add_flag("--no-window", no_window, "Don't run the command in the current console window");
    run->add_option("--sid", sid, "Sid of the session to run the command in")->capture_default_str();
    run->add_option("--log", log_path, "File path for error logging")->capture_default_str();
    run->add_option("command", command, "The command to execute in the session")->capture_default_str();
    app.require_subcommand(1);
    CLI11_PARSE(app);
    if (run->parsed())
      run_in_user_session(CLI::widen(command), sid, no_window);
    else
      print_sessions();
  }
  catch (const std::exception &e)
  {
    auto out = fmt::output_file(log_path);
    out.print("{}", e.what());
    return 1;
  }
}
